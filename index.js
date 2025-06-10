require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const admin = require("firebase-admin");
const crypto = require("crypto");
const getRawBody = require("raw-body");

const app = express();
const PORT = process.env.PORT || 5000;
app.use(cors());

const serviceAccount = require("/etc/secrets/firebase-service-account.json");
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});
const db = admin.firestore();

// 🧰 Utility: Sleep for retry backoff
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// 📦 Retry wrapper for Firestore writes
async function withRetries(taskFn, maxRetries = 3, delay = 1000) {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await taskFn();
    } catch (err) {
      console.error(`⚠️ Attempt ${attempt} failed:`, err.message);
      if (attempt === maxRetries) throw err;
      await sleep(delay * attempt); // exponential backoff
    }
  }
}

// ✅ Root check
app.get("/", (req, res) => {
  res.send("✅ SOMA Webhook Server is live");
});

// 💳 Paystack Webhook Handler
app.post("/paystack/webhook", async (req, res) => {
  try {
    const rawBody = await getRawBody(req);
    const secret = process.env.PAYSTACK_SECRET_KEY;
    const hash = crypto.createHmac("sha512", secret).update(rawBody).digest("hex");

    const signature = req.headers["x-paystack-signature"];
    if (hash !== signature) {
      console.error("❌ Invalid signature");
      return res.status(400).send("Invalid signature");
    }

    const event = JSON.parse(rawBody.toString());
    console.log("✅ Verified event:", event.event);

    if (event.event === "charge.success") {
      const data = event.data;
      const { userId, planId, planName } = data.metadata;
      const paidAt = new Date(data.paid_at);

      let durationInDays = 30;
      if (planId.includes("daily")) durationInDays = 1;
      else if (planId.includes("monthly")) durationInDays = 30;
      else if (planId.includes("annual")) durationInDays = 365;

      const expiresAt = new Date(paidAt);
      expiresAt.setDate(expiresAt.getDate() + durationInDays);

      // Firestore write with retry
      await withRetries(() =>
        db.collection("users").doc(userId).set(
          {
            subscription: {
              status: "active",
              planId,
              planName,
              paidAt: paidAt.toISOString(),
              expiresAt: expiresAt.toISOString(),
              reference: data.reference,
              channel: data.channel,
              amount: data.amount / 100,
              currency: data.currency,
            },
          },
          { merge: true }
        )
      );

      await withRetries(() =>
        db.collection("subscriptions").doc(data.reference).set({
          userId,
          planId,
          planName,
          paidAt: paidAt.toISOString(),
          expiresAt: expiresAt.toISOString(),
          reference: data.reference,
          status: "active",
          amount: data.amount / 100,
          currency: data.currency,
          email: data.customer.email,
          createdAt: admin.firestore.FieldValue.serverTimestamp(),
        })
      );

      await withRetries(() =>
        admin.auth().setCustomUserClaims(userId, {
          subscription: "active",
          plan: planId,
          role: data.metadata.role || "teacher",
        })
      );

      console.log(`✅ Subscription activated for ${userId} (${planId})`);
    }

    res.sendStatus(200);
  } catch (error) {
    console.error("❌ Error handling webhook:", error);
    res.sendStatus(500);
  }
});

// 🧼 Scheduled Cleanup for Expired Student Subscriptions
app.get("/cron/cleanup-expired-student-plans", async (req, res) => {
  try {
    const now = new Date();

    const expiredSubs = await db
      .collection("subscriptions_students")
      .where("expiresAt", "<=", now.toISOString())
      .where("status", "==", "active")
      .get();

    const batch = db.batch();
    expiredSubs.forEach((doc) => {
      batch.update(doc.ref, { status: "expired" });
    });

    await batch.commit();
    res.send(`✅ Cleaned up ${expiredSubs.size} expired student subscriptions.`);
  } catch (err) {
    console.error("❌ Cleanup error:", err);
    res.status(500).send("Cleanup failed");
  }
});

// 🔐 Revoke Expired Custom Claims
app.get("/cron/revoke-expired-claims", async (req, res) => {
  try {
    const now = new Date();
    const usersRef = db.collection("users");
    const snapshot = await usersRef
      .where("subscription.expiresAt", "<=", now.toISOString())
      .where("subscription.status", "==", "active")
      .get();

    let count = 0;

    for (const doc of snapshot.docs) {
      const uid = doc.id;
      await admin.auth().setCustomUserClaims(uid, null);
      await doc.ref.update({
        "subscription.status": "expired",
        "subscription.planId": admin.firestore.FieldValue.delete(),
        "subscription.planName": admin.firestore.FieldValue.delete(),
      });
      count++;
    }

    res.send(`✅ Revoked claims for ${count} users`);
  } catch (err) {
    console.error("❌ Revoke error:", err);
    res.status(500).send("Claim revocation failed");
  }
});

app.listen(PORT, () => {
  console.log(`🚀 Webhook Server running on port ${PORT}`);
});
