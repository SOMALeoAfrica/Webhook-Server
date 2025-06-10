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

// Initialize Firebase Admin SDK
const serviceAccount = require("/etc/secrets/firebase-service-account.json");
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();

app.get("/", (req, res) => {
  res.send("✅ SOMA Webhook Server is live");
});

// Paystack Webhook endpoint using raw-body for signature verification
app.post("/paystack/webhook", async (req, res) => {
  try {
    const rawBody = await getRawBody(req);
    const secret = process.env.PAYSTACK_SECRET_KEY;
    const hash = crypto
      .createHmac("sha512", secret)
      .update(rawBody)
      .digest("hex");

    const signature = req.headers["x-paystack-signature"];

    if (hash !== signature) {
      console.error("❌ Invalid signature. Rejecting request.");
      return res.status(400).send("Invalid signature");
    }

    const event = JSON.parse(rawBody.toString());
    console.log("✅ Verified event:", event.event);

    if (event.event === 'charge.success') {
      const data = event.data;
      const { userId, planId, planName } = data.metadata;
      const paidAt = new Date(data.paid_at);
      
      // Set plan duration (adjust as needed)
      const durationInMonths = planId.includes('annual') ? 12 : 1;
      const expiresAt = new Date(paidAt);
      expiresAt.setMonth(expiresAt.getMonth() + durationInMonths);

      // Write to Firestore: /users/{userId}
      await db.collection('users').doc(userId).set({
        subscription: {
          status: 'active',
          planId,
          planName,
          paidAt: paidAt.toISOString(),
          expiresAt: expiresAt.toISOString(),
          reference: data.reference,
          channel: data.channel,
          amount: data.amount / 100,
          currency: data.currency,
        }
      }, { merge: true });

      // Optional: record in /subscriptions for analytics/logging
      await db.collection('subscriptions').doc(data.reference).set({
        userId,
        planId,
        planName,
        paidAt: paidAt.toISOString(),
        expiresAt: expiresAt.toISOString(),
        reference: data.reference,
        status: 'active',
        amount: data.amount / 100,
        currency: data.currency,
        email: data.customer.email,
        createdAt: admin.firestore.FieldValue.serverTimestamp()
      });

      // Optional: Set Firebase custom claims
      await admin.auth().setCustomUserClaims(userId, {
        subscription: 'active',
        plan: planId,
        role: data.metadata.role || 'teacher'
      });

      console.log(`✅ Subscription activated for ${userId}`);
    }

    // 🔥 Continue processing event (e.g., Firestore logic here)
    // You can add your Firestore logic below as needed

    return res.sendStatus(200);
  } catch (error) {
    console.error("❌ Error handling webhook:", error);
    return res.sendStatus(500);
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
