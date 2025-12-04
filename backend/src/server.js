import express from "express";
import cors from "cors";
import bodyParser from "body-parser";
import dotenv from "dotenv";
import Stripe from "stripe";
import { v4 as uuidv4 } from "uuid";
import { init, query } from "./db.js";
import { encrypt, decrypt } from "./crypto.js";
import { issueToken, requireAuth } from "./auth.js";
dotenv.config();
const app = express();
const allowed = (process.env.FRONTEND_ORIGIN || "http://localhost:3000").split(",").map((x) => x.trim());
app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin) return cb(null, true);
      cb(null, allowed.includes(origin));
    },
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  })
);
app.use(bodyParser.json());
app.use((req, res, next) => {
  const rid = uuidv4();
  req.rid = rid;
  res.on("finish", () => {
    try {
      console.log(
        JSON.stringify({ rid, method: req.method, path: req.path, status: res.statusCode })
      );
    } catch {}
  });
  next();
});
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY || "");
const smallLimit = parseFloat(process.env.SMALL_LIMIT || "5");
const port = process.env.PORT || 4000;
app.post("/auth/login", async (req, res) => {
  const email = String(req.body.email || "").toLowerCase();
  const provider = String(req.body.oauth_provider || "email");
  if (!email) return res.status(400).json({ error: "email_required" });
  let r = await query("SELECT id FROM users WHERE email=$1", [email]);
  let id = r.rows[0]?.id;
  if (!id) {
    r = await query("INSERT INTO users(email, oauth_provider) VALUES($1,$2) RETURNING id", [email, provider]);
    id = r.rows[0].id;
  }
  const session_token = issueToken(id);
  res.json({ user_id: id, session_token });
});
app.get("/listings", async (req, res) => {
  const r = await query(
    "SELECT id, service_name, price_per_unit, unit_description, available_units FROM listings WHERE status='active' ORDER BY id DESC"
  );
  res.json(r.rows);
});
app.post("/listings", requireAuth, async (req, res) => {
  const owner_id = req.userId;
  const { service_name, api_key, price_per_unit, unit_description, available_units } = req.body;
  if (!service_name || !api_key || !price_per_unit || !unit_description || !available_units)
    return res.status(400).json({ error: "missing_fields" });
  const sn = String(service_name);
  const ud = String(unit_description);
  const ak = String(api_key);
  const pp = String(price_per_unit);
  if (sn.length < 1 || sn.length > 128) return res.status(400).json({ error: "bad_service_name" });
  if (ud.length < 1 || ud.length > 128) return res.status(400).json({ error: "bad_unit_description" });
  if (ak.length < 1 || ak.length > 4096) return res.status(400).json({ error: "bad_api_key" });
  if (!/^\d+(\.\d{1,2})?$/.test(pp)) return res.status(400).json({ error: "bad_price" });
  const p = Number(pp);
  const a = parseInt(available_units);
  if (!Number.isFinite(p) || p <= 0 || p > 1e9) return res.status(400).json({ error: "bad_price" });
  if (!Number.isInteger(a) || a <= 0 || a > 1e6) return res.status(400).json({ error: "bad_available_units" });
  const enc = encrypt(String(api_key));
  const r = await query(
    "INSERT INTO listings(owner_id, service_name, api_key_encrypted, price_per_unit, unit_description, available_units, status) VALUES($1,$2,$3,$4,$5,$6,'active') RETURNING id",
    [owner_id, service_name, enc, p, unit_description, a]
  );
  res.json({ id: r.rows[0].id });
});
app.post("/orders", requireAuth, async (req, res) => {
  const buyer_id = req.userId;
  const listing_id = parseInt(req.body.listing_id);
  const units = parseInt(req.body.units_requested || req.body.units || 1);
  if (!listing_id || !units) return res.status(400).json({ error: "missing_fields" });
  if (!Number.isInteger(units) || units <= 0 || units > 1e6) return res.status(400).json({ error: "bad_units" });
  await query("BEGIN");
  try {
    const lr = await query(
      "SELECT id, price_per_unit, available_units, api_key_encrypted, service_name FROM listings WHERE id=$1 FOR UPDATE",
      [listing_id]
    );
    const listing = lr.rows[0];
    if (!listing) {
      await query("ROLLBACK");
      return res.status(404).json({ error: "listing_not_found" });
    }
    if (listing.available_units < units) {
      await query("ROLLBACK");
      return res.status(400).json({ error: "insufficient_units" });
    }
    const payment_amount = ((Math.round(Number(listing.price_per_unit) * 100) * units) / 100).toFixed(2);
    const or = await query(
      "INSERT INTO orders(buyer_id, listing_id, units, payment_amount, payment_status) VALUES($1,$2,$3,$4,'pending') RETURNING id",
      [buyer_id, listing_id, units, payment_amount]
    );
    const order_id = or.rows[0].id;
    let payment_url = null;
    let payment_requires_confirmation = false;
    if (Number(payment_amount) <= smallLimit) {
      await query("UPDATE orders SET payment_status='paid' WHERE id=$1", [order_id]);
      const apiKey = decrypt(listing.api_key_encrypted);
      const expires_at = new Date(Date.now() + 30 * 24 * 3600 * 1000);
    const encToken = encrypt(apiKey);
    await query(
      "INSERT INTO tokens(order_id, service_name, api_key_encrypted, expires_at) VALUES($1,$2,$3,$4)",
      [order_id, listing.service_name, encToken, expires_at]
    );
      await query(
        "UPDATE listings SET available_units=available_units-$1, status=CASE WHEN available_units-$1<=0 THEN 'sold_out' ELSE status END WHERE id=$2",
        [units, listing_id]
      );
      await query("COMMIT");
    } else {
      await query("COMMIT");
      payment_requires_confirmation = true;
      if (!process.env.STRIPE_SECRET_KEY) {
        payment_url = `${process.env.BACKEND_PUBLIC_URL || `http://localhost:${port}`}/orders/dev/confirm/${order_id}`;
      } else {
        const session = await stripe.checkout.sessions.create({
          mode: "payment",
          line_items: [
            {
              price_data: {
                currency: "usd",
                product_data: { name: listing.service_name },
                unit_amount: Math.round(Number(listing.price_per_unit) * 100),
              },
              quantity: units,
            },
          ],
          success_url: `${process.env.SUCCESS_URL || "http://localhost:3000"}/orders/success?order_id=${order_id}`,
          cancel_url: `${process.env.CANCEL_URL || "http://localhost:3000"}/orders/cancel?order_id=${order_id}`,
          metadata: { order_id: String(order_id), buyer_id: String(buyer_id) },
        });
        payment_url = session.url;
      }
    }
    res.json({ order_id, payment_amount, payment_requires_confirmation, payment_url });
  } catch (e) {
    await query("ROLLBACK");
    throw e;
  }
});
app.get("/listings/:id", requireAuth, async (req, res) => {
  const id = parseInt(req.params.id);
  const r = await query(
    "SELECT id, service_name, price_per_unit, unit_description, available_units, status FROM listings WHERE id=$1",
    [id]
  );
  if (!r.rows[0]) return res.status(404).json({ error: "not_found" });
  res.json(r.rows[0]);
});
app.get("/orders/:id", requireAuth, async (req, res) => {
  const id = parseInt(req.params.id);
  const r = await query("SELECT id, payment_amount, payment_status, created_at FROM orders WHERE id=$1", [id]);
  if (!r.rows[0]) return res.status(404).json({ error: "not_found" });
  res.json(r.rows[0]);
});
app.get("/tokens", requireAuth, async (req, res) => {
  const uid = req.userId;
  const r = await query(
    "SELECT t.id as token_id, t.service_name, t.api_key_encrypted, t.expires_at FROM tokens t JOIN orders o ON t.order_id=o.id WHERE o.buyer_id=$1 ORDER BY t.id DESC",
    [uid]
  );
  res.json(
    r.rows.map((row) => ({ token_id: row.token_id, service_name: row.service_name, api_key: decrypt(row.api_key_encrypted), expires_at: row.expires_at }))
  );
});
app.post("/webhooks/stripe", bodyParser.raw({ type: "application/json" }), async (req, res) => {
  let event = null;
  try {
    const sig = req.headers["stripe-signature"];
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET || "");
  } catch {
    return res.status(400).send("bad");
  }
  if (event.type === "checkout.session.completed") {
    const s = event.data.object;
    const order_id = parseInt(s.metadata?.order_id || "0");
    if (order_id) {
      const ins = await query(
        "INSERT INTO webhook_events(source, event_id) VALUES($1,$2) ON CONFLICT (event_id) DO NOTHING RETURNING id",
        ["stripe", event.id]
      );
      if (ins.rows.length === 0) return res.json({ received: true });
      await query("BEGIN");
      try {
        const lr = await query(
          "SELECT listings.api_key_encrypted, listings.service_name, orders.listing_id, orders.units FROM orders JOIN listings ON orders.listing_id=listings.id WHERE orders.id=$1 FOR UPDATE",
          [order_id]
        );
        const row = lr.rows[0];
        if (row) {
          await query("UPDATE orders SET payment_status='paid' WHERE id=$1", [order_id]);
          const apiKey = decrypt(row.api_key_encrypted);
          const expires_at = new Date(Date.now() + 30 * 24 * 3600 * 1000);
        const encToken = encrypt(apiKey);
        await query(
          "INSERT INTO tokens(order_id, service_name, api_key_encrypted, expires_at) VALUES($1,$2,$3,$4)",
          [order_id, row.service_name, encToken, expires_at]
        );
          await query(
            "UPDATE listings SET available_units=available_units-$1, status=CASE WHEN available_units-$1<=0 THEN 'sold_out' ELSE status END WHERE id=$2",
            [row.units, row.listing_id]
          );
        }
        await query("COMMIT");
      } catch (e) {
        await query("ROLLBACK");
        throw e;
      }
    }
  }
  res.json({ received: true });
});
app.get("/healthz", async (req, res) => {
  try {
    await query("SELECT 1");
    res.json({ ok: true });
  } catch {
    res.status(500).json({ ok: false });
  }
});

const buckets = new Map();
const limitWindowMs = parseInt(process.env.RATE_LIMIT_WINDOW_MS || "60000");
const limitCount = parseInt(process.env.RATE_LIMIT_COUNT || "120");
app.use((req, res, next) => {
  const key = `${req.ip}:${req.path}`;
  const now = Date.now();
  const b = buckets.get(key) || { t: now, c: 0 };
  if (now - b.t > limitWindowMs) {
    b.t = now;
    b.c = 0;
  }
  b.c += 1;
  buckets.set(key, b);
  if (b.c > limitCount) return res.status(429).json({ error: "rate_limited" });
  next();
});
// Dev-only payment confirmation when Stripe is not configured
app.get("/orders/dev/confirm/:id", async (req, res) => {
  if (process.env.STRIPE_SECRET_KEY) return res.status(400).json({ error: "stripe_configured" });
  const order_id = parseInt(req.params.id);
  await query("BEGIN");
  try {
    const lr = await query(
      "SELECT listings.api_key_encrypted, listings.service_name, orders.listing_id, orders.units FROM orders JOIN listings ON orders.listing_id=listings.id WHERE orders.id=$1 FOR UPDATE",
      [order_id]
    );
    const row = lr.rows[0];
    if (!row) {
      await query("ROLLBACK");
      return res.status(404).json({ error: "not_found" });
    }
    await query("UPDATE orders SET payment_status='paid' WHERE id=$1", [order_id]);
    const apiKey = decrypt(row.api_key_encrypted);
    const expires_at = new Date(Date.now() + 30 * 24 * 3600 * 1000);
  const encToken = encrypt(apiKey);
  await query(
    "INSERT INTO tokens(order_id, service_name, api_key_encrypted, expires_at) VALUES($1,$2,$3,$4)",
    [order_id, row.service_name, encToken, expires_at]
  );
    await query(
      "UPDATE listings SET available_units=available_units-$1, status=CASE WHEN available_units-$1<=0 THEN 'sold_out' ELSE status END WHERE id=$2",
      [row.units, row.listing_id]
    );
    await query("COMMIT");
  } catch (e) {
    await query("ROLLBACK");
    throw e;
  }
  const success = `${process.env.SUCCESS_URL || "http://localhost:3000"}/orders/success?order_id=${order_id}`;
  res.redirect(success);
});
app.use((err, req, res, next) => {
  res.status(500).json({ error: "internal" });
});
init().then(() => {
  app.listen(port, () => {});
});
