import pg from "pg";
const { Pool } = pg;
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
export const query = (text, params) => pool.query(text, params);
export const init = async () => {
  await query(
    "CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, email TEXT UNIQUE NOT NULL, oauth_provider TEXT, created_at TIMESTAMP DEFAULT NOW())"
  );
  await query(
    "CREATE TABLE IF NOT EXISTS listings (id SERIAL PRIMARY KEY, owner_id INTEGER REFERENCES users(id), service_name TEXT NOT NULL, api_key_encrypted TEXT NOT NULL, price_per_unit NUMERIC NOT NULL, unit_description TEXT NOT NULL, available_units INTEGER NOT NULL, status TEXT NOT NULL, created_at TIMESTAMP DEFAULT NOW())"
  );
  await query(
    "CREATE TABLE IF NOT EXISTS orders (id SERIAL PRIMARY KEY, buyer_id INTEGER REFERENCES users(id), listing_id INTEGER REFERENCES listings(id), units INTEGER NOT NULL, payment_amount NUMERIC NOT NULL, payment_status TEXT NOT NULL, created_at TIMESTAMP DEFAULT NOW())"
  );
  await query(
    "CREATE TABLE IF NOT EXISTS tokens (id SERIAL PRIMARY KEY, order_id INTEGER REFERENCES orders(id), service_name TEXT NOT NULL, api_key_encrypted TEXT NOT NULL, api_key_plain TEXT, expires_at TIMESTAMP NOT NULL, created_at TIMESTAMP DEFAULT NOW())"
  );
  await query(
    "CREATE TABLE IF NOT EXISTS webhook_events (id SERIAL PRIMARY KEY, source TEXT NOT NULL, event_id TEXT UNIQUE NOT NULL, created_at TIMESTAMP DEFAULT NOW())"
  );
  await query("CREATE INDEX IF NOT EXISTS idx_listings_status ON listings(status)");
  await query("CREATE INDEX IF NOT EXISTS idx_orders_buyer ON orders(buyer_id)");
  await query("CREATE INDEX IF NOT EXISTS idx_orders_listing ON orders(listing_id)");
  await query("CREATE INDEX IF NOT EXISTS idx_tokens_order ON tokens(order_id)");
};
