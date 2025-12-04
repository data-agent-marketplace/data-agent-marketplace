ALTER TABLE listings
  ALTER COLUMN price_per_unit TYPE NUMERIC(10,2) USING ROUND(price_per_unit::numeric, 2),
  ADD CONSTRAINT chk_listings_available_units CHECK (available_units >= 0),
  ADD CONSTRAINT chk_listings_status CHECK (status IN ('active','sold_out'));

ALTER TABLE orders
  ALTER COLUMN payment_amount TYPE NUMERIC(10,2) USING ROUND(payment_amount::numeric, 2),
  ADD CONSTRAINT chk_orders_units CHECK (units > 0);

