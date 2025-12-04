ALTER TABLE tokens ADD COLUMN IF NOT EXISTS api_key_encrypted TEXT;
UPDATE tokens SET api_key_encrypted = api_key_plain WHERE api_key_encrypted IS NULL AND api_key_plain IS NOT NULL;
UPDATE tokens SET api_key_plain = NULL WHERE api_key_encrypted IS NOT NULL;
