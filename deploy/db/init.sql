-- initialize privileges for application user (when not created by env)
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'udam') THEN
    CREATE ROLE udam LOGIN PASSWORD 'udam';
  END IF;
END$$;
CREATE DATABASE udam OWNER udam;
GRANT ALL PRIVILEGES ON DATABASE udam TO udam;
