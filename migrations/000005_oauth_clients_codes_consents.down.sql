DROP TABLE IF EXISTS oauth_refresh_tokens;
DROP TABLE IF EXISTS consent_grants;
DROP TABLE IF EXISTS authorization_codes;
ALTER TABLE refresh_tokens DROP CONSTRAINT IF EXISTS refresh_tokens_client_id_fkey;
ALTER TABLE sessions DROP CONSTRAINT IF EXISTS sessions_client_id_fkey;
DROP TABLE IF EXISTS oauth_clients;
