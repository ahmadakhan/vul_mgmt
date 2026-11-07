--
-- 029 — self-service password reset via OTP.
--
-- Users can request a one-time password-reset code on the login page. The code
-- is delivered to the operator email configured via SMTP_FROM (deployment-level
-- SMTP). This keeps the self-service flow within the deployment's existing
-- alerting mailbox rather than requiring a per-user email column.
--
CREATE TABLE password_reset_tokens (
  username      text NOT NULL,
  code_hash     text NOT NULL,
  expires_at    timestamptz NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX password_reset_tokens_username ON password_reset_tokens(username);
CREATE INDEX password_reset_tokens_expires ON password_reset_tokens(expires_at);
INSERT INTO schema_migrations(version) VALUES(29) ON CONFLICT DO NOTHING;
