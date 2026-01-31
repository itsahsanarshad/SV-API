-- Migration: 006_2fa_codes.sql
-- Description: Create two_factor_codes table for 2FA verification

CREATE TABLE IF NOT EXISTS two_factor_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_uuid UUID NOT NULL,
    code VARCHAR(6) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_uuid) REFERENCES users(user_uuid) ON DELETE CASCADE
);

-- Index for faster lookups
CREATE INDEX IF NOT EXISTS idx_2fa_user_uuid ON two_factor_codes(user_uuid);
CREATE INDEX IF NOT EXISTS idx_2fa_expires ON two_factor_codes(expires_at);

-- Cleanup function to delete expired codes (optional, can be run periodically)
-- DELETE FROM two_factor_codes WHERE expires_at < NOW() OR used = TRUE;
