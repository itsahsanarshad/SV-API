-- Migration: 007_nda_signed.sql
-- Description: Add is_nda_signed column to users table

ALTER TABLE users ADD COLUMN IF NOT EXISTS is_nda_signed BOOLEAN DEFAULT FALSE;
