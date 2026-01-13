-- Serenity Vault Database Initialization Script
-- This script runs automatically when PostgreSQL container starts for the first time

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================
-- 1. Create users table
-- ============================================
CREATE TABLE IF NOT EXISTS users (
    user_uuid UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    first_name VARCHAR(255) NOT NULL,
    last_name VARCHAR(255) NOT NULL,
    contact_number VARCHAR(255),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_deleted BOOLEAN DEFAULT FALSE
);

-- Index for email lookups
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- ============================================
-- 2. Create resources table
-- ============================================
CREATE TABLE IF NOT EXISTS resources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    user_id UUID REFERENCES users(user_uuid) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Index for user_id lookups
CREATE INDEX IF NOT EXISTS idx_resources_user_id ON resources(user_id);

-- ============================================
-- 3. Create roles table
-- ============================================
CREATE TABLE IF NOT EXISTS roles (
    role_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role_name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_deleted BOOLEAN DEFAULT FALSE
);

-- ============================================
-- 4. Create users_roles_assignment table
-- ============================================
CREATE TABLE IF NOT EXISTS users_roles_assignment (
    user_role_assignment_id UUID NOT NULL DEFAULT gen_random_uuid(),
    user_uuid UUID NOT NULL,
    role_id UUID NOT NULL,
    created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_role_assignment_id),
    FOREIGN KEY (user_uuid) REFERENCES users(user_uuid),
    FOREIGN KEY (role_id) REFERENCES roles(role_id)
);

-- ============================================
-- 5. Insert default roles (optional)
-- ============================================
INSERT INTO roles (role_name) VALUES ('admin'), ('user')
ON CONFLICT DO NOTHING;
