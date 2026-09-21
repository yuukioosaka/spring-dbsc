-- DBSC storage schema (sessions, bound keys, challenges).
--
-- This migration is BYTE-EQUIVALENT to what JdbcStorageAdapter.initialize()
-- creates on startup. It exists so applications that run a migration tool can let
-- Flyway own the schema instead of granting the runtime user DDL rights.
--
-- If you use this path, set dbsc.storage to a JDBC-backed adapter with
-- initialize() skipped, or simply let the adapter's "CREATE TABLE IF NOT EXISTS"
-- run: the two are idempotent and identical, so applying this migration and then
-- starting the app is safe and changes nothing.
--
-- Portable SQL on purpose: no vendor-specific types, no sequences. Timestamps are
-- BIGINT epoch milliseconds, matching how the protocol carries them.

CREATE TABLE IF NOT EXISTS dbsc_sessions (
    id              VARCHAR(255) PRIMARY KEY,
    user_id         VARCHAR(255) NOT NULL,
    tier            VARCHAR(16)  NOT NULL,
    created_at      BIGINT       NOT NULL,
    expires_at      BIGINT       NOT NULL,
    last_refresh_at BIGINT       NOT NULL
);

CREATE INDEX IF NOT EXISTS dbsc_sessions_user_idx ON dbsc_sessions (user_id);

CREATE TABLE IF NOT EXISTS dbsc_bound_keys (
    session_id VARCHAR(255) PRIMARY KEY,
    jwk_json   TEXT         NOT NULL,
    algorithm  VARCHAR(16)  NOT NULL,
    created_at BIGINT       NOT NULL
);

CREATE TABLE IF NOT EXISTS dbsc_challenges (
    jti        VARCHAR(255) PRIMARY KEY,
    session_id VARCHAR(255) NOT NULL,
    created_at BIGINT       NOT NULL,
    expires_at BIGINT       NOT NULL,
    consumed   BOOLEAN      NOT NULL
);

CREATE INDEX IF NOT EXISTS dbsc_challenges_session_idx ON dbsc_challenges (session_id);
