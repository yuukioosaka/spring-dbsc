-- DBSC storage schema (sessions, device keys, challenges, registration tokens,
-- credential tickets).
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
    app_session_id  VARCHAR(255) NOT NULL,
    user_id         VARCHAR(255) NOT NULL,
    tier            VARCHAR(16)  NOT NULL,
    revoked         BOOLEAN      NOT NULL,
    created_at      BIGINT       NOT NULL,
    expires_at      BIGINT       NOT NULL,
    last_refresh_at BIGINT       NOT NULL
);

CREATE INDEX IF NOT EXISTS dbsc_sessions_user_idx ON dbsc_sessions (user_id);

-- At most one binding per application session. This is the lookup a guarded route
-- makes when a request arrives with no DBSC cookie, to tell a client that never
-- registered apart from one that dropped its cookies to escape a binding.
CREATE UNIQUE INDEX IF NOT EXISTS dbsc_sessions_app_session_idx ON dbsc_sessions (app_session_id);

CREATE TABLE IF NOT EXISTS dbsc_device_keys (
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

-- Single-use tokens naming the session a registration POST belongs to. They are
-- carried in the registration path, not a cookie, so that registration survives a
-- cross-site callback where a SameSite=Lax cookie is withheld.
CREATE TABLE IF NOT EXISTS dbsc_registration_tokens (
    token      VARCHAR(255) PRIMARY KEY,
    session_id VARCHAR(255) NOT NULL,
    created_at BIGINT       NOT NULL,
    expires_at BIGINT       NOT NULL,
    consumed   BOOLEAN      NOT NULL
);

CREATE INDEX IF NOT EXISTS dbsc_registration_tokens_session_idx ON dbsc_registration_tokens (session_id);

-- Credential-cookie values that still resolve to a session, with the expiry of
-- their grace. Written by credential rotation, which is unconditional: a refresh
-- mints a new ticket and leaves the old one resolving for dbsc.rotation-grace so a
-- second tab is not refused. A row is deleted when it is read after its expiry, so
-- the table stays near-empty.
CREATE TABLE IF NOT EXISTS dbsc_credential_tickets (
    ticket     VARCHAR(255) PRIMARY KEY,
    session_id VARCHAR(255) NOT NULL,
    expires_at BIGINT       NOT NULL
);

CREATE INDEX IF NOT EXISTS dbsc_credential_tickets_expiry_idx ON dbsc_credential_tickets (expires_at);

-- Looked up by session on cleanup, and by nothing else.
CREATE INDEX IF NOT EXISTS dbsc_credential_tickets_session_idx ON dbsc_credential_tickets (session_id);
