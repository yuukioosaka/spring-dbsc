-- DBSC proof replay cache.
--
-- Separate table, and a separate migration, because it is populated by a different
-- collaborator (JdbcProofReplayCache) which an application may replace or omit
-- entirely. Keeping it in V1 would make the sessions schema depend on a component
-- the adopter might not use.
--
-- replay_key is VARCHAR(512): it is "<sessionId>.<timestamp>.<first 43 chars of
-- signature>", so the bound is generous but not unbounded.
--
-- Rows are short-lived by design (TTL is twice the proof freshness window) and the
-- cache sweeps expired rows itself. If you would rather expire them in the
-- database, a periodic DELETE ... WHERE expires_at < :now is safe to add.

CREATE TABLE IF NOT EXISTS dbsc_proof_replay (
    replay_key VARCHAR(512) PRIMARY KEY,
    expires_at BIGINT       NOT NULL
);
