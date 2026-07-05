-- Fixed-window rate-limit counters + short-lived mutex locks.
-- Replaces flask-limiter (Redis) and parallel_limiter's SET NX lock.
CREATE TABLE rate_limit (
  key TEXT PRIMARY KEY,
  window_start INTEGER NOT NULL,
  count INTEGER NOT NULL DEFAULT 1
) WITHOUT ROWID;
