-- Phase 2 schema (loaded automatically by the timescaledb container on first start).
CREATE EXTENSION IF NOT EXISTS timescaledb;

CREATE TABLE IF NOT EXISTS ts_files (
    id           UUID PRIMARY KEY,
    filename     TEXT        NOT NULL,
    size_bytes   BIGINT      NOT NULL,
    status       TEXT        NOT NULL DEFAULT 'uploaded', -- uploaded|parsing|parsed|failed
    storage_key  TEXT        NOT NULL,                    -- MinIO object key
    uploaded_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    owner_id     TEXT                                       -- multi-user (phase 6)
);

-- Parsed system info: software version, serial, licenses, generation date, etc.
CREATE TABLE IF NOT EXISTS system_info (
    file_id  UUID  NOT NULL REFERENCES ts_files(id) ON DELETE CASCADE,
    key      TEXT  NOT NULL,
    value    TEXT  NOT NULL,
    PRIMARY KEY (file_id, key)
);

-- Index of log files found inside the archive.
CREATE TABLE IF NOT EXISTS log_files (
    id        UUID PRIMARY KEY,
    file_id   UUID NOT NULL REFERENCES ts_files(id) ON DELETE CASCADE,
    path      TEXT NOT NULL,   -- path inside the .tgz
    line_count BIGINT,
    size_bytes BIGINT
);

-- Counter time-series extracted by the regex parsers (hypertable).
CREATE TABLE IF NOT EXISTS counters (
    file_id  UUID        NOT NULL REFERENCES ts_files(id) ON DELETE CASCADE,
    name     TEXT        NOT NULL,  -- e.g. pkt_recv, flow_fwd_l3
    ts       TIMESTAMPTZ NOT NULL,
    value    DOUBLE PRECISION NOT NULL
);
SELECT create_hypertable('counters', 'ts', if_not_exists => TRUE);
CREATE INDEX IF NOT EXISTS counters_file_name_ts ON counters (file_id, name, ts DESC);
