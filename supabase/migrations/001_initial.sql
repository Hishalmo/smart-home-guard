-- ============================================================
-- 001_initial.sql — Smart Home Guard schema
-- ============================================================

-- ---------- 1. scan_sessions ----------
CREATE TABLE scan_sessions (
  id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id       uuid        NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  mode          text        NOT NULL CHECK (mode IN ('realtime', 'pcap')),
  status        text        NOT NULL DEFAULT 'idle'
                            CHECK (status IN ('idle','starting','scanning','stopping','completed','error')),
  interface_name      text,
  pcap_file_name      text,
  pcap_file_size_bytes bigint,
  started_at    timestamptz NOT NULL DEFAULT now(),
  ended_at      timestamptz,
  total_flows   int         NOT NULL DEFAULT 0,
  threat_count  int         NOT NULL DEFAULT 0,
  summary_json  jsonb,
  created_at    timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE scan_sessions ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users manage own scan sessions"
  ON scan_sessions FOR ALL
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);


-- ---------- 2. flow_events ----------
CREATE TABLE flow_events (
  id                uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id        uuid        NOT NULL REFERENCES scan_sessions(id) ON DELETE CASCADE,
  user_id           uuid        NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  captured_at       timestamptz NOT NULL DEFAULT now(),
  source_ip         text,
  destination_ip    text,
  source_port       int,
  destination_port  int,
  protocol_name     text,
  protocol_type     smallint,
  predicted_category text       NOT NULL,
  confidence        real        NOT NULL,
  features_json     jsonb       NOT NULL,
  created_at        timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_flow_events_threats ON flow_events (session_id, captured_at)
WHERE predicted_category != 'Benign';

ALTER TABLE flow_events ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users manage own flow events"
  ON flow_events FOR ALL
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

ALTER PUBLICATION supabase_realtime ADD TABLE flow_events;


-- ---------- 3. alerts ----------
CREATE TABLE alerts (
  id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id    uuid        NOT NULL REFERENCES scan_sessions(id) ON DELETE CASCADE,
  user_id       uuid        NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  flow_id       uuid        REFERENCES flow_events(id),
  severity      text        NOT NULL CHECK (severity IN ('critical','high','medium','info')),
  category      text        NOT NULL,
  source_ip     text,
  destination_ip text,
  message       text        NOT NULL,
  acknowledged  bool        NOT NULL DEFAULT false,
  triggered_at  timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE alerts ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users manage own alerts"
  ON alerts FOR ALL
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

ALTER PUBLICATION supabase_realtime ADD TABLE alerts;


-- ---------- 4. user_preferences ----------
CREATE TABLE user_preferences (
  user_id           uuid    PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  notify_critical   bool    NOT NULL DEFAULT true,
  notify_high       bool    NOT NULL DEFAULT true,
  notify_medium     bool    NOT NULL DEFAULT false,
  email_alerts      bool    NOT NULL DEFAULT false,
  default_scan_mode text    NOT NULL DEFAULT 'pcap',
  updated_at        timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE user_preferences ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users manage own preferences"
  ON user_preferences FOR ALL
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);
