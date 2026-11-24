-- FutPulse Match Center foundation
-- SQLite / Cloudflare D1. Apply only after reviewing the migration plan.
-- All identifiers are prefixed to keep this module isolated from other 221Cloud apps.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS futpulse_competitions (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,
  country TEXT,
  region TEXT,
  competition_type TEXT NOT NULL DEFAULT 'league'
    CHECK (competition_type IN ('league', 'cup', 'international', 'other')),
  logo_url TEXT,
  is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
  data_source TEXT,
  source_competition_id TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (data_source, source_competition_id)
);

CREATE TABLE IF NOT EXISTS futpulse_seasons (
  id TEXT PRIMARY KEY,
  competition_id TEXT NOT NULL REFERENCES futpulse_competitions(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  start_date TEXT,
  end_date TEXT,
  is_current INTEGER NOT NULL DEFAULT 0 CHECK (is_current IN (0, 1)),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (competition_id, name)
);

CREATE TABLE IF NOT EXISTS futpulse_teams (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,
  short_name TEXT,
  country TEXT,
  logo_url TEXT,
  data_source TEXT,
  source_team_id TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (data_source, source_team_id)
);

CREATE TABLE IF NOT EXISTS futpulse_matches (
  id TEXT PRIMARY KEY,
  competition_id TEXT NOT NULL REFERENCES futpulse_competitions(id) ON DELETE RESTRICT,
  season_id TEXT REFERENCES futpulse_seasons(id) ON DELETE SET NULL,
  home_team_id TEXT NOT NULL REFERENCES futpulse_teams(id) ON DELETE RESTRICT,
  away_team_id TEXT NOT NULL REFERENCES futpulse_teams(id) ON DELETE RESTRICT,
  kickoff_at TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'scheduled'
    CHECK (status IN ('scheduled', 'live', 'halftime', 'finished', 'postponed', 'cancelled', 'suspended')),
  home_score INTEGER CHECK (home_score IS NULL OR home_score >= 0),
  away_score INTEGER CHECK (away_score IS NULL OR away_score >= 0),
  venue TEXT,
  matchday TEXT,
  round_name TEXT,
  data_source TEXT,
  source_match_id TEXT,
  source_url TEXT,
  source_updated_at TEXT,
  last_synced_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CHECK (home_team_id <> away_team_id),
  UNIQUE (data_source, source_match_id)
);

CREATE TABLE IF NOT EXISTS futpulse_standings (
  id TEXT PRIMARY KEY,
  competition_id TEXT NOT NULL REFERENCES futpulse_competitions(id) ON DELETE CASCADE,
  season_id TEXT NOT NULL REFERENCES futpulse_seasons(id) ON DELETE CASCADE,
  team_id TEXT NOT NULL REFERENCES futpulse_teams(id) ON DELETE CASCADE,
  position INTEGER NOT NULL CHECK (position > 0),
  played INTEGER NOT NULL DEFAULT 0 CHECK (played >= 0),
  won INTEGER NOT NULL DEFAULT 0 CHECK (won >= 0),
  drawn INTEGER NOT NULL DEFAULT 0 CHECK (drawn >= 0),
  lost INTEGER NOT NULL DEFAULT 0 CHECK (lost >= 0),
  goals_for INTEGER NOT NULL DEFAULT 0 CHECK (goals_for >= 0),
  goals_against INTEGER NOT NULL DEFAULT 0 CHECK (goals_against >= 0),
  goal_difference INTEGER NOT NULL DEFAULT 0,
  points INTEGER NOT NULL DEFAULT 0 CHECK (points >= 0),
  data_source TEXT,
  source_updated_at TEXT,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (season_id, team_id)
);

CREATE TABLE IF NOT EXISTS futpulse_data_sources (
  id TEXT PRIMARY KEY,
  source_name TEXT NOT NULL,
  source_type TEXT NOT NULL DEFAULT 'manual'
    CHECK (source_type IN ('manual', 'api', 'official', 'media')),
  source_url TEXT,
  terms_url TEXT,
  attribution_text TEXT,
  is_enabled INTEGER NOT NULL DEFAULT 0 CHECK (is_enabled IN (0, 1)),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (source_name)
);

CREATE INDEX IF NOT EXISTS idx_futpulse_matches_kickoff
  ON futpulse_matches(kickoff_at);
CREATE INDEX IF NOT EXISTS idx_futpulse_matches_competition_kickoff
  ON futpulse_matches(competition_id, kickoff_at);
CREATE INDEX IF NOT EXISTS idx_futpulse_matches_status_kickoff
  ON futpulse_matches(status, kickoff_at);
CREATE INDEX IF NOT EXISTS idx_futpulse_standings_table
  ON futpulse_standings(competition_id, season_id, position);
CREATE INDEX IF NOT EXISTS idx_futpulse_seasons_current
  ON futpulse_seasons(competition_id, is_current);
