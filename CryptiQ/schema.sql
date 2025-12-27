-- schema.sql (Postgres)
-- Creates your full schema (tables + constraints + indexes) based on the SQLite CREATE TABLEs you pasted.
-- Safe to run on an empty database.

BEGIN;

-- -------------------------
-- USERS
-- -------------------------
CREATE TABLE IF NOT EXISTS users (
  id                     BIGSERIAL PRIMARY KEY,
  username               TEXT NOT NULL UNIQUE,
  email                  TEXT NOT NULL UNIQUE,
  password_hash          TEXT NOT NULL,
  is_admin               BOOLEAN NOT NULL DEFAULT FALSE,
  created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  banned                 BOOLEAN NOT NULL DEFAULT FALSE,
  has_posted             BOOLEAN NOT NULL DEFAULT FALSE,
  labs_info_seen         BOOLEAN NOT NULL DEFAULT FALSE,

  is_pro                 BOOLEAN NOT NULL DEFAULT FALSE,
  stripe_customer_id     TEXT,
  pro_since              TIMESTAMPTZ,
  stripe_subscription_id TEXT,
  pro_until              TIMESTAMPTZ,

  pro_current_period_end TIMESTAMPTZ,
  pro_cancel_at_period_end BOOLEAN NOT NULL DEFAULT FALSE
);

-- -------------------------
-- POSTS
-- -------------------------
CREATE TABLE IF NOT EXISTS posts (
  id            BIGSERIAL PRIMARY KEY,
  user_id       BIGINT REFERENCES users(id) ON DELETE SET NULL,
  title         TEXT NOT NULL,
  body          TEXT NOT NULL,
  image_filename TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  pinned        BOOLEAN NOT NULL DEFAULT FALSE,
  upvotes       INTEGER NOT NULL DEFAULT 0,
  downvotes     INTEGER NOT NULL DEFAULT 0
);

-- -------------------------
-- COMMENTS
-- -------------------------
CREATE TABLE IF NOT EXISTS comments (
  id         BIGSERIAL PRIMARY KEY,
  post_id    BIGINT NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
  user_id    BIGINT REFERENCES users(id) ON DELETE SET NULL,
  body       TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- -------------------------
-- POST VOTES
-- -------------------------
CREATE TABLE IF NOT EXISTS post_votes (
  id      BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  post_id BIGINT NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
  vote    INTEGER NOT NULL CHECK (vote IN (-1, 0, 1)),
  UNIQUE (user_id, post_id)
);

-- -------------------------
-- NOTIFICATIONS
-- -------------------------
CREATE TABLE IF NOT EXISTS notifications (
  id         BIGSERIAL PRIMARY KEY,
  user_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  actor_id   BIGINT REFERENCES users(id) ON DELETE SET NULL,
  post_id    BIGINT NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
  comment_id BIGINT REFERENCES comments(id) ON DELETE CASCADE,
  message    TEXT NOT NULL,
  is_read    BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- -------------------------
-- WEEKLY CIPHER
-- -------------------------
CREATE TABLE IF NOT EXISTS weekly_cipher (
  id          INTEGER PRIMARY KEY CHECK (id = 1),
  week_number INTEGER NOT NULL,
  title       TEXT NOT NULL,
  description TEXT,
  ciphertext  TEXT NOT NULL,
  solution    TEXT NOT NULL,
  hint        TEXT,
  posted_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- -------------------------
-- CIPHER SUBMISSIONS
-- -------------------------
CREATE TABLE IF NOT EXISTS cipher_submissions (
  id                BIGSERIAL PRIMARY KEY,
  user_id           BIGINT REFERENCES users(id) ON DELETE SET NULL,
  username          TEXT,
  cipher_week       INTEGER,
  answer            TEXT NOT NULL,
  is_correct        BOOLEAN NOT NULL DEFAULT FALSE,
  score             INTEGER NOT NULL DEFAULT 0,
  submitted_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  season            INTEGER NOT NULL DEFAULT 1,
  solve_time_seconds INTEGER
);

-- -------------------------
-- WORKSPACES
-- -------------------------
CREATE TABLE IF NOT EXISTS workspaces (
  id                   BIGSERIAL PRIMARY KEY,
  owner_id              BIGINT NOT NULL REFERENCES users(id),
  title                TEXT NOT NULL DEFAULT 'Untitled Workspace',
  cipher_text           TEXT NOT NULL DEFAULT '',
  notes                TEXT NOT NULL DEFAULT '',
  cipher_image_filename TEXT,
  created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  order_index           INTEGER NOT NULL DEFAULT 0,
  share_token           TEXT,
  is_shared             BOOLEAN NOT NULL DEFAULT FALSE,
  last_edited_by        BIGINT REFERENCES users(id) ON DELETE SET NULL
);

-- -------------------------
-- WORKSPACE IMAGES
-- -------------------------
CREATE TABLE IF NOT EXISTS workspace_images (
  id           BIGSERIAL PRIMARY KEY,
  workspace_id BIGINT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  filename     TEXT NOT NULL,
  label        TEXT NOT NULL DEFAULT 'Image',
  sort_index   INTEGER NOT NULL DEFAULT 0,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- -------------------------
-- WORKSPACE COLLABORATORS
-- -------------------------
CREATE TABLE IF NOT EXISTS workspace_collaborators (
  id           BIGSERIAL PRIMARY KEY,
  workspace_id BIGINT NOT NULL REFERENCES workspaces(id),
  user_id      BIGINT NOT NULL REFERENCES users(id),
  role         TEXT NOT NULL DEFAULT 'editor', -- editor | viewer
  added_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (workspace_id, user_id)
);

-- -------------------------
-- WORKSPACE HISTORY
-- -------------------------
CREATE TABLE IF NOT EXISTS workspace_history (
  id           BIGSERIAL PRIMARY KEY,
  workspace_id BIGINT NOT NULL REFERENCES workspaces(id),
  owner_id     BIGINT NOT NULL REFERENCES users(id),
  title        TEXT NOT NULL DEFAULT '',
  notes        TEXT NOT NULL DEFAULT '',
  cipher_text  TEXT NOT NULL DEFAULT '',
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  reason       TEXT NOT NULL DEFAULT 'save'
);

-- -------------------------
-- INDEXES (match your query patterns)
-- -------------------------

-- posts browsing/sorting
CREATE INDEX IF NOT EXISTS idx_posts_created_at ON posts (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_posts_pinned_created ON posts (pinned DESC, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_posts_user_id ON posts (user_id);

-- comments
CREATE INDEX IF NOT EXISTS idx_comments_post_created ON comments (post_id, created_at DESC);

-- votes
CREATE INDEX IF NOT EXISTS idx_post_votes_post ON post_votes (post_id);

-- notifications dropdown + unread badge
CREATE INDEX IF NOT EXISTS idx_notifications_user_created ON notifications (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notifications_user_unread ON notifications (user_id, is_read);

-- weekly / submissions
CREATE INDEX IF NOT EXISTS idx_cipher_submissions_week_correct ON cipher_submissions (cipher_week, is_correct);
CREATE INDEX IF NOT EXISTS idx_cipher_submissions_user ON cipher_submissions (user_id);
CREATE INDEX IF NOT EXISTS idx_cipher_submissions_season ON cipher_submissions (season);

-- workspaces list ordering
CREATE INDEX IF NOT EXISTS idx_workspaces_owner_order ON workspaces (owner_id, order_index);
CREATE INDEX IF NOT EXISTS idx_workspaces_updated ON workspaces (updated_at DESC);

-- share token uniqueness (only when token exists)
CREATE UNIQUE INDEX IF NOT EXISTS idx_workspaces_share_token
  ON workspaces (share_token)
  WHERE share_token IS NOT NULL;

-- images tabs ordering
CREATE INDEX IF NOT EXISTS idx_workspace_images_ws_sort ON workspace_images (workspace_id, sort_index, id);

-- collaborators list
CREATE INDEX IF NOT EXISTS idx_wc_workspace ON workspace_collaborators (workspace_id);
CREATE INDEX IF NOT EXISTS idx_wc_user ON workspace_collaborators (user_id);

-- history
CREATE INDEX IF NOT EXISTS idx_workspace_history_ws_created ON workspace_history (workspace_id, created_at DESC);

COMMIT;
