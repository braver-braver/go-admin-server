-- +goose Up

-- Sorting of business lists follows Chinese ordering, like the reference mock
-- (localeCompare 'zh-Hans-CN'). Requires a PostgreSQL built with ICU.
CREATE COLLATION IF NOT EXISTS zh_sort (provider = icu, locale = 'zh-Hans-CN');

-- System configuration. The authorization kernel (internal/authz) validates
-- every change against the whole configuration under one lock, so references
-- between these tables are stored as id arrays and enforced by the kernel.
-- `position` keeps insertion order, which is the list order.

-- Bumped by every system-configuration write; servers cache the loaded
-- configuration until it changes.
CREATE TABLE system_state (
    singleton bool PRIMARY KEY DEFAULT true CHECK (singleton),
    revision  bigint NOT NULL DEFAULT 0
);
INSERT INTO system_state DEFAULT VALUES;

CREATE TABLE departments (
    id        text PRIMARY KEY,
    position  bigserial NOT NULL,
    name      text NOT NULL,
    code      text NOT NULL UNIQUE,
    parent_id text NOT NULL DEFAULT '',
    enabled   bool NOT NULL,
    protected bool NOT NULL DEFAULT false
);

CREATE TABLE permissions (
    id          text PRIMARY KEY,
    position    bigserial NOT NULL,
    name        text NOT NULL,
    code        text NOT NULL UNIQUE,
    description text NOT NULL DEFAULT '',
    protected   bool NOT NULL DEFAULT false
);

CREATE TABLE menus (
    id         text PRIMARY KEY,
    position   bigserial NOT NULL,
    name       text NOT NULL,
    parent_id  text NOT NULL DEFAULT '',
    kind       text NOT NULL CHECK (kind IN ('directory', 'page')),
    route_id   text NOT NULL DEFAULT '',
    enabled    bool NOT NULL,
    visible    bool NOT NULL,
    sort_order int  NOT NULL,
    protected  bool NOT NULL DEFAULT false
);

CREATE TABLE roles (
    id             text PRIMARY KEY,
    position       bigserial NOT NULL,
    name           text NOT NULL,
    code           text NOT NULL UNIQUE,
    enabled        bool NOT NULL,
    permission_ids text[] NOT NULL DEFAULT '{}',
    menu_ids       text[] NOT NULL DEFAULT '{}',
    scope          text NOT NULL CHECK (scope IN ('all', 'department', 'descendants', 'self', 'custom')),
    department_ids text[] NOT NULL DEFAULT '{}',
    protected      bool NOT NULL DEFAULT false
);

CREATE TABLE accounts (
    id                 text PRIMARY KEY,
    position           bigserial NOT NULL,
    name               text NOT NULL,
    email              text NOT NULL UNIQUE CHECK (email = lower(email)),
    enabled            bool NOT NULL,
    department_id      text NOT NULL,
    role_ids           text[] NOT NULL DEFAULT '{}',
    protected          bool NOT NULL DEFAULT false,
    password_hash      text NOT NULL,
    -- Sessions carry the version they were issued with; a password reset,
    -- disabling or re-enabling the account bumps it and revokes them.
    credential_version int NOT NULL DEFAULT 0
);

-- Server-side sessions. Only a hash of the cookie token is stored.
CREATE TABLE sessions (
    token_hash         bytea PRIMARY KEY,
    account_id         text NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    credential_version int  NOT NULL,
    csrf_token         text NOT NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    expires_at         timestamptz NOT NULL,
    ip                 text NOT NULL DEFAULT '',
    user_agent         text NOT NULL DEFAULT ''
);
CREATE INDEX sessions_account_idx ON sessions (account_id);
CREATE INDEX sessions_expires_idx ON sessions (expires_at);

-- Business users (the example CRUD module).
CREATE TABLE users (
    id            text PRIMARY KEY,
    department_id text NOT NULL REFERENCES departments (id) ON DELETE RESTRICT,
    created_by    text NOT NULL,
    first_name    text NOT NULL,
    last_name     text NOT NULL,
    username      text NOT NULL,
    email         text NOT NULL,
    phone_number  text NOT NULL,
    status        text NOT NULL CHECK (status IN ('active', 'inactive', 'invited', 'suspended')),
    role          text NOT NULL CHECK (role IN ('superadmin', 'admin', 'manager', 'cashier')),
    avatar_url    text NOT NULL DEFAULT '',
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX users_email_key ON users (lower(email));
CREATE UNIQUE INDEX users_username_key ON users (lower(username));
CREATE INDEX users_department_idx ON users (department_id);
CREATE INDEX users_created_by_idx ON users (created_by);

CREATE TABLE audit_logs (
    id            bigserial PRIMARY KEY,
    created_at    timestamptz NOT NULL DEFAULT now(),
    actor_id      text NOT NULL,
    actor_name    text NOT NULL,
    actor_email   text NOT NULL,
    department_id text NOT NULL DEFAULT '',
    action        text NOT NULL,
    target        text NOT NULL,
    detail        text NOT NULL,
    ip            text NOT NULL DEFAULT ''
);
CREATE INDEX audit_logs_created_idx ON audit_logs (created_at DESC, id DESC);
CREATE INDEX audit_logs_action_idx ON audit_logs (action);

CREATE TABLE uploads (
    id           text PRIMARY KEY,
    name         text NOT NULL,
    content_type text NOT NULL,
    size         bigint NOT NULL,
    uploaded_by  text NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE uploads;
DROP TABLE audit_logs;
DROP TABLE users;
DROP TABLE sessions;
DROP TABLE accounts;
DROP TABLE roles;
DROP TABLE menus;
DROP TABLE permissions;
DROP TABLE departments;
DROP TABLE system_state;
DROP COLLATION IF EXISTS zh_sort;
