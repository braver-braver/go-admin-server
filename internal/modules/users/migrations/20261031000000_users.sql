-- +goose Up

-- Business users: the example CRUD module.
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

-- Avatar uploads; the bytes live in UPLOAD_DIR.
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
DROP TABLE users;
