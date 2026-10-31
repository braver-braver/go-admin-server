-- +goose Up

CREATE SEQUENCE ticket_number_seq;

CREATE TABLE tickets (
    id              text PRIMARY KEY,
    number          text NOT NULL UNIQUE,
    title           text NOT NULL,
    description     text NOT NULL,
    category        text NOT NULL CHECK (category IN ('consultation', 'fault', 'request', 'complaint')),
    priority        text NOT NULL CHECK (priority IN ('low', 'medium', 'high', 'urgent')),
    status          text NOT NULL CHECK (status IN ('open', 'in_progress', 'resolved', 'closed')),
    department_id   text NOT NULL REFERENCES departments (id) ON DELETE RESTRICT,
    -- Names are copied at write time so the timeline survives renamed or
    -- deleted accounts.
    created_by      text NOT NULL,
    created_by_name text NOT NULL,
    assignee_id     text,
    assignee_name   text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    resolved_at     timestamptz,
    closed_at       timestamptz,
    CHECK ((assignee_id IS NULL) = (assignee_name IS NULL))
);
CREATE INDEX tickets_department_idx ON tickets (department_id);
CREATE INDEX tickets_created_by_idx ON tickets (created_by);
CREATE INDEX tickets_assignee_idx ON tickets (assignee_id);
CREATE INDEX tickets_status_idx ON tickets (status);
CREATE INDEX tickets_updated_idx ON tickets (updated_at DESC, id DESC);

CREATE TABLE ticket_events (
    id            bigserial PRIMARY KEY,
    ticket_id     text NOT NULL REFERENCES tickets (id) ON DELETE CASCADE,
    kind          text NOT NULL CHECK (kind IN ('created', 'updated', 'comment', 'status_changed', 'assigned')),
    actor_id      text NOT NULL,
    actor_name    text NOT NULL,
    body          text NOT NULL DEFAULT '',
    from_status   text,
    to_status     text,
    assignee_name text,
    created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ticket_events_ticket_idx ON ticket_events (ticket_id, id);

-- +goose Down
DROP TABLE ticket_events;
DROP TABLE tickets;
DROP SEQUENCE ticket_number_seq;
