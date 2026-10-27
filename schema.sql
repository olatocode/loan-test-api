
CREATE TABLE loans (
  id                text PRIMARY KEY,                       -- e.g. 'LN-2041'
  customer_ref      text        NOT NULL,                   -- opaque id, NOT name/phone/email
  currency          char(3)     NOT NULL,
  amount_due_minor  bigint      NOT NULL CHECK (amount_due_minor > 0),
  amount_paid_minor bigint      NOT NULL DEFAULT 0 CHECK (amount_paid_minor >= 0),
  status            text        NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'paid')),
  created_at        timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE payments (
  id           bigserial   PRIMARY KEY,
  event_id     text        NOT NULL,
  loan_id      text        NOT NULL REFERENCES loans(id),
  amount_minor bigint      NOT NULL CHECK (amount_minor > 0),
  currency     char(3)     NOT NULL,
  paid_at      timestamptz NOT NULL,                        -- provider's time; for display/reporting only
  received_at  timestamptz NOT NULL DEFAULT now(),          -- our time

  CONSTRAINT payments_event_id_key UNIQUE (event_id)
);

CREATE INDEX payments_loan_id_idx ON payments (loan_id);
