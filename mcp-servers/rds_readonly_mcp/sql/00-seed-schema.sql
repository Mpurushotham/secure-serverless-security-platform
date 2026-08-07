-- Synthetic pharmacy e-commerce schema.
--
-- EVERY VALUE IN THIS FILE IS FABRICATED. The personnummer are deliberately
-- invalid (they fail the Luhn check used by Skatteverket), the emails are on
-- example.com, and the prescriptions are nonsense. Never seed this repository
-- with production data — the whole point of the exercise is that the agent is
-- untrusted, and an untrusted agent plus real Art. 9 data is a breach waiting
-- for a demo.
--
-- Shape mirrors a real online pharmacy because the controls only mean anything
-- against realistic joins: customer -> prescription (health data, GDPR Art. 9)
-- and customer -> order -> item -> product.

CREATE SCHEMA IF NOT EXISTS pharmacy;
SET search_path TO pharmacy, public;

CREATE TABLE IF NOT EXISTS customers (
    id            bigserial PRIMARY KEY,
    personnummer  text        NOT NULL UNIQUE,   -- Art. 9 adjacent: national ID
    full_name     text        NOT NULL,
    email         text        NOT NULL,
    phone         text,
    street        text,
    postal_code   text,
    city          text,
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS products (
    id                    bigserial PRIMARY KEY,
    name                  text        NOT NULL,
    category              text        NOT NULL,
    requires_prescription boolean     NOT NULL DEFAULT false,
    price_sek             numeric(10,2) NOT NULL
);

CREATE TABLE IF NOT EXISTS prescriptions (
    id                bigserial PRIMARY KEY,
    customer_id       bigint      NOT NULL REFERENCES customers(id),
    medication        text        NOT NULL,      -- GDPR Art. 9: health data
    dosage            text        NOT NULL,
    prescriber_hsa_id text        NOT NULL,      -- Swedish healthcare practitioner ID
    issued_at         date        NOT NULL,
    -- The consent flag is the RLS pivot. An analytics agent may only ever see
    -- records whose data subject consented to secondary processing.
    consent_analytics boolean     NOT NULL DEFAULT false
);

CREATE TABLE IF NOT EXISTS orders (
    id          bigserial PRIMARY KEY,
    customer_id bigint      NOT NULL REFERENCES customers(id),
    status      text        NOT NULL,
    total_sek   numeric(10,2) NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS order_items (
    id             bigserial PRIMARY KEY,
    order_id       bigint  NOT NULL REFERENCES orders(id),
    product_id     bigint  NOT NULL REFERENCES products(id),
    quantity       integer NOT NULL,
    unit_price_sek numeric(10,2) NOT NULL
);

INSERT INTO customers (personnummer, full_name, email, phone, street, postal_code, city)
VALUES
  ('19850101-0000', 'Astrid Lindqvist',  'astrid@example.com',  '+46700000001', 'Vasagatan 1',  '11157', 'Stockholm'),
  ('19900215-0000', 'Björn Karlsson',    'bjorn@example.com',   '+46700000002', 'Kungsgatan 4', '41119', 'Göteborg'),
  ('19771103-0000', 'Cecilia Nyström',   'cecilia@example.com', '+46700000003', 'Storgatan 9',  '21142', 'Malmö'),
  ('20010730-0000', 'Dmitri Andersson',  'dmitri@example.com',  '+46700000004', 'Drottninggatan 22', '11151', 'Stockholm')
ON CONFLICT (personnummer) DO NOTHING;

INSERT INTO products (name, category, requires_prescription, price_sek)
VALUES
  ('Paracetamol 500mg',   'analgesic',    false, 39.00),
  ('Ibuprofen 400mg',     'analgesic',    false, 49.50),
  ('Amoxicillin 500mg',   'antibiotic',   true, 189.00),
  ('Sertraline 50mg',     'psychiatric',  true, 249.00),
  ('Vitamin D3 2000IU',   'supplement',   false, 129.00)
ON CONFLICT DO NOTHING;

INSERT INTO prescriptions (customer_id, medication, dosage, prescriber_hsa_id, issued_at, consent_analytics)
VALUES
  (1, 'Sertraline 50mg',   '1 tablet daily',        'SE2321000016-1001', '2026-01-15', true),
  (2, 'Amoxicillin 500mg', '1 tablet 3x daily',     'SE2321000016-1002', '2026-02-02', true),
  -- Consent withheld: RLS must hide this row from the agent entirely.
  (3, 'Sertraline 50mg',   '2 tablets daily',       'SE2321000016-1003', '2026-02-20', false),
  (4, 'Amoxicillin 500mg', '1 tablet 2x daily',     'SE2321000016-1001', '2026-03-05', false)
ON CONFLICT DO NOTHING;

INSERT INTO orders (customer_id, status, total_sek)
VALUES (1, 'shipped', 288.00), (2, 'shipped', 189.00),
       (3, 'processing', 249.00), (4, 'cancelled', 88.50)
ON CONFLICT DO NOTHING;

INSERT INTO order_items (order_id, product_id, quantity, unit_price_sek)
VALUES (1, 4, 1, 249.00), (1, 1, 1, 39.00), (2, 3, 1, 189.00),
       (3, 4, 1, 249.00), (4, 1, 1, 39.00), (4, 2, 1, 49.50)
ON CONFLICT DO NOTHING;
