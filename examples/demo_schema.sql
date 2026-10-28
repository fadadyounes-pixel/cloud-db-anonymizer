-- Demo database for trying Cloud-DB-Anonymizer:  psql $DATABASE_URL -f examples/demo_schema.sql
CREATE TABLE users (
  id            serial PRIMARY KEY,
  email         varchar(120) UNIQUE NOT NULL,
  full_name     text,
  phone         varchar(30),
  date_of_birth date,
  last_login_ip text,
  settings      jsonb DEFAULT '{}'::jsonb,
  created_at    timestamptz DEFAULT now()
);
CREATE TABLE payments (
  id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  user_id      int REFERENCES users(id),
  card_number  varchar(19),
  iban         text,
  billing_name text,
  amount_cents int NOT NULL,
  tags         text[]
);
CREATE TABLE audit_logs (id serial PRIMARY KEY, msg text);

INSERT INTO users (email, full_name, phone, date_of_birth, last_login_ip, settings) VALUES
 ('jane.doe@acme.com', 'Jane Doe', '+212 600-111222', '1988-04-12', '41.250.12.9', '{"theme":"dark","newsletter":true}'),
 ('o''brien@acme.com', 'Liam O''Brien', '+1 415 555 0199', '1975-11-02', '8.8.8.8', '{"theme":"light"}'),
 ('yuki@example.jp', 'Yuki Tanaka', NULL, NULL, NULL, '[1,2,3]');
INSERT INTO payments (user_id, card_number, iban, billing_name, amount_cents, tags) VALUES
 (1, '4111111111111111', 'GB82WEST12345698765432', 'Jane Doe', 4999, ARRAY['pro','annual']),
 (1, '4111111111111111', 'GB82WEST12345698765432', 'Jane Doe', 999, NULL),
 (2, '5500000000000004', NULL, 'Liam O''Brien', 2500, ARRAY['monthly']);
INSERT INTO audit_logs (msg) VALUES ('login jane'), ('login liam');
