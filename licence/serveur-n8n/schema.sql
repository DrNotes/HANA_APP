-- Schéma PostgreSQL (ou Supabase) pour les licences HANA

CREATE TABLE IF NOT EXISTS licences (
  key           text PRIMARY KEY,                 -- ex. HANA-7F3A-91BC-44D2
  email         text,
  plan          text        NOT NULL DEFAULT 'standard',
  max_machines  int         NOT NULL DEFAULT 2,   -- nombre de Mac autorisés
  expires_at    timestamptz,                      -- NULL = licence perpétuelle
  revoked       boolean     NOT NULL DEFAULT false,
  created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS activations (
  id           bigserial PRIMARY KEY,
  licence_key  text        NOT NULL REFERENCES licences(key) ON DELETE CASCADE,
  machine_id   text        NOT NULL,              -- SHA-256 de l'UUID matériel du Mac
  app_version  text,
  first_seen   timestamptz NOT NULL DEFAULT now(),
  last_seen    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (licence_key, machine_id)
);

-- Créer une licence (clé aléatoire au format HANA-XXXX-XXXX-XXXX) :
-- INSERT INTO licences (key, email, max_machines)
-- VALUES ('HANA-' || upper(substr(md5(random()::text),1,4)) || '-'
--                 || upper(substr(md5(random()::text),1,4)) || '-'
--                 || upper(substr(md5(random()::text),1,4)),
--         'client@exemple.com', 2)
-- RETURNING key;

-- Révoquer une licence :
-- UPDATE licences SET revoked = true WHERE key = 'HANA-XXXX-XXXX-XXXX';

-- Voir les Mac activés :
-- SELECT * FROM activations WHERE licence_key = 'HANA-XXXX-XXXX-XXXX';
