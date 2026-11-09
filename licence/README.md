# Système de licence HANA

```
App Swift ──(clé + ID du Mac)──► n8n /webhook/hana/activate ──► PostgreSQL
    ▲                                   │ signe la licence (Ed25519, clé privée)
    └────────── licence signée ◄────────┘
    │  stockée dans le Trousseau, vérifiée avec la clé publique
    └──(en-tête X-Hana-Licence)──► Flask : @licence_requise
```

## Fichiers
| Fichier | Rôle |
|---|---|
| `serveur-n8n/schema.sql` | Tables `licences` et `activations` |
| `serveur-n8n/generer-cles.js` | Génère la paire de clés (une seule fois) |
| `serveur-n8n/workflow-activation-hana.json` | Workflow n8n à importer (activation + désactivation) |
| `swift/LicenceManager.swift` | Activation, vérification, Trousseau, ID du Mac |
| `swift/ActivationView.swift` | Écran SwiftUI « Entrer votre clé » |
| `flask/licence.py` | Décorateur `@licence_requise` pour vos routes Flask |

## Installation

1. **Clés** : `node serveur-n8n/generer-cles.js`
   - clé privée → variable d'environnement n8n `HANA_LICENCE_PRIVATE_KEY` (à garder secrète) ;
   - clé publique → `LicenceConfig.publicKeyBase64` (Swift) et `PUBLIC_KEY_B64` (Python).
2. **Base** : exécuter `schema.sql` sur PostgreSQL (ou Supabase).
3. **n8n** :
   - variables d'environnement : `NODE_FUNCTION_ALLOW_BUILTIN=crypto` et `N8N_BLOCK_ENV_ACCESS_IN_NODE=false` ;
   - importer `workflow-activation-hana.json`, choisir l'identifiant Postgres sur les 3 nœuds Postgres, activer le workflow ;
   - n8n doit être exposé en **HTTPS**.
4. **Swift** : ajouter les 2 fichiers au projet Xcode, renseigner les URL et la clé publique. Si l'app est sandboxée : entitlement `com.apple.security.network.client`.
5. **Flask** : `pip install cryptography`, puis `init_licence(app)` et `@licence_requise` sur les routes. Régler `FLASK_LOCAL` (True si Flask est embarqué dans l'app sur le Mac du client).

## Créer / révoquer une licence
Voir les requêtes en commentaire dans `schema.sql`.

## Comportement
- 2 Mac par clé (colonne `max_machines`), le client peut libérer un Mac via `desactiver()`.
- La licence fonctionne **30 jours hors ligne** (`JOURS_HORS_LIGNE` dans le nœud « Signer licence »), revalidation silencieuse chaque jour quand Internet est disponible.
- Licence révoquée ou expirée : refusée au prochain contact avec le serveur.

## API du webhook
`POST /webhook/hana/activate` — corps `{"key","machineId","appVersion"}`
- 200 → `{"payload","signature"}`
- 400 / 403 / 404 → `{"error": "message lisible"}`

`POST /webhook/hana/deactivate` — même corps → `{"ok": true}`
