// Génère la paire de clés Ed25519 — À EXÉCUTER UNE SEULE FOIS : node generer-cles.js
// - La clé PRIVÉE va dans la variable d'environnement n8n HANA_LICENCE_PRIVATE_KEY (jamais dans l'app !)
// - La clé PUBLIQUE (base64, 32 octets) va dans LicenceManager.swift et licence.py
const crypto = require('crypto');

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');

const privatePem = privateKey.export({ format: 'pem', type: 'pkcs8' });
// Les 32 derniers octets du DER SPKI = clé publique brute (format attendu par CryptoKit et cryptography)
const publicRaw = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);

console.log('=== CLÉ PRIVÉE (n8n : HANA_LICENCE_PRIVATE_KEY, sur une seule ligne) ===');
console.log(privatePem.trim().replace(/\n/g, '\\n'));
console.log('\n=== CLÉ PUBLIQUE (Swift + Flask) ===');
console.log(publicRaw.toString('base64'));
