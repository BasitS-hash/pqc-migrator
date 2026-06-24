// Deliberately quantum-vulnerable JavaScript fixture for regex scanner tests.
const crypto = require('crypto');

// PQC001: RSA keypair generation.
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
});

// PQC003: ECDH key exchange.
const ecdh = crypto.createECDH('prime256v1');
ecdh.generateKeys();

// PQC004: Diffie-Hellman.
const dh = crypto.createDiffieHellman(2048);

// PQC006: MD5 hashing.
const md5 = crypto.createHash('md5').update('x').digest('hex');

// PQC007: SHA-1 hashing.
const sha1 = crypto.createHash('sha1').update('x').digest('hex');

module.exports = { publicKey, privateKey, ecdh, dh, md5, sha1 };
