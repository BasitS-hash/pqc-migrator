// Deliberately quantum-vulnerable Go fixture for regex scanner tests.
package fixtures

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
)

// PQC001: RSA key generation.
func makeRSA() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// PQC002: ECDSA key generation.
func makeECDSA() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// PQC005: DSA key generation.
func makeDSA() *dsa.PrivateKey {
	var key dsa.PrivateKey
	return &key
}

// PQC006: MD5 hashing.
func weakHash(data []byte) [16]byte {
	return md5.Sum(data)
}
