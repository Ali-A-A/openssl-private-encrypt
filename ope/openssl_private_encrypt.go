package ope

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
)

const (
	// RSAPrivateType is type that taken from the preamble.
	RSAPrivateType = "RSA PRIVATE KEY"
)

// OpensslPrivateEncrypt encrypt data using privateKey.
// privateKey should be PKCS1.
func OpensslPrivateEncrypt(data, privateKey string) (string, bool) {
	block, _ := pem.Decode([]byte(privateKey))
	if block == nil {
		return "", false
	}

	if block.Type != RSAPrivateType {
		return "", false
	}

	rsaPrivateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", false
	}

	s, err := rsa.SignPKCS1v15(rand.Reader, rsaPrivateKey, crypto.Hash(0), []byte(data))
	if err != nil {
		return "", false
	}

	return base64.StdEncoding.EncodeToString(s), true
}
