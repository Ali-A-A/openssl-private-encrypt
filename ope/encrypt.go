package ope

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/ali-a-a/openssl-private-encrypt/pkg/utils"
	"github.com/pkg/errors"
)

const (
	// RSAPrivateType is type that taken from the preamble.
	RSAPrivateType = "RSA PRIVATE KEY"
)

// OpensslPrivateEncrypt encrypts data using privateKey.
// privateKey should be in PKCS1.
func OpensslPrivateEncrypt(data, privateKey string) (string, error) {
	block, _ := pem.Decode([]byte(privateKey))
	if block == nil {
		return "", errors.New("block is nil")
	}

	if block.Type != RSAPrivateType {
		return "", errors.New("rsa private type is invalid")
	}

	rsaPrivateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %w", err)
	}

	s, err := rsa.EncryptPKCS1v15(rand.Reader, &rsaPrivateKey.PublicKey, []byte(data))
	if err != nil {
		return "", fmt.Errorf("failed to encrypt data: %w", err)
	}

	return utils.EncodeBase64(s), nil
}
