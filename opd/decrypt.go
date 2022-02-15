package opd

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

// OpensslPrivateDecrypt decrypts encrypted data using privateKey.
// privateKey should be in PKCS1.
func OpensslPrivateDecrypt(encryptedData, privateKey string) (string, error) {
	block, _ := pem.Decode([]byte(privateKey))
	if block == nil {
		return "",  errors.New("block is nil")
	}

	if block.Type != RSAPrivateType {
		return "", errors.New("rsa private type is invalid")
	}

	rsaPrivateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %w", err)
	}

	ciphertext, err := utils.DecodeBase64(encryptedData)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}

	d, err := rsa.DecryptPKCS1v15(rand.Reader, rsaPrivateKey, ciphertext)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt data: %w", err)
	}

	return string(d), nil
}
