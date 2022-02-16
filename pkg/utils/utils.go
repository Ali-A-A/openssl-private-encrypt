package utils

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/pkg/errors"
)

const (
	// RSAPrivateType is type that taken from the preamble.
	RSAPrivateType = "RSA PRIVATE KEY"
)

// EncodeBase64 encodes base64 input into byte array.
func EncodeBase64(in []byte) string {
	return base64.StdEncoding.EncodeToString(in)
}

// DecodeBase64 decodes base64 input into byte array.
func DecodeBase64(in string) ([]byte, error) {
	n, err := base64.StdEncoding.DecodeString(in)
	if err != nil {
		return nil, err
	}

	return n, nil
}

// GetRsaPrivateKey converts string private key to *rsa.PrivateKey.
func GetRsaPrivateKey(privateKey string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privateKey))
	if block == nil {
		return nil, errors.New("block is nil")
	}

	if block.Type != RSAPrivateType {
		return nil, errors.New("rsa private type is invalid")
	}

	rsaPrivateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return rsaPrivateKey, nil
}
