package ope

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/ali-a-a/openssl-private/pkg/utils"
)

// OpensslPrivateEncrypt encrypts data using privateKey.
// privateKey should be in PKCS1.
func OpensslPrivateEncrypt(data, privateKey string) (string, error) {
	rsaPrivateKey, err := utils.GetRsaPrivateKey(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to get rsa private key: %w", err)
	}

	s, err := rsa.SignPKCS1v15(rand.Reader, rsaPrivateKey, crypto.Hash(0), []byte(data))
	if err != nil {
		return "", fmt.Errorf("failed to encrypt data: %w", err)
	}

	return utils.EncodeBase64(s), nil
}
