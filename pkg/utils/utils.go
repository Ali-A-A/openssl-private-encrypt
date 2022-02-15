package utils

import "encoding/base64"

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
