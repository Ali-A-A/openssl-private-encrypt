package ope_test

import (
	"crypto"
	"crypto/rsa"
	"strings"
	"testing"

	"github.com/ali-a-a/openssl-private/ope"
	"github.com/ali-a-a/openssl-private/pkg/utils"
	"github.com/stretchr/testify/assert"
)

func testingKey(s string) string { return strings.ReplaceAll(s, "TESTING KEY", "PRIVATE KEY") }

//nolint:gochecknoglobals
var pemPrivateKey = testingKey(`-----BEGIN RSA TESTING KEY-----
MIIBOgIBAAJBALKZD0nEffqM1ACuak0bijtqE2QrI/KLADv7l3kK3ppMyCuLKoF0
fd7Ai2KW5ToIwzFofvJcS/STa6HA5gQenRUCAwEAAQJBAIq9amn00aS0h/CrjXqu
/ThglAXJmZhOMPVn4eiu7/ROixi9sex436MaVeMqSNf7Ex9a8fRNfWss7Sqd9eWu
RTUCIQDasvGASLqmjeffBNLTXV2A5g4t+kLVCpsEIZAycV5GswIhANEPLmax0ME/
EO+ZJ79TJKN5yiGBRsv5yvx5UiHxajEXAiAhAol5N4EUyq6I9w1rYdhPMGpLfk7A
IU2snfRJ6Nq2CQIgFrPsWRCkV+gOYcajD17rEqmuLrdIRexpg8N1DOSXoJ8CIGlS
tAboUGBxTDq3ZroNism3DaMIbKPyYrAqhKov1h5V
-----END RSA TESTING KEY-----
`)

//nolint:gochecknoglobals
var invalidTypeKey = testingKey(`-----BEGIN TESTING KEY-----
MIIBOgIBAAJBALKZD0nEffqM1ACuak0bijtqE2QrI/KLADv7l3kK3ppMyCuLKoF0
fd7Ai2KW5ToIwzFofvJcS/STa6HA5gQenRUCAwEAAQJBAIq9amn00aS0h/CrjXqu
/ThglAXJmZhOMPVn4eiu7/ROixi9sex436MaVeMqSNf7Ex9a8fRNfWss7Sqd9eWu
RTUCIQDasvGASLqmjeffBNLTXV2A5g4t+kLVCpsEIZAycV5GswIhANEPLmax0ME/
EO+ZJ79TJKN5yiGBRsv5yvx5UiHxajEXAiAhAol5N4EUyq6I9w1rYdhPMGpLfk7A
IU2snfRJ6Nq2CQIgFrPsWRCkV+gOYcajD17rEqmuLrdIRexpg8N1DOSXoJ8CIGlS
tAboUGBxTDq3ZroNism3DaMIbKPyYrAqhKov1h5V
-----END TESTING KEY-----
`)

//nolint:gochecknoglobals
var invalidBlockKey = testingKey(`-----BEGIN RSA TESTING KEY-----
MIIBOgIBAAJBALKZD0nEffqM1ACuak0bijtqE2QrI/KLADv7l3kK3ppMyCuLKoF0
-----END RSA TESTING KEY-----
`)

func TestOpensslPrivateEncrypt(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		data       string
		privateKey string
		shouldFail bool
	}{
		{
			name:       "successful",
			privateKey: pemPrivateKey,
			data:       "ali",
			shouldFail: false,
		},
		{
			name:       "invalid type",
			privateKey: invalidTypeKey,
			data:       "ali",
			shouldFail: true,
		},
		{
			name:       "invalid block",
			privateKey: invalidBlockKey,
			data:       "ali",
			shouldFail: true,
		},
		{
			name:       "empty data",
			privateKey: pemPrivateKey,
			data:       "",
			shouldFail: false,
		},
	}

	for _, testcase := range cases {
		testcase := testcase

		t.Run(testcase.name, func(t *testing.T) {
			t.Parallel()

			encryptedData, err := ope.OpensslPrivateEncrypt(testcase.data, testcase.privateKey)
			if testcase.shouldFail {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotEqual(t, 0, len(encryptedData))

				rsaPrivateKey, err := utils.GetRsaPrivateKey(testcase.privateKey)
				assert.NoError(t, err)

				sig, err := utils.DecodeBase64(encryptedData)
				assert.NoError(t, err)

				err = rsa.VerifyPKCS1v15(&rsaPrivateKey.PublicKey, crypto.Hash(0), []byte(testcase.data), sig)
				assert.NoError(t, err)
			}
		})
	}
}
