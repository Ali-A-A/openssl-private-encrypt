package ope_test

import (
	"strings"
	"testing"

	"github.com/Ali-A-A/openssl-private-encrypt/ope"
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

	for _, tt := range cases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			encryptedData, ok := ope.OpensslPrivateEncrypt(tt.data, tt.privateKey)
			if tt.shouldFail {
				assert.Equal(t, false, ok)
			} else {
				assert.Equal(t, true, ok)
				assert.NotEqual(t, 0, len(encryptedData))
			}
		})
	}
}
