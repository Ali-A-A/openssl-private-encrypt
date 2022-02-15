# openssl-private

![GitHub Workflow Status](https://github.com/ali-a-a/openssl-private/workflows/ci/badge.svg)
[![codecov](https://codecov.io/gh/ali-a-a/openssl-private/branch/main/graph/badge.svg)](https://codecov.io/gh/ali-a-a/openssl-private)

## Description
Encrypt/Decrypt data using pem private key.

## Usage

- `OpensslPrivateEncrypt`: \
  The first input is a data that we want to encrypt.
  The scond one is the private key. **It shoud be in pkcs1 format**.
  
- `OpensslPrivateDecrypt`: \
   The first input is a encrypted data that we want to decrypt.
   The scond one is the private key. **It shoud be in pkcs1 format**.
