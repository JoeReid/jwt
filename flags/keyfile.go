package flags

import (
	"crypto/rsa"
	"fmt"
	"os"

	"github.com/golang-jwt/jwt"
)

type KeyFile string

func (k *KeyFile) PrivateKey() (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(string(*k))
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	return jwt.ParseRSAPrivateKeyFromPEM(data)
}

func (k *KeyFile) PublicKey() (*rsa.PublicKey, error) {
	data, err := os.ReadFile(string(*k))
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	return jwt.ParseRSAPublicKeyFromPEM(data)
}

func (k *KeyFile) Secret() (string, error) {
	if _, err := k.PrivateKey(); err == nil {
		return "", fmt.Errorf("key file is a private key")
	}

	if _, err := k.PublicKey(); err == nil {
		return "", fmt.Errorf("key file is a public key")
	}

	data, err := os.ReadFile(string(*k))
	if err != nil {
		return "", fmt.Errorf("failed to read key file: %w", err)
	}

	return string(data), nil
}

func (k *KeyFile) String() string {
	return string(*k)
}

func (k *KeyFile) Set(v string) error {
	if _, err := os.ReadFile(v); err != nil {
		return fmt.Errorf("failed to read key file: %w", err)
	}

	*k = KeyFile(v)
	return nil
}

func (k *KeyFile) Type() string {
	return "key file"
}
