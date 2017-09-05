package generatekeys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
)

// Returns composed path if there is not a name conflict and the directory is
// writable.
func pathIsAvail(dir string, file string) (string, error) {
	path, err := filepath.Abs(filepath.Join(dir, file))
	if err != nil {
		return "", err
	}

	if _, err := os.Stat(path); err == nil {
		return "", fmt.Errorf("File already exists: %v", path)
	} else if !os.IsNotExist(err) {
		return "", err
	}

	if unix.Access(dir, unix.W_OK) != nil {
		return "", fmt.Errorf("Path is not writable: %v", path)
	}

	return path, nil
}

// Write writes a new keypair to the given outputDir. It avoids overwriting
// existing keys of the same name.
func Write(outputDir string, keyLength int) ([]string, error) {
	var empty = []string{}

	if outputDir == "" {
		return empty, errors.New("Required parameter outputDir has invalid value, nil")
	}

	pubPath, err := pathIsAvail(outputDir, "public.key")
	if err != nil {
		return empty, err
	}

	privPath, err := pathIsAvail(outputDir, "private.key")
	if err != nil {
		return empty, err
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, keyLength)
	if err != nil {
		return empty, err
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return empty, err
	}

	pubEnc := &pem.Block{
		Type:    "PUBLIC KEY",
		Headers: nil,
		Bytes:   pubKeyBytes,
	}

	pubOut, err := os.Create(pubPath)
	if err != nil {
		return empty, err
	}
	defer pubOut.Close()

	if err = pem.Encode(pubOut, pubEnc); err != nil {
		return empty, err
	}

	// http://golang.org/pkg/encoding/pem/#Block
	var privEnc = &pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   x509.MarshalPKCS1PrivateKey(privateKey)}

	privOut, err := os.Create(privPath)
	if err != nil {
		return empty, err
	}
	defer privOut.Close()

	if err = pem.Encode(privOut, privEnc); err != nil {
		return empty, err
	}

	return []string{privPath, pubPath}, nil
}
