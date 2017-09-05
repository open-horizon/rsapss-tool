package sign

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

// Input taks a given privateKeyPath and input byte array and produces a
// cryptographic signature of the input. A base64-encoded signature is returned.
func Input(privateKeyPath string, input []byte) (string, error) {
	priv, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		return "", err
	}

	pemBlock, _ := pem.Decode(priv)
	if pemBlock == nil {
		return "", fmt.Errorf("Unable to find PEM block in provided private key: %v", privateKeyPath)
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if err != nil {
		return "", err
	}

	hasher := sha256.New()
	_, err = hasher.Write(input)
	if err != nil {
		return "", err
	}

	sig, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, hasher.Sum(nil), nil)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(sig), nil
}
