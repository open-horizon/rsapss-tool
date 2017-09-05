package verify

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

// Input takes given publicKeyPath, input byte array, and signature string.
// This function returns true iff the signature of the input can be verified by
// the public key.
func Input(publicKeyPath string, input []byte, signature []byte) (bool, error) {
	return InputVerifiedByAll([]string{publicKeyPath}, input, signature)
}

// InputVerifiedByAll returns true iff the signature of the input is
// verified by all of the specified keyfiles.
func InputVerifiedByAll(publicKeyPaths []string, input []byte, signature []byte) (bool, error) {
	hasher := sha256.New()
	_, err := hasher.Write(input)
	if err != nil {
		return false, err
	}

	decoded, err := base64.StdEncoding.DecodeString(string(signature))
	if err != nil {
		return false, err
	}

	// check provided keys until we get a match
	for _, keyPath := range publicKeyPaths {
		pubkey, err := ioutil.ReadFile(keyPath)
		if err != nil {
			return false, err
		}

		block, _ := pem.Decode(pubkey)
		if block == nil {
			return false, fmt.Errorf("Unable to find PEM block in the provided publick key: %v", keyPath)
		}

		publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return false, err
		}

		err = rsa.VerifyPSS(publicKey.(*rsa.PublicKey), crypto.SHA256, hasher.Sum(nil), decoded, nil)
		if err != nil {
			return false, nil
		}
	}

	// if the signature was verified by all of the given keys we return true
	return true, nil
}
