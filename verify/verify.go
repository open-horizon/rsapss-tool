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

// KeyMapping is a simple container for (key, signature) pairs
type KeyMapping struct {
	PublicKeyPath string
	Signature     string
}

func (m *KeyMapping) String() string {
	return fmt.Sprintf("PublicKeyPath: %v, Signature: %v", m.PublicKeyPath, m.Signature)
}

// Input takes given publicKeyPath, input byte array, and signature string.
// This function returns true iff the signature of the input can be verified by
// the public key.
func Input(publicKeyPath string, signature string, input []byte) (bool, error) {

	verified, _, err := InputVerifiedByAll([]*KeyMapping{&KeyMapping{publicKeyPath, signature}}, input)
	return verified, err
}

// InputVerifiedByAll returns true iff the signature of the input is verified
// by all of the specified keyfiles. In case of errors processing keyfiles, an
// error will be returned. In case of verification failure, all failed
// KeyMappings will be returned.
func InputVerifiedByAll(keyMappings []*KeyMapping, input []byte) (bool, []*KeyMapping, error) {
	var failed []*KeyMapping

	hasher := sha256.New()
	_, err := hasher.Write(input)
	if err != nil {
		return false, failed, err
	}

	if len(keyMappings) == 0 {
		return false, failed, fmt.Errorf("No keymappings provided; input not verified")
	}

	for _, keyMapping := range keyMappings {
		pubkeyRaw, err := ioutil.ReadFile(keyMapping.PublicKeyPath)
		if err != nil {
			return false, failed, err
		}

		block, _ := pem.Decode(pubkeyRaw)
		if block == nil {
			return false, failed, fmt.Errorf("Unable to find PEM block in the provided public key: %v", keyMapping.PublicKeyPath)
		}

		pubkey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return false, failed, err
		}

		signature, err := base64.StdEncoding.DecodeString(keyMapping.Signature)
		if err != nil {
			return false, failed, err
		}

		if err := rsa.VerifyPSS(pubkey.(*rsa.PublicKey), crypto.SHA256, hasher.Sum(nil), signature, nil); err != nil {
			failed = append(failed, &KeyMapping{keyMapping.PublicKeyPath, keyMapping.Signature})
		}
	}

	// if the signature was verified by all of the given keys we return true
	return len(failed) == 0, failed, nil
}
