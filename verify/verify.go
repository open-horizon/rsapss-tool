package verify

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"hash"
	"io/ioutil"
)

// KeyMapping is a simple container for (key, signature) pairs
type KeyMapping struct {
	PublicKeyPath string
	Signature     string
}

const COMMON_ERROR = "COMMON_ERROR"

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
		signatureBytes, err := base64.StdEncoding.DecodeString(keyMapping.Signature)
		if err != nil {
			return false, failed, err
		}

		if ok, err := verify(keyMapping.PublicKeyPath, signatureBytes, hasher); !ok {
			switch err.(type) {
			case VerificationError:
				failed = append(failed, &KeyMapping{keyMapping.PublicKeyPath, keyMapping.Signature})
			default:
				return false, failed, err
			}
		}
	}

	// if the signature was verified by all of the given keys we return true
	return len(failed) == 0, failed, nil
}

// Verify the input with given signature and a list of public keys.
// It returns true if any of the key verifies successfuly. The file name of the successful key is returned. (true, fn, nil).
// It returns false if all keys failed. The errors are returned as a map keyed by the key file name. The common
// errors are keyed by COMMON_ERROR. (false, "", map).
func InputVerifiedByAnyKey(keyFiles []string, signature string, input []byte) (bool, string, map[string]error) {
	failed := make(map[string]error)

	// no input files, failed
	if len(keyFiles) == 0 {
		failed[COMMON_ERROR] = fmt.Errorf("No public key files provided; input not verified")
		return false, "", failed
	}

	// hash input
	hasher := sha256.New()
	_, err := hasher.Write(input)
	if err != nil {
		failed[COMMON_ERROR] = fmt.Errorf("Error hashing input: %v, Error: %v", string(input), err)
		return false, "", failed
	}

	// decode the signature into its binary form.
	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		failed[COMMON_ERROR] = fmt.Errorf("Unable to base64 decode signature %v, error: %v", signature, err)
		return false, "", failed
	}

	for _, keyFile := range keyFiles {
		if ok, err := verify(keyFile, signatureBytes, hasher); !ok {
			failed[keyFile] = err
		} else {
			return true, keyFile, nil
		}
	}

	return false, "", failed
}

// Verification error
type VerificationError struct {
	Msg           string
	InternalError error
}

// Error provides a loggable error message including the message of an
// internal error (one enclosed in this error).
func (e VerificationError) Error() string {
	return fmt.Sprintf("%v. InternalError: %v", e.Msg, e.InternalError)
}

// Error found while checking the public key
type KeyError struct {
	Msg           string
	InternalError error
}

// Error provides a loggable error message including the message of an
// internal error (one enclosed in this error).
func (e KeyError) Error() string {
	return fmt.Sprintf("%v. InternalError: %v", e.Msg, e.InternalError)
}

// This function verifies the given signature and data with the public key.
// It returns true if the verification is successful.
// It returns false if the verification is not successful. The error indicates what went wrong.
// The error can be VerificationError or KeyError
func verify(keyFileName string, signatureBytes []byte, inputHash hash.Hash) (bool, error) {
	// open the file
	pubkeyRaw, err := ioutil.ReadFile(keyFileName)
	if err != nil {
		return false, KeyError{fmt.Sprintf("Unable to read key file: %v", keyFileName), err}
	}

	// check if the key is a public key
	block, _ := pem.Decode(pubkeyRaw)
	if block == nil {
		return false, KeyError{fmt.Sprintf("Unable to find PEM block in the provided public key: %v", keyFileName), err}
	}

	pubkey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false, KeyError{fmt.Sprintf("Unable to parse key file: %v, as a public key.", keyFileName), err}
	}

	// verify the signature
	err = rsa.VerifyPSS(pubkey.(*rsa.PublicKey), crypto.SHA256, inputHash.Sum(nil), signatureBytes, nil)
	if err != nil {
		return false, VerificationError{fmt.Sprintf("Unable to verify signature using pubkey file: %v", keyFileName), err}
	}

	return true, nil
}
