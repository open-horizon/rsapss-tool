package verify

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/open-horizon/rsapss-tool/constants"
	"hash"
	"io/ioutil"
	"math/big"
	"reflect"
	"time"
)

// KeyMapping is a simple container for (key, signature) pairs
type KeyMapping struct {
	CertificatePath string
	Signature       string
}

const COMMON_ERROR = "COMMON_ERROR"

func (m *KeyMapping) String() string {
	return fmt.Sprintf("CertificatePath: %v, Signature: %v", m.CertificatePath, m.Signature)
}

// Input takes given publicKeyPath, input byte array, and signature string.
// This function returns true iff the signature of the input can be verified by
// the public key.
func Input(certificatePath string, signature string, input []byte) (bool, error) {

	verified, _, err := InputVerifiedByAll([]*KeyMapping{&KeyMapping{certificatePath, signature}}, input)
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

		if ok, err := verify(keyMapping.CertificatePath, signatureBytes, hasher); !ok {
			switch err.(type) {
			case VerificationError:
				failed = append(failed, &KeyMapping{keyMapping.CertificatePath, keyMapping.Signature})
			default:
				return false, failed, err
			}
		}
	}

	// if the signature was verified by all of the given keys we return true
	return len(failed) == 0, failed, nil
}

// Verify the input with given signature and a list of either certificates containing public keys or public keys themselves.
// It returns true if any of the key verifies successfuly. The file name of the successful key is returned. (true, fn, nil).
// It returns false if all keys failed. The errors are returned as a map keyed by the key file name. The common
// errors are keyed by COMMON_ERROR. (false, "", map).
func InputVerifiedByAnyKey(certOrKeyFiles []string, signature string, input []byte) (bool, string, map[string]error) {
	failed := make(map[string]error)

	// no input files, failed
	if len(certOrKeyFiles) == 0 {
		failed[COMMON_ERROR] = fmt.Errorf("No certificate or public key files provided; input not verified")
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

	for _, certOrKeyFile := range certOrKeyFiles {
		if ok, err := verify(certOrKeyFile, signatureBytes, hasher); !ok {
			failed[certOrKeyFile] = err
		} else {
			return true, certOrKeyFile, nil
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
func verify(certOrKeyFileName string, signatureBytes []byte, inputHash hash.Hash) (bool, error) {
	// open the file
	pubkeyOrCertRaw, err := ioutil.ReadFile(certOrKeyFileName)
	if err != nil {
		return false, KeyError{fmt.Sprintf("Unable to read key file: %v", certOrKeyFileName), err}
	}

	var pubkey interface{}

	if certs, err := x509.ParseCertificates(pubkeyOrCertRaw); err == nil {
		// trying input file as an x509 cert

		if len(certs) != 1 {
			return false, KeyError{fmt.Sprintf("Singular x509 Certificate not parseable from given keyfile: %v", certOrKeyFileName), nil}
		}

		cert := certs[0]
		now := time.Now()

		// TODO: use VerifyOptions and Certificate.Verify() eventually; for now
		// we do custom checking b/c the certs should all be self-signed, no
		// CA's are allowed, and we don't validate DNS or IP

		// check that the cert is signed by privatekey of self (because they're all self-signed)

		if now.Before(cert.NotBefore) {
			return false, KeyError{fmt.Sprintf("Certificate invalid; current time %v before valid NotBefore time: %v", now, cert.NotBefore), nil}
		}

		if now.After(cert.NotAfter) {
			return false, KeyError{fmt.Sprintf("Certificate invalid; current time %v after valid NotAfter time: %v", now, cert.NotAfter), nil}
		}

		if (cert.NotAfter.Unix() - cert.NotBefore.Unix()) > constants.MaxSelfSignedCertExpirationDays*24*60*60 {
			return false, KeyError{fmt.Sprintf("Certificate %v invalid; 'NotAfter' validation date is too far in the future. Max allowed days from issuance: %v", cert.SerialNumber.String(), constants.MaxSelfSignedCertExpirationDays), nil}
		}

		if cert.SerialNumber.Cmp(big.NewInt(0)) < 1 {
			return false, KeyError{fmt.Sprintf("Certificate invalid; serial number not positive: %v", cert.SerialNumber.String()), nil}
		}

		if !cert.BasicConstraintsValid {
			return false, KeyError{fmt.Sprintf("Certificate invalid; basic constraints not included"), nil}
		}

		if cert.KeyUsage != x509.KeyUsageDigitalSignature {
			return false, KeyError{fmt.Sprintf("Certificate invalid; only KeyUsageDigitalSignature use type is permitted"), nil}
		}

		// next two checks are for self-issued certs; we do not yet accept CA certs and when we do we must validate the whole cert chain
		if cert.IsCA {
			return false, KeyError{fmt.Sprintf("Certificate invalid; cert is a CA which is not supported"), nil}
		}

		if cert.Issuer.CommonName == "" || !reflect.DeepEqual(cert.Issuer, cert.Subject) {
			return false, KeyError{fmt.Sprintf("Certificate invalid; certificate not self-issued"), nil}
		}

		pubkey = cert.PublicKey

	} else {
		// try as a pem-encoded key (we support this for now, need to remove it eventually once everyone moves to x509 certs

		block, _ := pem.Decode(pubkeyOrCertRaw)
		if block == nil {
			return false, KeyError{fmt.Sprintf("Unable to find PEM block in the provided public key: %v", certOrKeyFileName), err}
		}

		pubkey, err = x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return false, KeyError{fmt.Sprintf("Unable to parse key file: %v, as a public key.", certOrKeyFileName), err}
		}
	}

	// verify the signature
	err = rsa.VerifyPSS(pubkey.(*rsa.PublicKey), crypto.SHA256, inputHash.Sum(nil), signatureBytes, nil)
	if err != nil {
		return false, VerificationError{fmt.Sprintf("Unable to verify signature using pubkey file: %v", certOrKeyFileName), err}
	}

	return true, nil
}
