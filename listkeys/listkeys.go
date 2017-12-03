package listkeys

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"github.com/open-horizon/rsapss-tool/sign"
	"io/ioutil"
	"math/big"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

// KeyPairList is a record of an x509 certificate wrapping a pubkey and a matching private key
type KeyPair struct {
	SerialNumber   *big.Int
	SubjectNames   []pkix.AttributeTypeAndValue
	Issuer         []pkix.AttributeTypeAndValue
	HavePrivateKey bool
	NotValidBefore time.Time
	NotValidAfter  time.Time
}

func (k KeyPair) SimpleIssuer() string {
	var issuer string
	if reflect.DeepEqual(k.SubjectNames, k.Issuer) {
		issuer = "<self>"
	} else {
		issuer = fmt.Sprintf("%v", k.Issuer)
	}

	return issuer
}

func (k KeyPair) SimpleSubjectNames() map[string]interface{} {

	subjectNames := make(map[string]interface{}, 0)

	for _, subj := range k.SubjectNames {
		if reflect.DeepEqual(subj.Type, asn1.ObjectIdentifier{2, 5, 4, 10}) {
			subjectNames["organizationName (O)"] = subj.Value
		} else if reflect.DeepEqual(subj.Type, asn1.ObjectIdentifier{2, 5, 4, 3}) {
			subjectNames["commonName (CN)"] = subj.Value
		} else {
			subjectNames[subj.Type.String()] = subj.Value
		}
	}

	return subjectNames
}

func (k KeyPair) SerialOctet() string {
	shiftDivisor := big.NewInt(1 << 8)
	mask := big.NewInt((1 << 8) - 1)

	var accumulate func(acc []string, n *big.Int) []string

	accumulate = func(acc []string, n *big.Int) []string {
		if n.BitLen() == 0 {
			return acc
		}

		// get value of least significant 8 bits
		v := big.NewInt(0)
		v.And(n, mask)
		// prepend the new value
		acc = append([]string{fmt.Sprintf("%02x", v.Uint64())}, acc...)
		// we instantiate a new bigint to hold the result of the division so we don't change n
		return accumulate(acc, big.NewInt(0).Div(n, shiftDivisor))
	}

	return strings.Join(accumulate([]string{}, k.SerialNumber), ":")
}

func (k KeyPair) String() string {

	return fmt.Sprintf("SerialNumber: %v, SubjectNames: %v, Issuer: %v, HavePrivateKey: %t", k.SerialOctet(), k.SubjectNames, k.SimpleIssuer(), k.HavePrivateKey)
}

func pkFilenameFromCertFilename(filename string) (string, error) {
	split := strings.Split(filename, "-")
	// TODO: check split content

	if len(split) != 3 {
		return "", fmt.Errorf("Cert filename not in expected format %v", filename)
	}
	return fmt.Sprintf("%v-private.key", strings.Join(split[0:2], "-")), nil
}

// rips the rsapss pubkey out of the x509 cert
func pubkeyFromCert(cert *x509.Certificate) (rsa.PublicKey, error) {
	return *(cert.PublicKey.(*rsa.PublicKey)), nil
}

// ListPairs returns a slice of KeyPairList objects read from given directory or error
func ListPairs(dir string) (map[string]KeyPair, error) {
	list := make(map[string]KeyPair, 0)

	err := filepath.Walk(dir, func(filePath string, info os.FileInfo, err error) error {
		if !info.IsDir() && strings.HasSuffix(filePath, ".pem") {
			certBytes, err := ioutil.ReadFile(filePath)
			if err != nil {
				return err
			}

			block, _ := pem.Decode(certBytes)
			if block == nil {
				return fmt.Errorf("Unable to find PEM block in the provided cert: %v", filePath)
			}

			certs, err := x509.ParseCertificates(block.Bytes)
			if err != nil {
				return err
			}

			if len(certs) != 1 {
				return err
			}

			cert := certs[0]

			pkFilename, err := pkFilenameFromCertFilename(info.Name())
			if err != nil {
				return err
			}

			privatekey, err := sign.ReadPrivateKey(path.Join(dir, pkFilename))

			certPubkey, err := pubkeyFromCert(cert)
			if err != nil {
				return err
			}

			var havePrivateKey bool
			if privatekey != nil {
				havePrivateKey = reflect.DeepEqual(privatekey.PublicKey, certPubkey)
			}

			list[info.Name()] = KeyPair{
				SerialNumber:   cert.SerialNumber,
				SubjectNames:   cert.Subject.Names,
				NotValidBefore: cert.NotBefore,
				NotValidAfter:  cert.NotAfter,
				Issuer:         cert.Issuer.Names,
				HavePrivateKey: havePrivateKey,
			}
		}

		return nil
	})

	return list, err
}
