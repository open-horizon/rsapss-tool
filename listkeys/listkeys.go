package listkeys

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/open-horizon/rsapss-tool/sign"
	"github.com/open-horizon/rsapss-tool/utility"
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

	return utility.SimpleSubjectNames(k.SubjectNames)
}

func (k KeyPair) SerialOctet() string {

	return utility.SerialOctet(k.SerialNumber)
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
