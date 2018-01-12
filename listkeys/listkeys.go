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

// KeyPair is a record of an x509 certificate wrapping a pubkey and a matching private key
type KeyPair struct {
	SerialNumber   *big.Int
	SubjectNames   []pkix.AttributeTypeAndValue
	Issuer         []pkix.AttributeTypeAndValue
	HavePrivateKey bool
	NotValidBefore time.Time
	NotValidAfter  time.Time
}

// KeyPairSimple is a KeyPair serializable struct meant to aid generating pretty output in JSON
type KeyPairSimple struct {
	Type           string                 `json:"type"`
	SerialNumber   string                 `json:"serial_number"`
	SubjectNames   map[string]interface{} `json:"subject_names"`
	HavePrivateKey bool                   `json:"have_private_key"`
	NotValidBefore time.Time              `json:"not_valid_before"`
	NotValidAfter  time.Time              `json:"not_valid_after"`
	Raw            KeyPair                `json:"raw"`
}

func (k KeyPair) ToKeyPairSimple() KeyPairSimple {
	return KeyPairSimple{
		Type:           "KeyPairSimple",
		SerialNumber:   k.SerialOctet(),
		SubjectNames:   k.SimpleSubjectNames(),
		HavePrivateKey: k.HavePrivateKey,
		NotValidBefore: k.NotValidBefore,
		NotValidAfter:  k.NotValidAfter,
		Raw:            k,
	}
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

func ReadKeyPair(filePath string) (*KeyPair, error) {
	certBytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(certBytes)
	if block == nil {
		return nil, fmt.Errorf("Unable to find PEM block in the provided cert: %v", filePath)
	}

	certs, err := x509.ParseCertificates(block.Bytes)
	if err != nil {
		return nil, err
	}

	if len(certs) != 1 {
		return nil, err
	}

	cert := certs[0]

	pathParts := strings.Split(filePath, "/")
	var fileNameIndex int
	if len(pathParts) != 0 {
		fileNameIndex = len(pathParts) - 1
	}

	pkFilename, err := pkFilenameFromCertFilename(pathParts[fileNameIndex])
	if err != nil {
		return nil, err
	}

	pathSegments := strings.Split(filePath, "/")
	if len(pathSegments) == 0 {
		return nil, fmt.Errorf("Unusable path segment for key: %v", pathSegments)
	}

	privatekey, err := sign.ReadPrivateKey(path.Join(pathSegments[len(pathSegments)-1], pkFilename))

	certPubkey, err := pubkeyFromCert(cert)
	if err != nil {
		return nil, err
	}

	var havePrivateKey bool
	if privatekey != nil {
		havePrivateKey = reflect.DeepEqual(privatekey.PublicKey, certPubkey)
	}

	return &KeyPair{
		SerialNumber:   cert.SerialNumber,
		SubjectNames:   cert.Subject.Names,
		NotValidBefore: cert.NotBefore,
		NotValidAfter:  cert.NotAfter,
		Issuer:         cert.Issuer.Names,
		HavePrivateKey: havePrivateKey,
	}, nil
}

// ListPairs returns a slice of KeyPairList objects read from given directory or error
func ListPairs(dir string) (map[string]KeyPair, error) {
	list := make(map[string]KeyPair, 0)

	err := filepath.Walk(dir, func(filePath string, info os.FileInfo, err error) error {
		if !info.IsDir() && strings.HasSuffix(filePath, ".pem") {
			pair, err := ReadKeyPair(filePath)

			// TODO: output errors here without failing; for now we're skipping them b/c we're trying to be friendly about reading data from directory with mixed content
			if err == nil {
				list[info.Name()] = *pair
			}
		}

		return nil
	})

	return list, err
}
