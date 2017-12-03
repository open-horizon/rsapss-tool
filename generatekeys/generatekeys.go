package generatekeys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/open-horizon/rsapss-tool/constants"
	"golang.org/x/sys/unix"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"time"
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

func generateCertificate(cn string, organization string, certNotValidAfter time.Time, privateKey *rsa.PrivateKey) (*certRet, error) {
	// generate a cert
	random := rand.Reader

	serialMax := new(big.Int)
	// not crazy?
	serialMax.SetString(fmt.Sprintf("%f", math.Pow(2, 159)), 10)

	one := big.NewInt(1)
	// we add 1 to whatever random number is generated so we don't get a 0 b/c the RFC mentions
	// this as a special case for non-conforming CAs and we want to be as compliant as possible
	serial, _ := rand.Int(random, serialMax.Sub(serialMax, one))
	serial.Add(serial, one) // make sure it can't be a 0

	name := pkix.Name{
		CommonName:   cn,
		Organization: []string{organization},
	}

	now := time.Now()

	if (certNotValidAfter.Unix() - now.Unix()) > constants.MaxSelfSignedCertExpirationDays*24*60*60 {
		return nil, fmt.Errorf("x509 certificate validity date unacceptable. Please specify a time from request less than %d days away", constants.MaxSelfSignedCertExpirationDays)
	}

	template := x509.Certificate{
		// must be crypto-suitable random number up to 20 octets in length (cf. rfc5280 4.1.2.2)
		SerialNumber: serial,
		Issuer:       name,
		Subject:      name,
		NotBefore:    now.Add(time.Duration(-12) * time.Hour),
		NotAfter:     certNotValidAfter,

		// if we were to accept it as a CA we'd set KeyUsageCertSign and KeyUsageCRLSign too
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA: false,
	}
	certDerBytes, err := x509.CreateCertificate(random, &template,
		&template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err

	}

	return &certRet{serial, certDerBytes}, nil
}

// Write writes a new keypair to the given outputDir. It avoids overwriting
// existing keys of the same name.
func Write(outputDir string, keyLength int, cn string, org string, certNotValidAfter time.Time) ([]string, error) {
	var empty = []string{}

	if outputDir == "" {
		return empty, errors.New("Required parameter outputDir has invalid value, nil")
	}

	if keyLength < constants.MinAcceptableKeyLength {
		return empty, fmt.Errorf("Illegal input: keyLength value %d is shorter than the minimum allowed %v", keyLength, constants.MinAcceptableKeyLength)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, keyLength)
	if err != nil {
		return empty, err
	}

	certRet, err := generateCertificate(cn, org, certNotValidAfter, privateKey)
	if err != nil {
		return empty, err
	}

	orgFilenamePattern := regexp.MustCompile(`[\]\[ ,.!@#$%^&*()<>?/\\{}~]+`)

	fileOutPrefix := fmt.Sprintf("%s-%x-", orgFilenamePattern.ReplaceAllLiteralString(org, ""), certRet.serial)

	// x509 certificate with embedded RSA PSS pubkey
	certPath, err := pathIsAvail(outputDir, fmt.Sprintf("%spublic.cer", fileOutPrefix))
	if err != nil {
		return empty, err
	}

	certOut, err := os.Create(certPath)
	if err != nil {
		return empty, err
	}
	defer certOut.Close()

	_, err = certOut.Write(certRet.cert)
	if err != nil {
		return empty, err
	}

	// http://golang.org/pkg/encoding/pem/#Block
	var privEnc = &pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   x509.MarshalPKCS1PrivateKey(privateKey)}

	privPath, err := pathIsAvail(outputDir, fmt.Sprintf("%sprivate.key", fileOutPrefix))
	if err != nil {
		return empty, err
	}

	privOut, err := os.Create(privPath)
	if err != nil {
		return empty, err
	}
	defer privOut.Close()

	if err = pem.Encode(privOut, privEnc); err != nil {
		return empty, err
	}

	return []string{privPath, certPath}, nil
}

type certRet struct {
	serial *big.Int
	cert   []byte
}
