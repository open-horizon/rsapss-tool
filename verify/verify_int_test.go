// +build integration

package verify

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/open-horizon/rsapss-tool/constants"
	"github.com/open-horizon/rsapss-tool/sign"
	"io/ioutil"
	"math/big"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// N.B. Basic tests of verify.Input() (the convenience function) are done in the sign module

var testKeyContent = map[string]map[string]map[string]string{
	"somecontent to be verifiedbykeys011": {
		"1024bogus": {
			"Lx5FNcMY4uqeLOMAllMAZsevO208ZfcATiK0G4uMvYZebOxrUu4Qvtli/Qx7QsKI0XOcfnNgO8L313QNLYxFygfy8Yz2ycAdNcgWx7OznJd6FJk+heHYMNJYAN9SODkKF7XdiD45mID9mdxcGEBYJfUiP5kON03LntLQNbsikg4=": `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDEtgoalL7HfaaIYUhHqkR4j7ex
zoDOJ4djF/kIxij9aKqXv9cJdX1hae2B7qPODxasnhGo+2lUZ0b5Kqzvpxqs6QW1
DP2Qr14sYrmDnBPZPloZ1X6d8n/jEdB/ifjOYV4zDlAwGeQWDyexHbJa1CccRTuM
0kVvEzy84lJRk0waiQIDAQAB
-----END PUBLIC KEY-----`,
		},
		"1024-1valid": {
			"dLYOotQPP1pmbyWl/GHHxwqoDcyT3TnC63vIH3Fs3xQrsyEsb7cn99zZCg7VLHqSLD7npjf4Ntzz3N5uEeqZBCCCo1/TCiWRmsk82NUhmqM0KKKereZuQvBFcoPZBtUYZGrpIPeJIT8uC8+S1z3HiOlN30BU1f2LmB+zmfU0jaA=": `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCahFVCmkEAPU6O6n6tYr91ATkR
8mzataf//E2vFLvoMXgmWf4snxqqSBzknP8zI3H2o3g9960gWBJ0SZ8/YsKiaZXv
CQSFa7ejiq2pSsM5LPXbs5OWsTvNGAJUtvcSsg67Y4fzSPou0RRImr6aJ/C3JWxs
u0xh55qkESghh1/oBwIDAQAB
-----END PUBLIC KEY-----`,
		},
		"1024-2valid": {
			"xkk6A0XNwEUGXRDxmHDDgIZMFUJbVWiiUjwKG3JCQoxfJ/2WXxphmVDyBHQrFmx7kWADG9pVv67UX8m3r04XSCUWIZHGppNhCyLtEUs5EFmeXprhCYTpqFVFnDQbGbA3PntNhHgHQu1zJTG7S9P2XsTXKuYAPDnKZkI4NXpGn4o=": `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDYv9JPtun4CTaZeCs3zkrYkvtp
sMUGs+9wDWDDWCYuX7kIwUZAPo4cMyPX3nC5jyUsXnBY0McAiUVbVbr4Np8BC+VG
UbkdjwoCmCHELDRijORpD/V9KiZ1oTcOd6rvaXSAHyAyPc9eXwBMaNYLgfTxLsR/
ZQN2gHoC7ccOTPK52QIDAQAB
-----END PUBLIC KEY-----`,
		},
		"2048valid": {
			"EhGrP7lg4+QheUCxDur3kim1Om5T1VM2064zMgCHtvYx7ZZ0GnMekTEr5lhUGc3GJcidFtKOv16xmiCX3pjXiqE07HArOjmEytHSlhCj1NnWdbrAmXp+peSdYcDadROG+77XpG/kXQHyOZw2JSZANOg0bdOYjKDWqRrSiYbpNszCwY4SNdTrnpj+ke//JwDGshbgj7uDjvfHnTnNxt4IF+owdvF7QywFOk2STC9cRUP4QaWEbTjd4/s0pLycHF4MzyoK4qUN41/oUQAGUOiZ34nyhU9JnYxZ0OxH4hn4y8GgVDOsvkvBxqZK/0/lc7yJNraX6aWZ27/wXZiwL2ac3w==": `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArjDt2Sl9XxeCKQFwpllw
Z5DdcP6DOb0SBgSJSOpMf7K7eyJSIy8Q4pGo5ELVsj0mdgr9Bzrgv8xoPpcb2DbG
dpxdYSCAXJQ97JYvXHU3Zb9TUOIZloTCE3em21cNJ0YoKehqV1ZfJVS+EWw0PBpU
H5BsOHPF5cXNCLreebG8s9chnlUXALOPB9xhySBKLpcEFBQ+pCe1H+DtULWZ4egO
oxOpBQ31F7zJNioXasl3QT3BQes7C3ifdTmnjAQGmTrtt7MDYit1cqDIFbTzKy6d
AzeUhCqiTPo+hOF4b2eDS88dfmqD0B8vcyEX4w4k7yvH0nMpR0SDDWZva6PCzM4o
QwIDAQAB
-----END PUBLIC KEY-----`,
		},
	},
}

// used for testing certs
var validTestPrivKey = `-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDAzJUe8MrDpOFu8uJT2rKLo0pic0fksDny6RRszKeRF6uz8ewp
9zTox/ZcLAo7q/XRCos3LMxf7aoXdPY2livwmu7S0CvjcmnxOrZGtH7mwy+Ls5UK
WJ5nPZeZoWogMofQJymgpfXyVABm7AnIuA2hHQjmqFqpxcjFi2RLc6bhawIDAQAB
AoGBAIfIjc14sJURbmOBU7zS7aRCoIStxBhftLBLT0NA71LUZO0amMUFgZHgIrXP
nnVgKoPK9Tkqp9V3wK88hJr1MIPOE3Yi4CgHe8eQ8Q5Z62bb1kUa/yc3nn6MI/Uz
Kn6q7wIYjpSpFQHUNeJZJ3hrU6NfYJbiKVHe0n0ip5WkcjUBAkEA7xWP5cA2Dmra
bze9Thn9Twk+M4UEEEGUUAhkq3QKjTaTi2JTUjd6jue9TKSEcGCNd+rMXsiJ5ucX
EZPCjAphYQJBAM5wrVlybYUqPtBTyfdBsvKlVRpXDPekS0U5HoOHi6pYG8xiLFbG
McooADfvEzv2NTHzwozWJT0fx4Re9wMImksCQHuPezTT55v/4TAFcJKCoAVO05Sw
s+7q1YmfLNfnOuTMReiNQl6FSZO9dHm9tKyXWcWV1VVO8uYgnC17XdoeK0ECQHt4
PuXZn5Few/TbuFbu73Va1zyKxhGzLOW5FPv77Ne0HOQv727y2UKcjAzoK6vYRNac
gUa0qc8WG8Ga/sfMtGMCQQCMWudwltirtK4+U9G1phKiSZcew6O/BlMDM1UjjZQQ
nBKZcF0+H62TmtIIHvRm0wTq+nPPTtoEH8NrNwRZZ2hC
-----END RSA PRIVATE KEY-----`
var validTestCert = `-----BEGIN CERTIFICATE-----
MIICHTCCAYagAwIBAgIUYqKtvgqzrCoAUi0aX6WViO/RpOYwDQYJKoZIhvcNAQEL
BQAwOjEeMBwGA1UEChMVUlNBUFNTIFRvb2wgdGVzdCBjZXJ0MRgwFgYDVQQDEw9k
ZXZlbG9wbWVudC1vbmUwHhcNMTcxMjAyMTk1ODMyWhcNMjcxMTMwMDc1ODMyWjA6
MR4wHAYDVQQKExVSU0FQU1MgVG9vbCB0ZXN0IGNlcnQxGDAWBgNVBAMTD2RldmVs
b3BtZW50LW9uZTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAwMyVHvDKw6Th
bvLiU9qyi6NKYnNH5LA58ukUbMynkRers/HsKfc06Mf2XCwKO6v10QqLNyzMX+2q
F3T2NpYr8Jru0tAr43Jp8Tq2RrR+5sMvi7OVClieZz2XmaFqIDKH0CcpoKX18lQA
ZuwJyLgNoR0I5qhaqcXIxYtkS3Om4WsCAwEAAaMgMB4wDgYDVR0PAQH/BAQDAgeA
MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADgYEAcs5DAT+frZfJsoSKEMOu
WJh0S/UVYC+InMv9iUnPF3f0KjVBXTE45GDG1zxY6SFLpOVskNp9mMkH9PLqDMrb
kWsF7xOtgBrzIaibDeEhhcQvvHb6Yct1bSgYxWpS1oGKicXA9PFyXxigUW2e8+DH
SoxItJkxfl2adAjY2DVzdhY=
-----END CERTIFICATE-----`

func regenerateCert(t *testing.T, serialNo int, isCa bool, basicConstraintsValid bool, keyUsage x509.KeyUsage, issuer pkix.Name, subject pkix.Name, notBefore time.Time, notAfter time.Time, privateKeyPath string) string {

	serial := big.NewInt(int64(serialNo))

	template := x509.Certificate{
		// must be crypto-suitable random number up to 20 octets in length (cf. rfc5280 4.1.2.2)
		SerialNumber: serial,
		Issuer:       issuer,
		Subject:      subject,
		NotBefore:    notBefore,
		NotAfter:     notAfter,

		// if we were to accept it as a CA we'd set KeyUsageCertSign and KeyUsageCRLSign too
		KeyUsage:              keyUsage,
		BasicConstraintsValid: basicConstraintsValid,
		IsCA: isCa,
	}

	// TODO: read private key from provided file
	keyRaw, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		t.Error(err)
	}

	pemBlock, _ := pem.Decode(keyRaw)
	if pemBlock == nil {
		t.Errorf("Unable to find PEM block in provided private key: %v", privateKeyPath)
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if err != nil {
		t.Error(err)
	}

	random := rand.Reader
	// giving this method equal templates for template and parent makes self-signed
	certDerBytes, err := x509.CreateCertificate(random, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Error(err)
	}

	var certEnc = &pem.Block{
		Type:    "CERTIFICATE",
		Headers: nil,
		Bytes:   certDerBytes}

	dirParts := strings.Split(privateKeyPath, "/")
	dir := strings.Join(dirParts[0:len(dirParts)-1], "/")

	regeneratedCertPath := path.Join(dir, fmt.Sprintf("regencert-%d", serialNo))

	certOut, err := os.Create(regeneratedCertPath)
	if err != nil {
		t.Error(err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, certEnc); err != nil {
		t.Error(err)
	}
	return regeneratedCertPath
}

func setupTesting(t *testing.T) (string, []byte, []*KeyMapping, []*KeyMapping, []*KeyMapping, string, string) {
	dir, err := ioutil.TempDir("", "verify-")
	if err != nil {
		t.Error(err)
	}

	var allKeyMappings []*KeyMapping
	var onlyValidKeyMappings []*KeyMapping
	var onlyBogusKeyMappings []*KeyMapping
	var retC string

	for content, keyListing := range testKeyContent {
		retC = content

		for keyName, vals := range keyListing {
			path := filepath.Join(dir, keyName)

			for sig, keyVal := range vals {
				mapping := &KeyMapping{path, sig}
				allKeyMappings = append(allKeyMappings, mapping)
				if !strings.Contains(keyName, "bogus") {
					onlyValidKeyMappings = append(onlyValidKeyMappings, mapping)
				} else {
					onlyBogusKeyMappings = append(onlyBogusKeyMappings, mapping)
				}

				if err := ioutil.WriteFile(path, []byte(keyVal), 0660); err != nil {
					t.Error(err)
				}
			}
		}
	}

	block, _ := pem.Decode([]byte(validTestCert))

	validCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Errorf("Error setting up cert for test: %v", err)
	}

	validCertFilePath := path.Join(dir, validCert.SerialNumber.String())

	if err := ioutil.WriteFile(validCertFilePath, []byte(validTestCert), 0644); err != nil {
		t.Error(err)
	}

	validPrivateKeyPath := path.Join(dir, validCert.SerialNumber.String()+"-privkey")

	if err := ioutil.WriteFile(validPrivateKeyPath, []byte(validTestPrivKey), 0644); err != nil {
		t.Error(err)
	}

	return dir, []byte(retC), allKeyMappings, onlyValidKeyMappings, onlyBogusKeyMappings, validCertFilePath, validPrivateKeyPath
}

func Test_InputVerifiedByAll_Suite(t *testing.T) {
	// setup
	dir, content, allKeyMappings, onlyValidKeyMappings, _, _, _ := setupTesting(t)
	defer os.RemoveAll(dir)

	// tests in suite
	t.Run("verify fails on empty mappings input", func(t *testing.T) {
		if _, _, err := InputVerifiedByAll([]*KeyMapping{}, content); err == nil {
			t.Error("Verify did not return an error on empty key/sig input")
		}
	})

	t.Run("verify fails on bogus signature", func(t *testing.T) {
		if verified, failed, err := InputVerifiedByAll(allKeyMappings, content); err != nil {
			t.Error(err)
		} else if verified {
			t.Error("Verify incorrectly reported all provided keyMappings as verified when bogus should have failed")
		} else if len(failed) != 1 {
			t.Error(fmt.Sprintf("Verify returned incorrect number of failed keys (%v). Returned slice: %v", len(failed), failed))
		}
	})

	t.Run("verify succeeds on all verified signatures", func(t *testing.T) {
		if verified, failed, err := InputVerifiedByAll(onlyValidKeyMappings, content); err != nil {
			t.Error(err)
		} else if !verified {
			t.Error("Verify incorrectly reported provided keyMappings as unverified when all should have succeeded")
		} else if len(failed) != 0 {
			t.Error("Verify returned incorrect number of failed keys", failed)
		}
	})

}

func Test_InputVerifiedByAnyKey_Suite(t *testing.T) {
	// setup
	dir, content, allKeyMappings, onlyValidKeyMappings, onlyBogusKeyMappings, validCertPath, validPrivateKeyPath := setupTesting(t)
	defer os.RemoveAll(dir)

	var sig string
	for _, k := range onlyValidKeyMappings {
		sig = k.Signature
		break
	}

	someContent := []byte("somecontent")

	validSig, err := sign.Input(validPrivateKeyPath, someContent)
	if err != nil {
		t.Error(err)
	}

	// tests in suite
	t.Run("verify fails on empty mappings input", func(t *testing.T) {
		if verified, _, failed := InputVerifiedByAnyKey(make([]string, 0), sig, content); len(failed) == 0 {
			t.Error("Verify did not return an error on empty key/sig input.")
		} else if verified {
			t.Error("Verify returned verified but it should not.")
		}
	})

	t.Run("verify fails on bogus signature", func(t *testing.T) {

		keys := make([]string, 0, len(onlyBogusKeyMappings))
		for _, k := range onlyBogusKeyMappings {
			keys = append(keys, k.CertificatePath)
		}

		if verified, _, failed := InputVerifiedByAnyKey(keys, sig, content); verified {
			t.Error("Verify incorrectly reported all provided keys as verified when bogus should have failed")
		} else if len(failed) == 0 {
			t.Error(fmt.Sprintf("Verify returned incorrect number of failed keys (%v). Returned slice: %v", len(failed), failed))
		}
	})

	t.Run("verify succeeds on all verified signatures", func(t *testing.T) {

		keys := make([]string, 0, len(allKeyMappings))
		for _, k := range allKeyMappings {
			keys = append(keys, k.CertificatePath)
		}

		if verified, _, failed := InputVerifiedByAnyKey(keys, sig, content); !verified {
			t.Error("Verify incorrectly reported provided keys as unverified when all should have succeeded")
		} else if len(failed) != 0 {
			t.Error("Verify returned incorrect number of failed keys", failed)
		}
	})

	t.Run("verify succeeds with valid x509 cert", func(t *testing.T) {
		if verified, _, failed := InputVerifiedByAnyKey([]string{validCertPath}, validSig, someContent); !verified {
			t.Errorf("Signature reported as invalid but shouldn't have been. Failed: %v", failed)
		}
	})

	t.Run("verify fails invalid x509 certs", func(t *testing.T) {

		ident := pkix.Name{
			CommonName:   "somecn",
			Organization: []string{"someo"},
		}

		// varied invalid certs
		invalidCerts := []string{
			// cert not yet valid
			regenerateCert(t, 14, false, true, x509.KeyUsageDigitalSignature, ident, ident, time.Now().Add(10*time.Hour), time.Now().Add(10*time.Hour), validPrivateKeyPath),
			// cert expired
			regenerateCert(t, 15, false, true, x509.KeyUsageDigitalSignature, ident, ident, time.Now().Add(-1*time.Minute), time.Now().Add(-10*time.Hour), validPrivateKeyPath),
			// cert valid too long
			regenerateCert(t, 15, false, true, x509.KeyUsageDigitalSignature, ident, ident, time.Now().Add(-1*time.Minute), time.Now().AddDate(0, 0, constants.MaxSelfSignedCertExpirationDays+1), validPrivateKeyPath),
			// cert serial invalid
			regenerateCert(t, 0, false, true, x509.KeyUsageDigitalSignature, ident, ident, time.Now().Add(-1*time.Minute), time.Now().Add(10*time.Hour), validPrivateKeyPath),
			// cert serial invalid
			regenerateCert(t, -1, false, true, x509.KeyUsageDigitalSignature, ident, ident, time.Now().Add(-1*time.Minute), time.Now().Add(10*time.Hour), validPrivateKeyPath),
			// cert basic constraints invalid
			regenerateCert(t, 20, false, false, x509.KeyUsageDigitalSignature, ident, ident, time.Now().Add(-1*time.Minute), time.Now().Add(10*time.Hour), validPrivateKeyPath),
			// cert keyusage too permissive
			regenerateCert(t, 21, false, true, x509.KeyUsageDigitalSignature&x509.KeyUsageCertSign, ident, ident, time.Now().Add(-1*time.Minute), time.Now().Add(10*time.Hour), validPrivateKeyPath),
			// cert isCA
			regenerateCert(t, 22, true, true, x509.KeyUsageDigitalSignature, ident, ident, time.Now().Add(-1*time.Minute), time.Now().Add(10*time.Hour), validPrivateKeyPath),
			// cert not self-issued
			regenerateCert(t, 23, false, true, x509.KeyUsageDigitalSignature, ident, pkix.Name{}, time.Now().Add(-1*time.Minute), time.Now().Add(10*time.Hour), validPrivateKeyPath),
		}

		for _, invalidCertPath := range invalidCerts {
			by, err := ioutil.ReadFile(invalidCertPath)
			if err != nil {
				t.Error(err)
			}

			block, _ := pem.Decode(by)
			if block == nil {
				t.Errorf("Unable to find PEM block in cert: %v", invalidCertPath)
			}

			cert, err := x509.ParseCertificates(block.Bytes)
			if err != nil {
				t.Error(err)
			}

			if verified, _, failed := InputVerifiedByAnyKey([]string{invalidCertPath}, validSig, someContent); verified {
				t.Errorf("Signature reported as valid but shouldn't have been. Cert serial number: %v", cert[0].SerialNumber.String())
			} else if len(failed) != 1 {
				t.Errorf("Unexpected content returned for invalid cert: %v", failed)
			} else {
				t.Logf("Expected error has message: %v", failed[invalidCertPath])
			}

			// now test just the cert validator function and expect it gives the same result
			if pubkey, err := ValidKeyOrCert(by); err == nil {
				t.Errorf("Expected error on invalid cert %v but didn't get one", cert[0].SerialNumber.String())
			} else if pubkey != nil {
				t.Errorf("Expected nil pubkey returned because of invalid input for cert %v", cert[0].SerialNumber.String())
			}

			// don't bother logging these, it is done above
		}
	})

}
