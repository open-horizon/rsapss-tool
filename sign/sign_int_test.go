// +build integration

package sign

import (
	"crypto/x509"
	"encoding/pem"
	"github.com/open-horizon/rsapss-tool/verify"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

const serializedPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIICWgIBAAKBgGXYNI11qtOPvOArG3qotJ+7kFrepdLPjXXbZf6RCQ1c6lx7ivQU
xvANuQgBdqhWKEr/AYHDSTgIO7QqfmF2BevY+uYLzRVfeAo/I0REOPbkQLboEqCa
7FtV2zUHY1H6vBIJYkLpJCm5TfMihSd7M6oBCbFcKubTuco9H1UvzOzHAgMBAAEC
gYAnlPr/y66j4OZ4fWiFqJHizuQQ3R23rCD/oFCoure48NbJMN7VdEnJPJwgR2lV
jX7FfwyX4U1QsKp7oFRUDqnH+GzEhLZqPLQM2i0EQvfhqaV7vES5bO8DimqsQaIy
vqcCCFj6jNdRE99ji4XJ19TypCeoY+p64OursfraGrdkeQJAeTeSsiZb4NN07NSs
WCyMBFmPcEdq6HJxc7yYcDNw2HuO+5QH0DqsdbOQYTRx8Mun0Zo3/HjZeI95OFP4
1wfiywJBANcWPnXLMupVKuSYcPIgsX7FpDgT/+ZF2LPQaTBA+MZAOT+bPrUR/oYF
6dYyeR63ORS1MKGrVJIqvhJeB2nAEnUCQDlPxzIn5MT19ZCMNTgzR7g+yAzkF23z
viRkhQZ3q+EO+lmEcfVH6IZ18cujykN5Zs05R0M9uETCQSQav8qbVeUCQQCGh2wz
ww+qj/CPIGXsm9RI5ZesV54ESoWbGmzgeJLhdUQZa6GSIZof+8zhY5psQs+aCyZK
yF3SOpe950AdvbwNAkAy+sP9jXzI4J9rq0OwTvt/x5wUWa5vhv04rAk9n1FEDWE2
3pVg2QK49XIdzLtaJI+ngnLlGoTDhZP/yYO9xuPr
-----END RSA PRIVATE KEY-----`

const unmatchedSerializedPublicKey = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDlJyMeC1iZXM2fG7kV6PX3ZKHe
G7HJj98HbHvmgabxLHzrU10lmZbw+npwl/4EixuCjdMEDfO6Yr30CDVMQhdLXPm4
M7rPgmL524BBSooPN8UbebMfn0aD/LGvqoAX3rVnynQAa80jhTrk6MLMM02P1rbI
0t+oXwKI7Owg7C4rBQIDAQAB
-----END PUBLIC KEY-----`

func setupTesting(t *testing.T) string {
	dir, err := ioutil.TempDir("", "sign-")
	if err != nil {
		t.Error(err)
	}

	pkBytes := []byte(serializedPrivateKey)

	if err := ioutil.WriteFile(filepath.Join(dir, "private.key"), pkBytes, 0660); err != nil {
		t.Error(err)
	}

	pemBlock, _ := pem.Decode(pkBytes)
	if pemBlock == nil {
		t.Error("Unable to find PEM block in test's private key")
	}

	pk, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if err != nil {
		t.Error("Error setting up test", err)
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&pk.PublicKey)
	if err != nil {
		t.Error("Error setting up test", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:    "PUBLIC KEY",
		Headers: nil,
		Bytes:   pubKeyBytes,
	})

	if err := ioutil.WriteFile(filepath.Join(dir, "public.key"), pemBytes, 0660); err != nil {
		t.Error(err)
	}

	if err := ioutil.WriteFile(filepath.Join(dir, "public-other.key"), []byte(unmatchedSerializedPublicKey), 0660); err != nil {
		t.Error(err)
	}

	return dir
}

func Test_Input_Suite(t *testing.T) {
	// setup
	dir := setupTesting(t)
	defer os.RemoveAll(dir)

	// tests in suite
	t.Run("no private key", func(t *testing.T) {
		if _, err := Input("notreal", []byte{}); err == nil {
			t.Error("Expected error opening bogus keyfile")
		}
	})

	input := []byte("wubba lubba dub dub! -R")
	sig, err := Input(filepath.Join(dir, "private.key"), input)
	if err != nil {
		t.Error(err)
	}

	t.Run("signature verifies legitimate", func(t *testing.T) {
		verified, err := verify.Input(filepath.Join(dir, "public.key"), sig, input)
		if err != nil {
			t.Error(err)
		} else if !verified {
			t.Errorf("Signature %v could not be verified. Either the sign or verify implementations have failed", sig)
		}
	})

	t.Run("signature does not verify illegitimate", func(t *testing.T) {
		// use a valid pubkey but one that doesn't match the private key used to generate the signature
		shouldNotVerify, err := verify.Input(filepath.Join(dir, "public-other.key"), sig, input)
		if err != nil {
			t.Error(err)
		} else if shouldNotVerify {
			t.Errorf("Signature %v verified and shouldn't have", sig)
		}
	})

}
