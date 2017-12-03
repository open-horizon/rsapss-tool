// +build integration

package generatekeys

import (
	"github.com/open-horizon/rsapss-tool/constants"
	"github.com/open-horizon/rsapss-tool/sign"
	"github.com/open-horizon/rsapss-tool/verify"
	"io/ioutil"
	"os"
	"strings"
	"testing"
	"time"
)

func setupTesting(t *testing.T) string {
	dir, err := ioutil.TempDir("", "generatekeys-")
	if err != nil {
		t.Error(err)
	}

	return dir
}

func Test_Write_Suite(t *testing.T) {
	// setup
	dir := setupTesting(t)
	defer os.RemoveAll(dir)

	var cert string
	var privatekey string

	generatedContent, err := Write(dir, constants.MinAcceptableKeyLength, "mycn", "myorg-1", time.Now().Add(1*time.Hour))
	if err != nil {
		t.Error(err)
	}

	for _, f := range generatedContent {
		if strings.Contains(f, ".pem") {
			cert = f
		} else if strings.Contains(f, ".key") {
			privatekey = f
		}
	}

	t.Run("generatekeys generates usable key and cert pair", func(t *testing.T) {
		input := []byte("some content to sign")

		// sign
		sig, err := sign.Input(privatekey, input)
		if err != nil {
			t.Error(err)
		}

		// verify (this also tests the cert's suitability)
		verified, err := verify.Input(cert, sig, input)
		if err != nil {
			t.Error(err)
		} else if !verified {
			t.Errorf("Signature %v could not be verified. Either the sign or verify implementations have failed", sig)
		}
	})

	t.Run("generatekeys errors on key length smaller than minimum", func(t *testing.T) {
		_, err := Write(dir, constants.MinAcceptableKeyLength-1, "mycn", "myorg-2", time.Now().Add(10*time.Hour))
		if err == nil {
			t.Error("Expected error b/c requested key length is too short")
		} else if !strings.Contains(err.Error(), "short") {
			t.Error("Expected error specifying requested key length is too short")
		}
	})

	t.Run("generatekeys rejects cert generation requests for certs valid for too long", func(t *testing.T) {
		_, err := Write(dir, constants.MinAcceptableKeyLength, "mycn", "myorg-3", time.Now().AddDate(0, 0, constants.MaxSelfSignedCertExpirationDays+1))
		if err == nil {
			t.Error("Expected error b/c requested cert is valid too far in the future")
		} else if !strings.Contains(err.Error(), "validity") {
			t.Error("Expected error specifying requested validity date too far away")
		}
	})

}
