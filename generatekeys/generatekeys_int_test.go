// +build integration

package generatekeys

import (
	"github.com/michaeldye/rsapss-tool/sign"
	"github.com/michaeldye/rsapss-tool/verify"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
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

	var pubkey string
	var privatekey string

	generatedContent, err := Write(dir, MinAcceptableKeyLength)
	if err != nil {
		t.Error(err)
	}

	for _, key := range generatedContent {
		if strings.Contains(key, "public") {
			pubkey = key
		} else if strings.Contains(key, "private") {
			privatekey = key
		}
	}

	t.Run("generatekeys generates usable keypair", func(t *testing.T) {
		input := []byte("some content to sign")

		// sign
		sig, err := sign.Input(privatekey, input)
		if err != nil {
			t.Error(err)
		}

		// verify
		verified, err := verify.Input(pubkey, sig, input)
		if err != nil {
			t.Error(err)
		} else if !verified {
			t.Errorf("Signature %v could not be verified. Either the sign or verify implementations have failed", sig)
		}
	})

	t.Run("generatekeys errors on key length smaller than minimum", func(t *testing.T) {
		_, err := Write(dir, MinAcceptableKeyLength-1)
		if err == nil {
			t.Error("Expected error b/c requested key length is too short")
		} else if !strings.Contains(err.Error(), "short") {
			t.Error("Expected error specifying requested key length is too short")
		}
	})

	t.Run("generatekeys errors on keys already in dir", func(t *testing.T) {
		// N.B. We're counting on the test setup having run successfully and generated a private key
		if _, err := os.Stat(filepath.Join(dir, "private.key")); os.IsNotExist(err) {
			t.Error("Test conditions not correct")
		}

		_, err := Write(dir, MinAcceptableKeyLength-1)
		if err == nil {
			t.Error("Expected error b/c requested key length is too short")
		} else if !strings.Contains(err.Error(), "short") {
			t.Error("Expected error specifying requested key length is too short")
		}
	})

	defer os.RemoveAll(dir)
}
