// +build integration

package verify

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// N.B. Basic tests of verify.Input() (the convenience function) are done in the sign module

var testContent = map[string]map[string]map[string]string{
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

func setupTesting(t *testing.T) (string, []byte, []*KeyMapping, []*KeyMapping, []*KeyMapping) {
	dir, err := ioutil.TempDir("", "verify-")
	if err != nil {
		t.Error(err)
	}

	var allKeyMappings []*KeyMapping
	var onlyValidKeyMappings []*KeyMapping
	var onlyBogusKeyMappings []*KeyMapping
	var retC string

	for content, keyListing := range testContent {
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

	return dir, []byte(retC), allKeyMappings, onlyValidKeyMappings, onlyBogusKeyMappings
}

func Test_InputVerifiedByAll_Suite(t *testing.T) {
	// setup
	dir, content, allKeyMappings, onlyValidKeyMappings, _ := setupTesting(t)

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

	defer os.RemoveAll(dir)
}

func Test_InputVerifiedByAnyKey_Suite(t *testing.T) {
	// setup
	dir, content, allKeyMappings, onlyValidKeyMappings, onlyBogusKeyMappings := setupTesting(t)

	var sig string
	for _, k := range onlyValidKeyMappings {
		sig = k.Signature
		break
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
			keys = append(keys, k.PublicKeyPath)
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
			keys = append(keys, k.PublicKeyPath)
		}

		if verified, _, failed := InputVerifiedByAnyKey(keys, sig, content); !verified {
			t.Error("Verify incorrectly reported provided keys as unverified when all should have succeeded")
		} else if len(failed) != 0 {
			t.Error("Verify returned incorrect number of failed keys", failed)
		}
	})

	defer os.RemoveAll(dir)
}
