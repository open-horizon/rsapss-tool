// +build unit

package listkeys

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

const serializedCert = `-----BEGIN CERTIFICATE-----
MIIE6DCCAtCgAwIBAgIUGTK1ZJjWADIhfEyL3kkqsvrGloEwDQYJKoZIhvcNAQEL
BQAwHTEMMAoGA1UEChMDSUJNMQ0wCwYDVQQDEwRtZHllMB4XDTE3MTExMDE3MzYw
N1oXDTIxMTExMTA1MzYwNlowHTEMMAoGA1UEChMDSUJNMQ0wCwYDVQQDEwRtZHll
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtFeKK4Z+m2CgfXseLRNl
JStgteUqDJ4IvzCiEjtC1heSNUx7l50wNnTxDdrmcIdOpR68VVn3KGaqcNCwJHWS
f+Trzw5xmnRNljKWHab3lLPOekF4LioZ6Fk/exRhQ75ckPmtx0lb8SH1En0hs9kR
HxE6GxrLpI1a7V0bFBen0DaMfsLD/zQ4WAbuIzcjXA1unKYQ1nHyytwyfOlQsKqy
2eZX3ab/HM/HgmM5rh7dnSuo1xT1nVokhXArl351AzHyFXrfU0aXP1aBeP+5U93g
qsHqigwU1fbceAFVKV05mpg/x+xi9HLrKxSjmPWx2WLhbVMFPUNxgjH6b4Ez+6mK
ODRIppJ3TpaK0rei3WQ+CunC8xgKwwVveyqozVLaUNLTKTS5NeIjtQIpz+UrH2Zn
kCfCfmUlWjIBxDa6N87xkl+yYulWgYgrUb4Y3WuZkUK6pd7CL5AA7WsEqAefQKoA
vdecCDHknuuJ/Y9bCbCmH2dbnKePmeIScTWCAP+4dZuJr6axmVlc/1g741uMfQHW
zoGSW5B4jv+TUhDTmYkbLZf9RduEvj/aMbPOpMuMPawUSBwnorEX8AbqkIz2hWMb
fdtYOSe9HAixjyDniWTbZTV2kQaVz0U3OWL6oW+wicqrsPeqPpFLe1bpGDQPpHm+
ipyx1hmY7RUkwm1eyDnevVcCAwEAAaMgMB4wDgYDVR0PAQH/BAQDAgeAMAwGA1Ud
EwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBACV5ispf4ii0O3Y6lUv0wfNQ9Fs6
nbD6bMyJ/1eJfuVrEZyC/B17/KVXEY5Sf3iQhx1E1r8pQ0ggALWX/LlJnopO7DIB
KYoXR5xo9hO3gSrEOhxRwjj8qf693Zccvfh6clKlJmm+einM4BQOwv6BucTIWGPr
yGIqL47XoWplO3SAWERst2t+q7br9E8GNIu+6GFCB+O0+S7RxDE+Cm++urUaaJuk
H/34HYeJvl+9DPBZbkoKh0/oEDAHTgS8GXiSBar61Zqx/uJLzZO05yRMDqNNUz/3
JzC5BeMWBxnuNxLGZoMkcDLi9yB7Ue2Yg5BzVPQIB3QQQMM39WesWzBDzMZGWxzg
XKBb6taMiipoPVQ77K6c4o20ROum+tP2qPU8l1B6E6ADfJmn3GRCXNp/2ti5bnQO
ifECcEz2dyyY6V+FMF8PO8r+MlnXf3iKWtV4RQ9EZWGAQYUZw5O9g1qRYpZT/h9I
b5dY1W7GhEK4kjIWkP5e+nROuouXeSHkQvq2nDi4Ny9ZiLLrTa7YuuMTclvb+QU4
2bJGTo/EQ+Dznop8FSnTPzqNL2dYEbhRmlMgmev+MCnan9UCDc3GikaPysuKmXug
ZTsioDJuoMfTY8P5rr3vJQvUH3gbVl3vJ03O6+3nYN2nIUCEDvN2YvEkIH838a93
9tZvEXRCnKTjvFn2
-----END CERTIFICATE-----`

var cert *x509.Certificate

func setup() error {
	block, _ := pem.Decode([]byte(serializedCert))
	if block == nil {
		return fmt.Errorf("Unable to decode PEM: serializedCert")
	}

	var err error
	cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("Unable to parse cert from PEM: %v", err)
	}

	return nil
}

func Test_KeypairSerialOctet_Suite(suite *testing.T) {
	err := setup()
	if err != nil {
		suite.Error(err)
	}

	pair := KeyPair{SerialNumber: cert.SerialNumber}

	suite.Run("Cert serial output is correct octet string", func(t *testing.T) {
		assert.EqualValues(t, "19:32:b5:64:98:d6:00:32:21:7c:4c:8b:de:49:2a:b2:fa:c6:96:81", pair.SerialOctet())
		assert.EqualValues(t, 20, len(strings.Split(pair.SerialOctet(), ":")))
	})
}
