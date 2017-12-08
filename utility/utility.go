package utility

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"reflect"
	"strings"
)

func SimpleSubjectNames(attr []pkix.AttributeTypeAndValue) map[string]interface{} {

	subjectNames := make(map[string]interface{}, 0)

	for _, subj := range attr {
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

func SerialOctet(serial *big.Int) string {
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

	return strings.Join(accumulate([]string{}, serial), ":")
}
