package cert

import (
	"math/big"
	"strings"
	"time"

	"cert2go/pkg/assertion"
)

func ValidateTime(t time.Time) error {
	return assertion.AssertTimeNotZero(t)
}

func ValidateSerialNumber(sn *big.Int) error {
	return assertion.AssertWithinRange(sn.BitLen(), 1, RFC5280SerialNumberLen)
}

func ValidateSubjectAltName(san []string) (err error) {
	err = assertion.AssertWithinRange(len(san), 0, MaxDomainSliceLen)
	if err != nil {
		return
	}
	return assertion.AssertWithinRange(len(strings.Join(san, "")), 0, MaxSANLen)
}

func ValidateCommonName(cn string) error {
	return assertion.AssertWithinRange(len(cn), 1, RFC5280CommonNameLen)
}

func ValidateOrganization(o string) error {
	return assertion.AssertWithinRange(len(o), 1, RFC5280OrganizationLen)
}

func ValidateOrganizationalUnit(ou string) error {
	return assertion.AssertWithinRange(len(ou), 1, RFC5280OrganizationalUnitLen)
}

func ValidateCountry(c string) error {
	return assertion.AssertExactly(len(c), RFC5280CountryLen)
}

func ValidateState(s string) error {
	return assertion.AssertWithinRange(len(s), 1, RFC5280StateLen)
}

func ValidateLocality(l string) error {
	return assertion.AssertWithinRange(len(l), 1, RFC5280LocalityLen)
}
