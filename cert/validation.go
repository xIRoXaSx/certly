package cert

import (
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/xiroxasx/certly/cert/assertion"
)

func ValidateTime(t time.Time) (err error) {
	err = assertion.AssertTimeNotZero(t)
	if err != nil {
		return
	}
	return assertion.AssertTimeNotNegative(t)
}

func ValidateSerialNumber(sn *big.Int) error {
	return assertion.AssertWithinRange(sn.BitLen(), 1, RFC5280SerialNumberLen)
}

func ValidateSubjectAltName(san []string) (err error) {
	err = assertion.AssertWithinRange(len(san), 0, MaxDomainSliceLen)
	if err != nil {
		return
	}

	var sanLen int
	for _, s := range san {
		sLen := len(strings.TrimSpace(s))
		err = assertion.AssertGreaterThan(sLen, 0)
		if err != nil {
			return err
		}
		sanLen += sLen
	}
	return assertion.AssertWithinRange(sanLen, 0, MaxSANLen)
}

func ValidateIPAddress(ip []net.IP) (err error) {
	err = assertion.AssertWithinRange(len(ip), 0, MaxIPSliceLen)
	if err != nil {
		return
	}

	for _, addr := range ip {
		err = assertion.AssertWithinRange(len(addr), 7, MaxIPLen)
		if err != nil {
			return
		}
	}
	return
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
