package cert

import (
	"crypto/rand"
	"math"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	r "github.com/stretchr/testify/require"
)

func TestValidateTime(t *testing.T) {
	t.Parallel()

	r.NoError(t, ValidateTime(time.Now()))
	r.Error(t, ValidateTime(time.Time{}))
	r.Error(t, ValidateTime(time.Time{}.Add(-math.MaxInt64)))
}

func TestValidateSerialNumber(t *testing.T) {
	t.Parallel()

	limit := new(big.Int).Lsh(big.NewInt(1), RFC5280SerialNumberLen)
	serial, err := rand.Int(rand.Reader, limit)
	r.NoError(t, err)
	r.NoError(t, ValidateSerialNumber(serial))

	limit = new(big.Int).Lsh(big.NewInt(1), 0)
	serial, err = rand.Int(rand.Reader, limit)
	r.Error(t, ValidateSerialNumber(serial))
}

func TestValidateSubjectAltName(t *testing.T) {
	t.Parallel()

	san := "test.local"
	r.NoError(t, ValidateSubjectAltName([]string{san}))

	sans := make([]string, MaxDomainSliceLen)
	for i := range sans {
		sans[i] = san
	}
	r.NoError(t, ValidateSubjectAltName(sans))

	sans = append(sans, san)
	r.Error(t, ValidateSubjectAltName(sans))

	// Test MaxSANLen.
	for i := range sans {
		sans[i] = strings.Repeat("a", int(math.Ceil(MaxSANLen/20))+1)
	}
	r.Error(t, ValidateSubjectAltName(sans))
}

func TestValidateIPAddress(t *testing.T) {
	t.Parallel()

	ip := net.ParseIP("10.10.10.10")
	r.NoError(t, ValidateIPAddress([]net.IP{ip}))
	ip = net.ParseIP("0.0.0.0")
	r.NoError(t, ValidateIPAddress([]net.IP{ip}))

	ips := make([]net.IP, MaxIPSliceLen)
	for i := range ips {
		ips[i] = ip
	}
	r.NoError(t, ValidateIPAddress(ips))

	ips = append(ips, ip)
	r.Error(t, ValidateIPAddress(ips))

	ip = net.ParseIP(".0.0.0")
	r.Error(t, ValidateIPAddress([]net.IP{ip}))
}

func TestValidateCommonName(t *testing.T) {
	r.NoError(t, ValidateCommonName("test"))
	r.NoError(t, ValidateCommonName("t"))
	r.Error(t, ValidateCommonName(""))
	r.NoError(t, ValidateCommonName(strings.Repeat("a", RFC5280CommonNameLen)))
	r.Error(t, ValidateCommonName(strings.Repeat("a", RFC5280CommonNameLen+1)))
}

func TestValidateOrganization(t *testing.T) {
	r.NoError(t, ValidateOrganization("test"))
	r.NoError(t, ValidateOrganization("t"))
	r.Error(t, ValidateOrganization(""))
	r.NoError(t, ValidateOrganization(strings.Repeat("a", RFC5280OrganizationLen)))
	r.Error(t, ValidateOrganization(strings.Repeat("a", RFC5280OrganizationLen+1)))
}

func TestValidateOrganizationalUnit(t *testing.T) {
	r.NoError(t, ValidateOrganizationalUnit("test"))
	r.NoError(t, ValidateOrganizationalUnit("t"))
	r.Error(t, ValidateOrganizationalUnit(""))
	r.NoError(t, ValidateOrganizationalUnit(strings.Repeat("a", RFC5280OrganizationalUnitLen)))
	r.Error(t, ValidateOrganizationalUnit(strings.Repeat("a", RFC5280OrganizationalUnitLen+1)))
}

func TestValidateCountry(t *testing.T) {
	r.NoError(t, ValidateCountry(strings.Repeat("a", RFC5280CountryLen)))
	r.Error(t, ValidateCountry("t"))
	r.Error(t, ValidateCountry(""))
	r.Error(t, ValidateCountry(strings.Repeat("a", RFC5280CountryLen+1)))
}

func TestValidateState(t *testing.T) {
	r.NoError(t, ValidateState("test"))
	r.NoError(t, ValidateState("t"))
	r.Error(t, ValidateState(""))
	r.NoError(t, ValidateState(strings.Repeat("a", RFC5280StateLen)))
	r.Error(t, ValidateState(strings.Repeat("a", RFC5280StateLen+1)))
}

func TestValidateLocality(t *testing.T) {
	r.NoError(t, ValidateLocality("test"))
	r.NoError(t, ValidateLocality("t"))
	r.Error(t, ValidateLocality(""))
	r.NoError(t, ValidateLocality(strings.Repeat("a", RFC5280LocalityLen)))
	r.Error(t, ValidateLocality(strings.Repeat("a", RFC5280LocalityLen+1)))
}
