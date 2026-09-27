package controls

import (
	"github.com/go-directory/common"
)

func protocolError(msg ...string) error {
	m := append([]string{"Protocol error"}, msg...)
	return common.LDAPResultProtocolError.New(m...)
}

/*
ErrorUnexpectedControlType returns an LDAP Protocol Error for situations
in which a "controlType" [LDAPOID] instance received differs from that
which was expected.
*/
func ErrorUnexpectedControlType(want, got LDAPOID) error {
	return protocolError("Control: type OID unexpected; want ",
		want.String(), ", got ", got.String())
}
