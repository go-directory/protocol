package protocol

/*
types.go contains type and function aliases from go-directory/syntax.
*/

import (
	"github.com/go-directory/syntax"
)

/*
Aliases of [go-directory/syntax] types which need not be extended.

[go-directory/syntax]: https://github.com/go-directory/syntax
*/
type (
	URI                     = syntax.URI
	Filter                  = syntax.Filter
	LDAPDN                  = syntax.LDAPDN
	LDAPOID                 = syntax.LDAPOID
	Boolean                 = syntax.Boolean
	Integer                 = syntax.Integer
	LDAPString              = syntax.LDAPString
	Enumerated              = syntax.Enumerated
	OctetString             = syntax.OctetString
	AttributeList           = syntax.AttributeList
	AttributeValue          = syntax.AttributeValue
	AssertionValue          = syntax.AssertionValue
	RelativeLDAPDN          = syntax.RelativeLDAPDN
	PartialAttribute        = syntax.PartialAttribute
	AttributeSelection      = syntax.AttributeSelection
	AttributeDescription    = syntax.AttributeDescription
	PartialAttributeList    = syntax.PartialAttributeList
	AttributeValueAssertion = syntax.AttributeValueAssertion
)

/*
DefaultFilter represents the official default [Filter], "(objectClass=*)".
*/
var DefaultFilter = syntax.DefaultFilter

/*
FilterDecode is a top-level [Filter] decompiler.
*/
var FilterDecode = syntax.FilterDecode

func NewInteger(x any) (Integer, error) {
	i, err := syntax.NewInteger(x)
	return i, err
}

var NewLDAPDN = syntax.NewLDAPDN
var NewLDAPOID = syntax.NewLDAPOID

var NewFilter = syntax.NewFilter

/*
Text is a convenience type meant to work in situations
where either a string or []byte is acceptable for input.
*/
type Text interface{ ~string | ~[]byte }
