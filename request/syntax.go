package request

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
	Filter                  = syntax.Filter
	LDAPDN                  = syntax.LDAPDN
	LDAPOID                 = syntax.LDAPOID
	Boolean                 = syntax.Boolean
	Integer                 = syntax.Integer
	Attribute               = syntax.Attribute
	LDAPString              = syntax.LDAPString
	Enumerated              = syntax.Enumerated
	OctetString             = syntax.OctetString
	AttributeType           = syntax.AttributeType
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

const MaxInt = syntax.MaxInt

type Null syntax.Null

func (r Null) cast() syntax.Null { return syntax.Null(r) }

/*
defaultFilter represents the official default [Filter], "(objectClass=*)".
*/
var defaultFilter = syntax.DefaultFilter

/*
filterDecode is a top-level [Filter] decompiler.
*/
var filterDecode = syntax.FilterDecode

func NewInteger(x any) (Integer, error) {
	i, err := syntax.NewInteger(x)
	return i, err
}

var NewLDAPDN = syntax.NewLDAPDN
var NewLDAPOID = syntax.NewLDAPOID
var NewFilter = syntax.NewFilter
