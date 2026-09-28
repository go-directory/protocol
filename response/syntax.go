package response

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
	URI                  = syntax.URI
	LDAPDN               = syntax.LDAPDN
	LDAPOID              = syntax.LDAPOID
	LDAPString           = syntax.LDAPString
	Enumerated           = syntax.Enumerated
	OctetString          = syntax.OctetString
	AttributeValue       = syntax.AttributeValue
	PartialAttribute     = syntax.PartialAttribute
	AttributeDescription = syntax.AttributeDescription
	PartialAttributeList = syntax.PartialAttributeList
)

const MaxInt = syntax.MaxInt
