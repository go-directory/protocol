package protocol

/*
syntax.go serves as an interface to go-directory/syntax.
*/

import (
	"github.com/go-directory/syntax"
)

/*
Aliases of [go-directory/syntax] types which need not be extended.

[go-directory/syntax]: https://github.com/go-directory/syntax
*/
type (
	LDAPDN                  = syntax.LDAPDN
	LDAPString              = syntax.LDAPString
	AttributeType           = syntax.AttributeType
	AttributeList           = syntax.AttributeList
	AttributeValue          = syntax.AttributeValue
	AttributeOption         = syntax.AttributeOption
	PartialAttribute        = syntax.PartialAttribute
	AttributeSelection      = syntax.AttributeSelection
	AttributeDescription    = syntax.AttributeDescription
)

type EntryAttribute syntax.PartialAttribute
