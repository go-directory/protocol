package protocol

/*
request.go serves as an interface to go-directory/protocol/request.
*/

import (
	"github.com/go-directory/protocol/request"
)

/*
Request implements a subset of LDAPMessage.ProtocolOp, encompassing only the *request*
types defined throughout the subsections of [§ 4.1 of RFC4511].

[§ 4.1 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.1
*/
type Request = request.Request

/*
	MessageID ::= INTEGER (0 ..  maxInt)

MessageID implements [§ 4.1.1 of RFC4511], and serves the "messageID"
component of the LDAPMessage SEQUENCE.

Note that instances of this type are constrained to the unsigned portion
of int32:

	(0 ..  maxInt)
	maxInt INTEGER ::= 2147483647 -- (2^^31 - 1) --

[§ 4.1.1 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.1.1
*/
type MessageID = request.MessageID

/*
Request tags, linked from the [request] package.
*/
const (
	TagBindRequest     = request.TagBind     // 0
	TagUnbindRequest   = request.TagUnbind   // 2
	TagSearchRequest   = request.TagSearch   // 3
	TagModifyRequest   = request.TagModify   // 6
	TagAddRequest      = request.TagAdd      // 8
	TagDelRequest      = request.TagDel      // 10
	TagModifyDNRequest = request.TagModifyDN // 12
	TagCompareRequest  = request.TagCompare  // 14
	TagAbandonRequest  = request.TagAbandon  // 16
	TagExtendedRequest = request.TagExtended // 23
)

/*
Request CHOICE names, as defined in [§ 4.1.1 of RFC4511].

[§ 4.1.1 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.1.1
*/
const (
	nameAbandonRequestChoice  = `abandonRequest`
	nameAddRequestChoice      = `addRequest`
	nameBindRequestChoice     = `bindRequest`
	nameCompareRequestChoice  = `compareRequest`
	nameDelRequestChoice      = `delRequest`
	nameExtendedRequestChoice = `extendedReq`
	nameModifyRequestChoice   = `modifyRequest`
	nameModifyDNRequestChoice = `modDNRequest`
	nameSearchRequestChoice   = `searchRequest`
	nameUnbindRequestChoice   = `unbindRequest`
)

var (
	requestDecode      = request.Decode
	requestDecodeByTag = request.DecodeByTag
)

/*
StartTLSRequest defines an instance of [ExtendedRequest], per [§ 4.14.1 of RFC4511].
It is used by the DUA to request StartTLS be used for the session.

[§ 4.14.1 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.14.1
*/
var StartTLSRequest = ExtendedRequest{
	RequestName: request.NoticeOfStartTLS,
}

/*
	ModifyRequest ::= [APPLICATION 6] SEQUENCE {
	        object          LDAPDN,
	        changes         SEQUENCE OF change SEQUENCE {
	                operation       ENUMERATED {
	                        add     (0),
	                        delete  (1),
	                        replace (2),
	                        ...  },
	        modification    PartialAttribute } }

ModifyRequest implements [§ 4.6 of RFC4511].

[§ 4.6 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.6
*/
type ModifyRequest = request.Modify

type ModifyRequestChange = request.ModifyChange

/*
	ModifyDNRequest ::= [APPLICATION 12] SEQUENCE {
	        entry           LDAPDN,
	        newrdn          RelativeLDAPDN,
	        deleteoldrdn    BOOLEAN,
	        newSuperior     [0] LDAPDN OPTIONAL }

ModifyDN implements [§ 4.9 of RFC4511]. Instances of this type can be assembled
using the [RenameEntry], [MoveEntry] and [RenameAndMoveEntry] functions.

[§ 4.9 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.9
*/
type ModifyDNRequest = request.ModifyDN

/*
	CompareRequest ::= [APPLICATION 14] SEQUENCE {
	     entry           LDAPDN,
	     ava             AttributeValueAssertion }

CompareRequest implements [§ 4.10 of RFC4511].

[§ 4.10 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.10
*/
type CompareRequest = request.Compare

/*
	Extended ::= [APPLICATION 23] SEQUENCE {
	     requestName      [0] LDAPOID,
	     requestValue     [1] OCTET STRING OPTIONAL }

Extended implements [§ 4.12 of RFC4511].

[§ 4.12 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.12
*/
type ExtendedRequest = request.Extended

/*
	AddRequest ::= [APPLICATION 8] SEQUENCE {
	     entry           LDAPDN,
	     attributes      AttributeList }

AddRequest implements [§ 4.7 of RFC4511].

[§ 4.7 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.7
*/
type AddRequest = request.Add

/*
	BindRequest ::= [APPLICATION 0] SEQUENCE {
	        version                 INTEGER (1 ..  127),
	        name                    LDAPDN,
	        authentication          AuthenticationChoice }

BindRequest implements [§ 4.2 of RFC4511].

[§ 4.2 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.2
*/
type BindRequest = request.Bind

/*
SimpleBind returns an instance of [BindRequest] in the context of a
"simple" [request.AuthenticationChoice]. Successful use of this method
will return the following structure:

	  BindRequest{
		Version: 3,
		Name: LDAPDN(<the bind dn>),	     		  // LDAPDN (OCTET STRING)
		Authentication: SimpleCredentials(<the bind pw>), // Authentication CHOICE [0], OCTET STRING
	  }
*/
var SimpleBind = request.SimpleBind

/*
	UnbindRequest ::= [APPLICATION 2] NULL

UnbindRequest implements [§ 4.3 of RFC4511].

Note that there is no response counterpart definition for this type.

[§ 4.3 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.3
*/
type UnbindRequest = request.Unbind

/*
	DelRequest ::= [APPLICATION 10] LDAPDN

DelRequest implements [§ 4.8 of RFC4511].

[§ 4.8 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.8
*/
type DelRequest = request.Del

/*
	scope ::= ENUMERATED {
	    baseObject       (0),
	    singleLevel      (1),
	    wholeSubtree     (2),
	    ...  },

Search Scope constants, per [SearchRequest], defined in [§ 4.5.1 of RFC4511].

[§ 4.5.1 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.5.1
*/
const (
	ScopeBaseObject   = request.ScopeBaseObject   // 0
	ScopeSingleLevel  = request.ScopeSingleLevel  // 1
	ScopeWholeSubtree = request.ScopeWholeSubtree // 2
)

/*
	derefAliases ::= ENUMERATED {
	     neverDerefAliases       (0),
	     derefInSearching        (1),
	     derefFindingBaseObj     (2),
	     derefAlways             (3) },

Alias Dereferencing constants, per [SearchRequest], defined in [§ 4.5.1 of RFC4511].

[§ 4.5.1 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.5.1
*/
const (
	DerefAliasesNever   = request.DerefAliasesNever   // 0
	DerefInSearching    = request.DerefInSearching    // 1
	DerefFindingBaseObj = request.DerefFindingBaseObj // 2
	DerefAlways         = request.DerefAlways         // 3
)

/*
	SearchRequest ::= [APPLICATION 3] SEQUENCE {
	     baseObject      LDAPDN,
	     scope           ENUMERATED {
	          baseObject              (0),
	          singleLevel             (1),
	          wholeSubtree            (2),
	          ...  },
	     derefAliases    ENUMERATED {
	          neverDerefAliases       (0),
	          derefInSearching        (1),
	          derefFindingBaseObj     (2),
	          derefAlways             (3) },
	     sizeLimit       INTEGER (0 ..  maxInt),
	     timeLimit       INTEGER (0 ..  maxInt),
	     typesOnly       BOOLEAN,
	     filter          Filter,
	     attributes      AttributeSelection }

SearchRequest implements [§ 4.5.1 of RFC4511].

[§ 4.5.1 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.5.1
*/
type SearchRequest = request.Search

/*
	AbandonRequest ::= [APPLICATION 16] MessageID

Abandon request implements [§ 4.11 of RFC4511], circumscribing a [MessageID].

Note that there is no response counterpart definition for this type.

[§ 4.11 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.11
*/
type AbandonRequest = request.Abandon
