package protocol

/*
Request and response tags.  Note that all of these
are bound to the APPLICATION ASN.1 class, and not
CONTEXT-SPECIFIC.

For example:

	ModifyResponse ::= [APPLICATION 7] LDAPResult
*/
const (
	TagBindRequest           = iota // 0
	TagBindResponse                 // 1
	TagUnbindRequest                // 2
	TagSearchRequest                // 3
	TagSearchResultEntry            // 4
	TagSearchResultDone             // 5
	TagModifyRequest                // 6
	TagModifyResponse               // 7
	TagAddRequest                   // 8
	TagAddResponse                  // 9
	TagDelRequest                   // 10
	TagDelResponse                  // 11
	TagModifyDNRequest              // 12
	TagModifyDNResponse             // 13
	TagCompareRequest               // 14
	TagCompareResponse              // 15
	TagAbandonRequest               // 16
	_                               // 17
	_                               // 18
	TagSearchResultReference        // 19
	_                               // 20
	_                               // 21
	_                               // 22
	TagExtendedRequest              // 23
	TagExtendedResponse             // 24
	TagIntermediateResponse         // 25
)

const (
	TagExtendedRequestName   = 0
	TagExtendedRequestValue  = 1
	TagExtendedResponseName  = 10
	TagExtendedResponseValue = 11
)

const TagIntermediateResponseName = 0
const TagIntermediateResponseValue = 1

const TagAuthenticationChoiceSimple = 0
const TagAuthenticationChoiceSaslCredentials = 3

const TagModifyDNRequestNewSuperior = 0

const TagBindResponseServerSaslCreds = 7

const modifyRequestChangeOperationAdd = 0
const modifyRequestChangeOperationDelete = 1
const modifyRequestChangeOperationReplace = 2

var enumeratedModifyRequestChangeOperation = map[Enumerated]string{
	modifyRequestChangeOperationAdd:     "add",
	modifyRequestChangeOperationDelete:  "delete",
	modifyRequestChangeOperationReplace: "replace",
}

const ( 
	UBMessageID = MaxInt
	UBSizeLimit = MaxInt
	UBTimeLimit = MaxInt
)

//	maxInt INTEGER ::= 2147483647
const MaxInt = 2147483647
