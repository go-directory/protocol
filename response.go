package protocol

/*
response.go serves as an interface to go-directory/protocol/response.
*/

import (
	"github.com/go-directory/protocol/response"
)

/*
Response links to the [response.Response] interface type.
*/
type Response = response.Response

/*
	LDAPResult ::= SEQUENCE {
		resultCode         ENUMERATED {
			success                      (0),
			operationsError              (1),
			protocolError                (2),
			timeLimitExceeded            (3),
			sizeLimitExceeded            (4),
			compareFalse                 (5),
			compareTrue                  (6),
			authMethodNotSupported       (7),
			strongerAuthRequired         (8),
				-- 9 reserved --
			referral                     (10),
			adminLimitExceeded           (11),
			unavailableCriticalExtension (12),
			confidentialityRequired      (13),
			saslBindInProgress           (14),
			noSuchAttribute              (16),
			undefinedAttributeType       (17),
			inappropriateMatching        (18),
			constraintViolation          (19),
			attributeOrValueExists       (20),
			invalidAttributeSyntax       (21),
				-- 22-31 unused --
			noSuchObject                 (32),
			aliasProblem                 (33),
			invalidDNSyntax              (34),
				-- 35 reserved for undefined isLeaf --
			aliasDereferencingProblem    (36),
				-- 37-47 unused --
			inappropriateAuthentication  (48),
			invalidCredentials           (49),
			insufficientAccessRights     (50),
			busy                         (51),
			unavailable                  (52),
			unwillingToPerform           (53),
			loopDetect                   (54),
				-- 55-63 unused --
			namingViolation              (64),
			objectClassViolation         (65),
			notAllowedOnNonLeaf          (66),
			notAllowedOnRDN              (67),
			entryAlreadyExists           (68),
			objectClassModsProhibited    (69),
				-- 70 reserved for CLDAP --
			affectsMultipleDSAs          (71),
				-- 72-79 unused --
			other                        (80),
			...  },
		matchedDN          LDAPDN,
		diagnosticMessage  LDAPString,
		referral           [3] Referral OPTIONAL }

LDAPResult implements [§ 4.1.9 of RFC4511]. See also the LDAP result code constants.

[§ 4.1.9 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.1.9
*/
type LDAPResult = response.LDAPResult

var (
	responseDecode      = response.Decode
	responseDecodeByTag = response.DecodeByTag
)

/*
StartTLSResponse defines an instance of [ExtendedResponse], per [§ 4.14.2 of RFC4511].
It is used by the DSA to respond to a request for StartTLS.

[§ 4.14.2 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.14.2
*/
var StartTLSResponse = ExtendedResponse{
	ResponseName: &response.NoticeOfStartTLS,
}

/*
Response tags.
*/
const (
	TagBindResponse          = response.TagBind                  // 1
	TagSearchResultEntry     = response.TagSearchResultEntry     // 4
	TagSearchResultDone      = response.TagSearchResultDone      // 5
	TagModifyResponse        = response.TagModify                // 7
	TagAddResponse           = response.TagAdd                   // 9
	TagDelResponse           = response.TagDel                   // 11
	TagModifyDNResponse      = response.TagModifyDN              // 13
	TagCompareResponse       = response.TagCompare               // 15
	TagSearchResultReference = response.TagSearchResultReference // 19
	TagExtendedResponse      = response.TagExtended              // 24
	TagIntermediateResponse  = response.TagIntermediate          // 25
)

/*
	AddResponse ::= [APPLICATION 9] LDAPResult

Add implements [§ 4.7 of RFC4511].

[§ 4.7 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.7
*/
type AddResponse = response.Add

/*
	BindResponse ::= [APPLICATION 1] SEQUENCE {
		COMPONENTS OF LDAPResult,
		serverSaslCreds    [7] OCTET STRING OPTIONAL }

Bind implements [§ 4.2.2 of RFC4511].

[§ 4.2.2 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.2.2
*/
type BindResponse = response.Bind

/*
	CompareResponse ::= [APPLICATION 15] LDAPResult

Compare implements [§ 4.10 of RFC4511].

[§ 4.10 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.10
*/
type CompareResponse = response.Compare

/*
	ExtendedResponse ::= [APPLICATION 24] SEQUENCE {
		COMPONENTS OF LDAPResult,
		responseName     [10] LDAPOID OPTIONAL,
		responseValue    [11] OCTET STRING OPTIONAL }

Extended implements [§ 4.12 of RFC4511].

[§ 4.12 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.12
*/
type ExtendedResponse = response.Extended

/*
	DelResponse ::= [APPLICATION 11] LDAPResult

Del implements [§ 4.8 of RFC4511], circumscribing an [LDAPResult].

[§ 4.8 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.8
*/
type DelResponse = response.Del

/*
	IntermediateResponse ::= [APPLICATION 25] SEQUENCE {
	     responseName     [0] LDAPOID OPTIONAL,
	     responseValue    [1] OCTET STRING OPTIONAL }

Intermediate implements [§ 4.13 of RFC4511].

[§ 4.13 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.13
*/
type IntermediateResponse = response.Intermediate

/*
	ModifyDNResponse ::= [APPLICATION 13] LDAPResult

ModifyDN implements [§ 4.9 of RFC4511], circumscribing an [LDAPResult].

[§ 4.9 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.9
*/
type ModifyDNResponse = response.ModifyDN

/*
	ModifyResponse ::= [APPLICATION 7] LDAPResult

Modify implements [§ 4.6 of RFC4511], circumscribing an [LDAPResult].

[§ 4.6 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.6
*/
type ModifyResponse = response.Modify

/*
	SearchResultDone ::= [APPLICATION 5] LDAPResult

SearchResultDone implements [§ 4.5.2 of RFC4511], circumscribing
an [LDAPResult] SEQUENCE.

[§ 4.5.2 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.5.2
*/
type SearchResultDone = response.SearchResultDone

/*
	SearchResultReference ::= [APPLICATION 19] SEQUENCE SIZE (1..MAX) OF uri URI

SearchResultReference implements [§ 4.5.2 of RFC4511].

[§ 4.5.2 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.5.2
*/
type SearchResultReference = response.SearchResultReference

/*
	SearchResultEntry ::= [APPLICATION 4] SEQUENCE {
	    objectName LDAPDN,
	    attributes PartialAttributeList }

SearchResultEntry implements [§ 4.5.2 of RFC4511].

[§ 4.5.2 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.5.2
*/
type SearchResultEntry = response.SearchResultEntry

/*
        Referral ::= SEQUENCE SIZE (1..MAX) OF uri URI

Referral implements [§ 4.1.10 of RFC4511].

[§ 4.1.10 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.1.10
*/
type Referral = response.Referral
