package protocol

/*
response.go serves as an interface to go-directory/protocol/response.
*/

import (
	"github.com/go-directory/protocol/response"
)

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

var responseDecode = response.Decode

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
