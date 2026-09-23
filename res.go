package protocol

import (
	"github.com/go-directory/common"
	"github.com/go-directory/encoding/asn1"
)

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

LDAPResult implements [§ 4.1.9 of RFC4511].

See also the [Enumerated] LDAP result code constants.

[§ 4.1.9 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.1.9
*/
type LDAPResult struct {
	ResultCode        Enumerated
	MatchedDN         LDAPDN
	DiagnosticMessage LDAPString
	Referral          *Referral
}

func (r LDAPResult) Encode() ([]byte, error) {
	var out []byte
	code, err := r.ResultCode.Encode()
	if err == nil {
		var payload []byte
		payload = append(payload, code...)

		var mdn []byte
		mdn, err = r.MatchedDN.Encode()
		if err == nil {
			payload = append(payload, mdn...)
			var diag []byte
			diag, err = OctetString(r.DiagnosticMessage).Encode()
			if err == nil {
				payload = append(payload, diag...)
				if r.Referral != nil {
					var refs []byte
					refs, err = r.Referral.Encode() // SEQUENCE OF
					if err == nil {
						// Wrap as a CONTEXT-SPECIFIC [3]
						refs, err = asn1.WrapTLV(refs,
							aTag(asn1.ClassContextSpecific,
								true, uint32(3)))

						if err == nil {
							payload = append(payload, refs...)
						}
					}
				}

				if err == nil {
					// Wrap entire payload as SEQUENCE
					out, err = asn1.WrapTLV(payload, uSeqTag())
				}
			}
		}
	}

	return out, err
}

// setComponentsOf is "broken away" from LDAPResult.Decode, as other protocol
// op types embed LDAPResult and need to call this method *directly* during a
// decode procedure.
func (r *LDAPResult) setComponentsOf(payload []byte) (p int, err error) {
	// resultCode (ENUMERATED)
	_, err = asn1.ReadExpectedPrimitiveTLV(payload, &p,
		asn1.ClassUniversal, uint32(asn1.TagEnumerated))
	if err != nil {
		return p, err
	}
	err = r.ResultCode.Decode(payload[:p])
	if err != nil {
		return p, err
	}

	// matchedDN (OCTET STRING)
	r.MatchedDN, err = asn1.ReadExpectedPrimitiveTLV(payload, &p,
		asn1.ClassUniversal, uint32(asn1.TagOctetString))
	if err != nil {
		return p, err
	}

	// diagnosticMessage (OCTET STRING)
	r.DiagnosticMessage, err = asn1.ReadExpectedPrimitiveTLV(payload, &p,
		asn1.ClassUniversal, uint32(asn1.TagOctetString))
	if err != nil {
		return p, err
	}

	// referral ([3] SEQUENCE OF OCTET STRING) OPTIONAL
	if p >= len(payload) {
		return p, nil
	}

	tag, _ := asn1.ReadTag(payload[p:])
	if tag.Class == asn1.ClassContextSpecific && tag.Tag == 3 {
		tlvLen := func(b []byte) (int, error) {
			if len(b) < 2 {
				return 0, protocolError("ExtendedResponse: short TLV")
			}
			i := 1 // single-byte tag already known
			if i >= len(b) {
				return 0, protocolError("ExtendedResponse: short TLV")
			}
			lb := b[i]
			i++
			var length int
			if lb&0x80 == 0 {
				length = int(lb)
			} else {
				n := int(lb & 0x7F)
				if len(b) < i+n {
					return 0, protocolError("ExtendedResponse: short length octet(s)")
				}
				for j := 0; j < n; j++ {
					length = (length << 8) | int(b[i+j])
				}
				i += n
			}
			return i + length, nil
		}

		total, e := tlvLen(payload[p:])
		if e != nil {
			return p, e
		}

		var refSeq []byte
		// Unwrap CONTEXT-SPECIFIC [3]
		if refSeq, err = asn1.UnwrapTLV(payload[p:], tag); err == nil {
			// Unwrap the outer SEQUENCE wrapping,
			// and decode the individual LDAPString
			// (URI) slices.
			r.Referral = &Referral{}
			err = r.Referral.Decode(refSeq)
		}

		p += total
	}

	return p, err
}

func (r *LDAPResult) Decode(enc []byte) error {
	payload, err := asn1.UnwrapTLV(enc, uSeqTag())
	if err == nil {
		_, err = r.setComponentsOf(payload)
	}

	return err
}

/*
ResultCode [Enumerated] constants, per [§ 4.1.9 of RFC4511].

Note that the following codes and code ranges are RESERVED:

  - 9
  - 15
  - 22 through 31
  - 35
  - 37 through 47
  - 55 through 63
  - 70
  - 72 through 79

[§ 4.1.9 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.1.9
*/
const (
	LDAPResultSuccess                      = Enumerated(common.LDAPResultSuccess)                      // 0
	LDAPResultOperationsError              = Enumerated(common.LDAPResultOperationsError)              // 1
	LDAPResultProtocolError                = Enumerated(common.LDAPResultProtocolError)                // 2
	LDAPResultTimeLimitExceeded            = Enumerated(common.LDAPResultTimeLimitExceeded)            // 3
	LDAPResultSizeLimitExceeded            = Enumerated(common.LDAPResultSizeLimitExceeded)            // 4
	LDAPResultCompareFalse                 = Enumerated(common.LDAPResultCompareFalse)                 // 5
	LDAPResultCompareTrue                  = Enumerated(common.LDAPResultCompareTrue)                  // 6
	LDAPResultAuthMethodNotSupported       = Enumerated(common.LDAPResultAuthMethodNotSupported)       // 7
	LDAPResultStrongAuthRequired           = Enumerated(common.LDAPResultStrongAuthRequired)           // 8
	LDAPResultReferral                     = Enumerated(common.LDAPResultReferral)                     // 10
	LDAPResultAdminLimitExceeded           = Enumerated(common.LDAPResultAdminLimitExceeded)           // 11
	LDAPResultUnavailableCriticalExtension = Enumerated(common.LDAPResultUnavailableCriticalExtension) // 12
	LDAPResultConfidentialityRequired      = Enumerated(common.LDAPResultConfidentialityRequired)      // 13
	LDAPResultSaslBindInProgress           = Enumerated(common.LDAPResultSaslBindInProgress)           // 14
	LDAPResultNoSuchAttribute              = Enumerated(common.LDAPResultNoSuchAttribute)              // 16
	LDAPResultUndefinedAttributeType       = Enumerated(common.LDAPResultUndefinedAttributeType)       // 17
	LDAPResultInappropriateMatching        = Enumerated(common.LDAPResultInappropriateMatching)        // 18
	LDAPResultConstraintViolation          = Enumerated(common.LDAPResultConstraintViolation)          // 19
	LDAPResultAttributeOrValueExists       = Enumerated(common.LDAPResultAttributeOrValueExists)       // 20
	LDAPResultInvalidAttributeSyntax       = Enumerated(common.LDAPResultInvalidAttributeSyntax)       // 21
	LDAPResultNoSuchObject                 = Enumerated(common.LDAPResultNoSuchObject)                 // 32
	LDAPResultAliasProblem                 = Enumerated(common.LDAPResultAliasProblem)                 // 33
	LDAPResultInvalidDNSyntax              = Enumerated(common.LDAPResultInvalidDNSyntax)              // 34
	LDAPResultAliasDereferencingProblem    = Enumerated(common.LDAPResultAliasDereferencingProblem)    // 36
	LDAPResultInappropriateAuthentication  = Enumerated(common.LDAPResultInappropriateAuthentication)  // 48
	LDAPResultInvalidCredentials           = Enumerated(common.LDAPResultInvalidCredentials)           // 49
	LDAPResultInsufficientAccessRights     = Enumerated(common.LDAPResultInsufficientAccessRights)     // 50
	LDAPResultBusy                         = Enumerated(common.LDAPResultBusy)                         // 51
	LDAPResultUnavailable                  = Enumerated(common.LDAPResultUnavailable)                  // 52
	LDAPResultUnwillingToPerform           = Enumerated(common.LDAPResultUnwillingToPerform)           // 53
	LDAPResultLoopDetect                   = Enumerated(common.LDAPResultLoopDetect)                   // 54
	LDAPResultNamingViolation              = Enumerated(common.LDAPResultNamingViolation)              // 64
	LDAPResultObjectClassViolation         = Enumerated(common.LDAPResultObjectClassViolation)         // 65
	LDAPResultNotAllowedOnNonLeaf          = Enumerated(common.LDAPResultNotAllowedOnNonLeaf)          // 66
	LDAPResultNotAllowedOnRDN              = Enumerated(common.LDAPResultNotAllowedOnRDN)              // 67
	LDAPResultEntryAlreadyExists           = Enumerated(common.LDAPResultEntryAlreadyExists)           // 68
	LDAPResultObjectClassModsProhibited    = Enumerated(common.LDAPResultObjectClassModsProhibited)    // 69
	LDAPResultAffectsMultipleDSAs          = Enumerated(common.LDAPResultAffectsMultipleDSAs)          // 71
	LDAPResultOther                        = Enumerated(common.LDAPResultOther)                        // 80
)
