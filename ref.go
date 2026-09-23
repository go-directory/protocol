package protocol

import (
	"github.com/go-directory/encoding/asn1"
)

/*
	Referral ::= SEQUENCE SIZE (1..MAX) OF uri URI

Referral implements [§ 4.1.10 of RFC4511].

[§ 4.1.10 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.1.10
*/
type Referral []URI

/*
Tag returns 0x10 (16) for SEQUENCE OF.
*/
func (_ Referral) Tag() int { return int(asn1.TagSequence) }
func (_ Referral) classTag() asn1.Tag {
	return aTag(asn1.ClassUniversal, true, uint32(asn1.TagSequence))
}

func (r Referral) Encode() ([]byte, error) {
	// Create slice of encoded URIs
	var err error
	var enc []byte
	for i := 0; i < len(r) && err == nil; i++ {
		var slice []byte
		slice, err = OctetString(r[i]).Encode()
		enc = append(enc, slice...)
	}

	if err == nil {
		// Wrap as a SEQUENCE OF URI
		enc, err = asn1.WrapTLV(enc, uSeqTag())
	}

	return enc, err
}

func (r *Referral) Decode(enc []byte) error {
	payload, err := asn1.UnwrapTLV(enc, uSeqTag())
	if err == nil {
		p := 0
		for p < len(payload) && err == nil {
			var uriVal []byte
			uriVal, err = asn1.ReadExpectedPrimitiveTLV(payload, &p,
				asn1.ClassUniversal, uint32(asn1.TagOctetString))

			if err == nil {
				*r = append(*r, URI(uriVal))
			}
		}
	}

	return err
}
