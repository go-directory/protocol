package protocol

import (
	"github.com/go-directory/encoding/asn1"
)

/*
	IntermediateResponse ::= [APPLICATION 25] SEQUENCE {
	     responseName     [0] LDAPOID OPTIONAL,
	     responseValue    [1] OCTET STRING OPTIONAL }

IntermediateResponse implements [§ 4.13 of RFC4511].

[§ 4.13 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.13
*/
type IntermediateResponse struct {
	ResponseName  *LDAPOID
	ResponseValue *OctetString
}

func (_ IntermediateResponse) Tag() int { return TagIntermediateResponse }
func (_ IntermediateResponse) classTag() asn1.Tag {
	return aTag(asn1.ClassApplication, true, uint32(TagIntermediateResponse))
}
func (_ IntermediateResponse) isProtocolOp() {}
func (_ IntermediateResponse) isResponseOp() {}

/*
Encode returns an instance of []byte alongside an error following
an attempt to encode the contents of the receiver instance as
[APPLICATION 25], circumscribing a SEQUENCE.
*/
func (r IntermediateResponse) Encode() ([]byte, error) {
	var enc []byte
	var err error
	if r.ResponseName != nil {
		var cmpnt []byte
		cmpnt, err = r.ResponseName.Encode()
		if err == nil {
			cmpnt, err = asn1.WrapTLV(cmpnt,
				aTag(asn1.ClassContextSpecific, false,
					uint32(TagIntermediateResponseName)))
			if err == nil {
				enc = append(enc, cmpnt...)
			}
		}
	}

	if r.ResponseValue != nil && err == nil {
		var cmpnt []byte
		cmpnt, err = r.ResponseValue.Encode()
		if err == nil {
			cmpnt, err = asn1.WrapTLV(cmpnt,
				aTag(asn1.ClassContextSpecific, false,
					uint32(TagIntermediateResponseValue)))
			if err == nil {
				enc = append(enc, cmpnt...)
			}
		}
	}

	if err == nil {
		enc, err = asn1.WrapTLV(enc,
			uSeqTag(),    // SEQUENCE
			r.classTag()) // [APPLICATION 23]
	}

	return enc, err
}

/*
Decode returns an error following an attempt to decode and write the
input encoding to the receiver instance
*/
func (r *IntermediateResponse) Decode(enc []byte) error {
	payload, err := asn1.UnwrapTLV(enc,
		r.classTag(), // [APPLICATION 23]
		uSeqTag())    // SEQUENCE

	ct := 0
	if len(payload) > 0 && err == nil {
		p := 0
		for p < len(payload) && ct < 2 && err == nil {
			var val []byte
			val, err = asn1.ReadExpectedPrimitiveTLV(payload,
				&p, asn1.ClassContextSpecific, uint32(ct))

			if err == nil {
				if ct == TagIntermediateResponseName {
					var loid LDAPOID
					err = loid.Decode(val)
					r.ResponseName = &loid
				} else if ct == TagIntermediateResponseValue {
					var rval OctetString
					err = rval.Decode(val)
					r.ResponseValue = &rval
				}
				ct++
			}
		}
	}

	return err
}
