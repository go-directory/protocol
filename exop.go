package protocol

import (
	"github.com/go-directory/encoding/asn1"
)

/*
	ExtendedRequest ::= [APPLICATION 23] SEQUENCE {
	     requestName      [0] LDAPOID,
	     requestValue     [1] OCTET STRING OPTIONAL }

ExtendedRequest implements [§ 4.12 of RFC4511].

[§ 4.12 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.12
*/
type ExtendedRequest struct {
	RequestName  LDAPOID
	RequestValue *OctetString
}

func (_ ExtendedRequest) classTag() asn1.Tag {
	return aTag(asn1.ClassApplication, true, uint32(TagExtendedRequest))
}
func (_ ExtendedRequest) Tag() int      { return TagExtendedRequest }
func (_ ExtendedRequest) isProtocolOp() {}
func (_ ExtendedRequest) isRequestOp()  {}

/*
Encode returns an instance of []byte alongside an error following
an attempt to encode the contents of the receiver instance as an
[APPLICATION 23] tag, circumscribing a SEQUENCE.
*/
func (r ExtendedRequest) Encode() ([]byte, error) {
	var enc []byte
	cmpnt, err := r.RequestName.Encode()
	if err == nil {
		cmpnt, err = asn1.WrapTLV(cmpnt,
			aTag(asn1.ClassContextSpecific,
				false, uint32(TagExtendedRequestName)))

		if err == nil {
			enc = append(enc, cmpnt...)
			if r.RequestValue != nil {
				cmpnt, err = r.RequestValue.Encode()
				if err == nil {
					cmpnt, err = asn1.WrapTLV(cmpnt,
						aTag(asn1.ClassContextSpecific, false,
							uint32(TagExtendedRequestValue)))
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
		}
	}

	return enc, err
}

/*
Decode returns an error following an attempt to decode and write the
input encoding to the receiver instance. The encoding must not be
truncated and must bear the [APPLICATION 23] tag, circumscribing a
SEQUENCE.
*/
func (r *ExtendedRequest) Decode(enc []byte) error {
	var err error
	enc, err = asn1.UnwrapTLV(enc,
		r.classTag(), // [APPLICATION 23]
		uSeqTag())    // SEQUENCE

	if err == nil {
		p := 0
		var payload []byte
		payload, err = asn1.ReadExpectedPrimitiveTLV(enc, &p,
			asn1.ClassContextSpecific,
			uint32(TagExtendedRequestName))

		var value []byte
		if err == nil {
			p2 := 0
			value, err = asn1.ReadExpectedPrimitiveTLV(payload, &p2,
				asn1.ClassUniversal,
				uint32(asn1.TagOctetString))
		}

		if err == nil {
			r.RequestName = value
			if len(payload) < len(enc) {
				rest := enc[len(payload)+2:] // 2 == header

				p = 0
				payload, err = asn1.ReadExpectedPrimitiveTLV(rest,
					&p, asn1.ClassContextSpecific,
					uint32(TagExtendedRequestValue))

				if err == nil {
					p = 0
					value, err = asn1.ReadExpectedPrimitiveTLV(payload, &p,
						asn1.ClassUniversal, uint32(asn1.TagOctetString))

					if err == nil {
						val := OctetString(value)
						r.RequestValue = &val
					}
				}
			}
		}
	}

	return err
}

/*
	ExtendedResponse ::= [APPLICATION 24] SEQUENCE {
		COMPONENTS OF LDAPResult,
		responseName     [10] LDAPOID OPTIONAL,
		responseValue    [11] OCTET STRING OPTIONAL }

ExtendedResponse implements [§ 4.12 of RFC4511].

[§ 4.12 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.12
*/
type ExtendedResponse struct {
	LDAPResult
	ResponseName  *LDAPOID
	ResponseValue *OctetString
}

/*
Encode returns an instance of []byte alongside an error following
an attempt to encode the contents of the receiver instance as an
[APPLICATION 24] tag, circumscribing a SEQUENCE.
*/
func (r ExtendedResponse) Encode() ([]byte, error) {
	var enc []byte
	res, err := r.LDAPResult.Encode()
	if err == nil {
		// COMPONENTS OF: get rid of the
		// outer SEQUENCE layer, leaving
		// just the component values.
		// Those are what we keep.
		res, err = asn1.UnwrapTLV(res, uSeqTag())
		if err == nil {
			enc = append(enc, res...)
			if r.ResponseName != nil {
				res, err = r.ResponseName.Encode()
				if err == nil {
					res, err = asn1.WrapTLV(res,
						aTag(asn1.ClassContextSpecific, false,
							uint32(TagExtendedResponseName)))
					if err == nil {
						enc = append(enc, res...)
					}
				}
			}

			if r.ResponseValue != nil {
				res, err = r.ResponseValue.Encode()
				if err == nil {
					res, err = asn1.WrapTLV(res,
						aTag(asn1.ClassContextSpecific, false,
							uint32(TagExtendedResponseValue)))
					if err == nil {
						enc = append(enc, res...)
					}
				}
			}

			if err == nil {
				enc, err = asn1.WrapTLV(enc,
					uSeqTag(),    // SEQUENCE
					r.classTag()) // [APPLICATION 24]
			}
		}
	}

	return enc, err
}

/*
Decode returns an error following an attempt to decode and write the
input encoding to the receiver instance.  The encoding must not be
truncated and must bear the [APPLICATION 24] tag, circumscribing a
SEQUENCE.
*/
func (r *ExtendedResponse) Decode(enc []byte) error {
	payload, err := asn1.UnwrapTLV(enc,
		r.classTag(), // [APPLICATION 24]
		uSeqTag())    // SEQUENCE

	if err == nil {
		var p int
		p, err = r.LDAPResult.setComponentsOf(payload)
		for p < len(payload) && err == nil {
			tag, _ := asn1.ReadTag(payload[p:])
			var res []byte
			res, err = asn1.ReadExpectedPrimitiveTLV(payload, &p,
				asn1.ClassContextSpecific, tag.Tag)

			if err == nil {
				switch tag.Tag {
				case TagExtendedResponseName:
					var loid LDAPOID
					err = loid.Decode(res)
					r.ResponseName = &loid

				case TagExtendedResponseValue:
					var val OctetString
					err = val.Decode(res)
					r.ResponseValue = &val
				}
			}
		}
	}

	return err
}

func (_ ExtendedResponse) classTag() asn1.Tag {
	return aTag(asn1.ClassApplication, true, uint32(TagExtendedResponse))
}
func (_ ExtendedResponse) Tag() int      { return TagExtendedResponse }
func (_ ExtendedResponse) isProtocolOp() {}
func (_ ExtendedResponse) isResponseOp() {}
