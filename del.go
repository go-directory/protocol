package protocol

import (
	"github.com/go-directory/encoding/asn1"
	"github.com/go-directory/syntax"
)

/*
	DelRequest ::= [APPLICATION 10] LDAPDN

DelRequest implements [§ 4.8 of RFC4511].

[§ 4.8 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.8
*/
type DelRequest syntax.LDAPDN

func (_ DelRequest) Tag() int { return TagDelRequest }
func (_ DelRequest) classTag() asn1.Tag {
	return aTag(asn1.ClassApplication, false, uint32(TagDelRequest))
}
func (_ DelRequest) isProtocolOp() {}
func (_ DelRequest) isRequestOp()  {}

/*
Encode returns an instance of []byte alongside an error following
an attempt to encode the contents of the receiver instance as an
[APPLICATION 10] [LDAPDN].
*/
func (r DelRequest) Encode() ([]byte, error) {
	var enc []byte
	payload, err := OctetString(r).Encode()
	if err == nil {
		enc, err = asn1.WrapTLV(payload, r.classTag()) // [APPLICATION 10]
	}

	return enc, err
}

/*
Decode returns an error following an attempt to decode and write
the input encoding to the receiver instance. The encoding must not
be truncated, and must bear the [APPLICATION 10] tag.
*/
func (r *DelRequest) Decode(enc []byte) error {
	payload, err := asn1.UnwrapTLV(enc, r.classTag()) // [APPLICATION 10]
	if err == nil {
		var dec OctetString
		if err = dec.Decode(payload); err == nil {
			*r = DelRequest(dec)
		}
	}

	return err
}

/*
	DelResponse ::= [APPLICATION 11] LDAPResult

DelRequest implements [§ 4.8 of RFC4511], circumscribing an [LDAPResult].

[§ 4.8 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.8
*/
type DelResponse LDAPResult

func (_ DelResponse) Tag() int { return TagDelResponse }
func (_ DelResponse) classTag() asn1.Tag {
	return aTag(asn1.ClassApplication, true, uint32(TagDelResponse))
}
func (_ DelResponse) isProtocolOp() {}
func (_ DelResponse) isResponseOp() {}

/*
Encode returns an instance of []byte alongside an error following
an attempt to encode the contents of the receiver instance as an
[APPLICATION 11] [LDAPResult] SEQUENCE.
*/
func (r DelResponse) Encode() ([]byte, error) {
	var enc []byte
	res, err := LDAPResult(r).Encode() // LDAPResult SEQUENCE
	if err == nil {
		enc, err = asn1.WrapTLV(res, r.classTag()) // [APPLICATION 11]
	}

	return enc, err
}

/*
Decode returns an error following an attempt to decode and write
the input encoding to the receiver instance. The encoding must not
be truncated, and must bear the [APPLICATION 11] tag, circumscribing
an [LDAPResult] SEQUENCE.
*/
func (r *DelResponse) Decode(enc []byte) error {
	payload, err := asn1.UnwrapTLV(enc, r.classTag()) // [APPLICATION 11]
	if err == nil {
		var dec LDAPResult
		if err = dec.Decode(payload); err == nil { // LDAPResult SEQUENCE
			*r = DelResponse(dec)
		}
	}

	return err
}
