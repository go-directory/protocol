package protocol

import (
	"github.com/go-directory/encoding/asn1"
)

/*
	AddRequest ::= [APPLICATION 8] SEQUENCE {
	     entry           LDAPDN,
	     attributes      AttributeList }

AddRequest implements [§ 4.7 of RFC4511].

[§ 4.7 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.7
*/
type AddRequest struct {
	Entry      LDAPDN
	Attributes AttributeList
}

func (_ AddRequest) Kind() string   { return `request` }
func (_ AddRequest) Choice() string { return nameAddRequestChoice }
func (_ AddRequest) Tag() int       { return TagAddRequest }
func (_ AddRequest) classTag() asn1.Tag {
	return aTag(asn1.ClassApplication, true, uint32(TagAddRequest))
}

func (r AddRequest) Encode() ([]byte, error) {
	var outer []byte
	ldn, err := r.Entry.Encode()
	if err == nil {
		var attrs []byte
		if attrs, err = r.Attributes.Encode(); err == nil {
			outer, err = asn1.WrapTLV(append(ldn, attrs...),
				uSeqTag(),    // SEQUENCE
				r.classTag()) // [APPLICATION 8]
		}
	}

	return outer, err
}

func (r *AddRequest) Decode(enc []byte) error {
	payload, err := asn1.UnwrapTLV(enc,
		r.classTag(), // [APPLICATION 8]
		uSeqTag())    // SEQUENCE

	if err == nil {
		p := 0
		var dnPayload []byte
		dnPayload, err = asn1.ReadExpectedPrimitiveTLV(payload, &p,
			asn1.ClassUniversal, uint32(asn1.TagOctetString))

		if err == nil {
			r.Entry = dnPayload

			var atl AttributeList
			if err = atl.Decode(payload[p:]); err == nil {
				r.Attributes = atl
			}
		}
	}

	return err

}

func (_ AddRequest) isProtocolOp() {}
func (_ AddRequest) isRequestOp()  {}

/*
	AddResponse ::= [APPLICATION 9] LDAPResult

AddResponse implements [§ 4.7 of RFC4511].

[§ 4.7 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.7
*/
type AddResponse LDAPResult

func (_ AddResponse) Kind() string   { return `response` }
func (_ AddResponse) Choice() string { return nameAddResponseChoice }
func (_ AddResponse) Tag() int       { return TagAddResponse }
func (_ AddResponse) classTag() asn1.Tag {
	return aTag(asn1.ClassApplication, true, uint32(TagAddResponse))
}

func (r AddResponse) Encode() ([]byte, error) {
	var enc []byte
	res, err := LDAPResult(r).Encode() // LDAPResult SEQUENCE
	if err == nil {
		enc, err = asn1.WrapTLV(res, r.classTag()) // [APPLICATION 9]
	}

	return enc, err
}

func (r *AddResponse) Decode(enc []byte) error {
	payload, err := asn1.UnwrapTLV(enc, r.classTag()) // [APPLICATION 9]
	if err == nil {
		var dec LDAPResult
		if err = dec.Decode(payload); err == nil { // LDAPResult SEQUENCE
			*r = AddResponse(dec)
		}
	}

	return err
}

func (_ AddResponse) isProtocolOp() {}
func (_ AddResponse) isResponseOp() {}
