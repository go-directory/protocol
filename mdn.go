package protocol

import (
	"github.com/go-directory/encoding/asn1"
)

/*
	ModifyDNRequest ::= [APPLICATION 12] SEQUENCE {
		entry           LDAPDN,
		newrdn          RelativeLDAPDN,
		deleteoldrdn    BOOLEAN,
		newSuperior     [0] LDAPDN OPTIONAL }

ModifyDNRequest implements [§ 4.9 of RFC4511].

[§ 4.9 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.9
*/
type ModifyDNRequest struct {
	Entry        LDAPDN
	NewRDN       RelativeLDAPDN
	DeleteOldRDN Boolean
	NewSuperior  *LDAPDN
}

func (_ ModifyDNRequest) Tag() int { return TagModifyDNRequest }
func (_ ModifyDNRequest) classTag() asn1.Tag {
	return aTag(asn1.ClassApplication, true, uint32(TagModifyDNRequest))
}
func (_ ModifyDNRequest) isProtocolOp() {}
func (_ ModifyDNRequest) isRequestOp()  {}

/*
Encode returns an instance of []byte alongside an error following
an attempt to encode the contents of the receiver instance as an
[APPLICATION 12] SEQUENCE.
*/
func (r ModifyDNRequest) Encode() ([]byte, error) {
	var enc []byte
	var err error

	encoders := []func() ([]byte, error){
		r.Entry.Encode,
		r.NewRDN.Encode,
		r.DeleteOldRDN.Encode,
		// OPTIONAL NewSuperior not included
	}

	for i := 0; i < len(encoders) && err == nil; i++ {
		var payload []byte
		if payload, err = encoders[i](); err == nil {
			enc = append(enc, payload...)
		}
	}

	if err == nil && r.NewSuperior != nil {
		// OPTIONAL NewSuperior
		var payload []byte
		if payload, err = r.NewSuperior.Encode(); err == nil {
			enc = append(enc, payload...)
		}
	}

	if err == nil {
		enc, err = asn1.WrapTLV(enc,
			uSeqTag(),    // SEQUENCE
			r.classTag()) // [APPLICATION 12]
	}

	return enc, err
}

/*
Decode returns an error following an attempt to decode and write the
input encoding to the receiver instance. The encoding must not be
truncated, and must bear the [APPLICATION 12] SEQUENCE tag.
*/
func (r *ModifyDNRequest) Decode(enc []byte) error {
	payload, err := asn1.UnwrapTLV(enc,
		r.classTag(), // [APPLICATION 12]
		uSeqTag())    // SEQUENCE

	if err == nil {
		p := 0

		decoders := []func([]byte) error{
			r.Entry.Decode,
			r.NewRDN.Decode,
			r.DeleteOldRDN.Decode,
			// OPTIONAL NewSuperior not included
		}

		dtags := []byte{
			asn1.TagOctetString,
			asn1.TagOctetString,
			asn1.TagBoolean,
		}

		var last int
		for i := 0; i < len(decoders) && err == nil; i++ {
			_, err = asn1.ReadExpectedPrimitiveTLV(payload, &p,
				asn1.ClassUniversal, uint32(dtags[i]))
			if err == nil {
				err = decoders[i](payload[last:p])
			}
			last = p
		}

		if err == nil && p < len(payload) {
			// OPTIONAL NewSuperior
			_, err = asn1.ReadExpectedPrimitiveTLV(payload, &p,
				asn1.ClassUniversal, uint32(asn1.TagOctetString))
			if err == nil {
				var ldn LDAPDN
				err = ldn.Decode(payload[last:p])
				r.NewSuperior = &ldn
			}
		}
	}

	return err
}

/*
	ModifyDNResponse ::= [APPLICATION 13] LDAPResult

ModifyDNResponse implements [§ 4.9 of RFC4511], circumscribing an [LDAPResult].

[§ 4.9 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.9
*/
type ModifyDNResponse LDAPResult

func (_ ModifyDNResponse) Tag() int { return TagModifyDNResponse }
func (_ ModifyDNResponse) classTag() asn1.Tag {
	return aTag(asn1.ClassApplication, true, uint32(TagModifyDNResponse))
}
func (_ ModifyDNResponse) isProtocolOp() {}
func (_ ModifyDNResponse) isResponseOp() {}

/*
Encode returns an instance of []byte alongside an error following
an attempt to encode the contents of the receiver instance as an
[APPLICATION 13].
*/
func (r ModifyDNResponse) Encode() ([]byte, error) {
	var enc []byte
	res, err := LDAPResult(r).Encode() // LDAPResult SEQUENCE
	if err == nil {
		enc, err = asn1.WrapTLV(res, r.classTag()) // [APPLICATION 13]
	}

	return enc, err
}

/*
Decode returns an error following an attempt to decode and write the
input encoding to the receiver instance. The encoding must not be
truncated, and must bear the [APPLICATION 13] tag.
*/
func (r *ModifyDNResponse) Decode(enc []byte) error {
	payload, err := asn1.UnwrapTLV(enc, r.classTag()) // [APPLICATION 13]
	if err == nil {
		var dec LDAPResult
		if err = dec.Decode(payload); err == nil { // LDAPResult SEQUENCE
			*r = ModifyDNResponse(dec)
		}
	}

	return err
}
