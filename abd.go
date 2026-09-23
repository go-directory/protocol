package protocol

import (
	"github.com/go-directory/encoding/asn1"
)

/*
	AbandonRequest ::= [APPLICATION 16] MessageID

Abandon request implements [§ 4.11 of RFC4511], circumscribing a [MessageID].

Note that there is no response counterpart definition for this type.

[§ 4.11 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.11
*/
type AbandonRequest MessageID

func (_ AbandonRequest) Tag() int      { return TagAbandonRequest }
func (_ AbandonRequest) isProtocolOp() {}
func (_ AbandonRequest) isRequestOp()  {}

/*
Encode returns an instance of []byte alongside an error following
an attempt to encode the contents of the receiver instance as an
[APPLICATION 16] wrapped [MessageID].
*/
func (r AbandonRequest) Encode() ([]byte, error) {
	enc, err := MessageID(r).Encode()
	if err == nil {
		enc, err = asn1.WrapTLV(enc,
			aTag(asn1.ClassApplication,
				false, uint32(r.Tag())))
	}

	return enc, err
}

/*
Decode returns an error following an attempt to decode and write
the input encoding to the receiver instance. The encoding must not
be truncated and must bear a tag of [APPLICATION 16].
*/
func (r *AbandonRequest) Decode(enc []byte) error {
	var err error
	enc, err = asn1.UnwrapTLV(enc,
		aTag(asn1.ClassApplication,
			false, uint32(r.Tag())))

	if err == nil {
		var dec MessageID
		if err = dec.Decode(enc); err == nil {
			*r = AbandonRequest(dec)
		}
	}

	return err
}
