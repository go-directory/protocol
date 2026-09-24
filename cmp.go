package protocol

/*
	CompareRequest ::= [APPLICATION 14] SEQUENCE {
	     entry           LDAPDN,
	     ava             AttributeValueAssertion }

CompareRequest implements [§ 4.10 of RFC4511].

[§ 4.10 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.10
*/
type CompareRequest struct {
	Entry LDAPDN
	AVA   AttributeValueAssertion
}

func (_ CompareRequest) Kind() string   { return `request` }
func (_ CompareRequest) Choice() string { return nameCompareRequestChoice }
func (_ CompareRequest) Tag() int       { return TagCompareRequest }
func (_ CompareRequest) isProtocolOp()  {}
func (_ CompareRequest) isRequestOp()   {}

/*
Encode returns an instance of []byte alongside an error following
an attempt to encode the contents of the receiver instance as an
[APPLICATION 14] SEQUENCE.
*/
func (r CompareRequest) Encode() ([]byte, error) {
	var outer []byte
	ldn, err := r.Entry.Encode()
	if err == nil {
		var attrs []byte
		if attrs, err = r.AVA.Encode(); err == nil {
			outer, err = wrapTLV(append(ldn, attrs...),
				uSeqTag(),    // SEQUENCE
				r.classTag()) // [APPLICATION 14]
		}
	}

	return outer, err
}

/*
Decode returns an error following an attempt to decode and write
the input encoding to the receiver instance. The encoding must
not be truncated, and must bear the [APPLICATION 14] SEQUENCE tag.
*/
func (r *CompareRequest) Decode(enc []byte) error {
	payload, err := unwrapTLV(enc,
		r.classTag(), // [APPLICATION 14]
		uSeqTag())    // SEQUENCE

	if err == nil {
		p := 0
		var dnPayload []byte
		dnPayload, err = readEPTLV(payload, &p, classU, uint32(tOct))

		if err == nil {
			r.Entry = dnPayload

			var ava AttributeValueAssertion
			if err = ava.Decode(payload[p:]); err == nil {
				r.AVA = ava
			}
		}
	}

	return err

}

/*
	CompareResponse ::= [APPLICATION 15] LDAPResult

CompareResponse implements [§ 4.10 of RFC4511].

[§ 4.10 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.10
*/
type CompareResponse LDAPResult

func (_ CompareResponse) Kind() string   { return `response` }
func (_ CompareResponse) Choice() string { return nameCompareResponseChoice }
func (_ CompareResponse) Tag() int       { return TagCompareResponse }
func (_ CompareResponse) isProtocolOp()  {}
func (_ CompareResponse) isResponseOp()  {}

/*
Encode returns an instance of []byte alongside an error following
an attempt to encode the contents of the receiver instance as an
[APPLICATION 15], circumscribing an [LDAPResult] SEQUENCE.
*/
func (r CompareResponse) Encode() ([]byte, error) {
	var enc []byte
	res, err := LDAPResult(r).Encode() // LDAPResult SEQUENCE
	if err == nil {
		enc, err = wrapTLV(res, r.classTag()) // [APPLICATION 15]
	}

	return enc, err
}

/*
Decode returns an error following an attempt to decode and write the
input encoding to the receiver instance. The encoding must not be
truncated, and must bear the [APPLICATION 15] tag, circumscribing
an [LDAPResult] SEQUENCE.
*/
func (r *CompareResponse) Decode(enc []byte) error {
	payload, err := unwrapTLV(enc, r.classTag()) // [APPLICATION 15]
	if err == nil {
		var dec LDAPResult
		if err = dec.Decode(payload); err == nil { // LDAPResult SEQUENCE
			*r = CompareResponse(dec)
		}
	}

	return err
}
