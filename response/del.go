package response

/*
	DelResponse ::= [APPLICATION 11] LDAPResult

Del implements [§ 4.8 of RFC4511], circumscribing an [LDAPResult].

[§ 4.8 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.8
*/
type Del LDAPResult

func (_ Del) Kind() string   { return `response` }
func (_ Del) Choice() string { return nameDelChoice }
func (_ Del) Tag() int       { return TagDel }
func (_ Del) IsProtocolOp()  {}
func (_ Del) IsResponseOp()  {}
func (_ Del) classTag() Tag  { return aTag(classA, true, uint32(TagDel)) }

/*
Encode returns an instance of []byte alongside an error following
an attempt to encode the contents of the receiver instance as an
[APPLICATION 11] [LDAPResult] SEQUENCE.
*/
func (r Del) Encode() ([]byte, error) {
	var enc []byte
	res, err := LDAPResult(r).Encode() // LDAPResult SEQUENCE
	if err == nil {
		enc, err = wrapTLV(res, r.classTag()) // [APPLICATION 11]
	}

	return enc, err
}

/*
Decode returns an error following an attempt to decode and write
the input encoding to the receiver instance. The encoding must not
be truncated, and must bear the [APPLICATION 11] tag, circumscribing
an [LDAPResult] SEQUENCE.
*/
func (r *Del) Decode(enc []byte) error {
	payload, err := unwrapTLV(enc, r.classTag()) // [APPLICATION 11]
	if err == nil {
		var dec LDAPResult
		if err = dec.Decode(payload); err == nil { // LDAPResult SEQUENCE
			*r = Del(dec)
		}
	}

	return err
}
