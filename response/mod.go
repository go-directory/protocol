package response

/*
	ModifyResponse ::= [APPLICATION 7] LDAPResult

Modify implements [§ 4.6 of RFC4511], circumscribing an [LDAPResult].

[§ 4.6 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.6
*/
type Modify LDAPResult

func (_ Modify) IsProtocolOp()  {}
func (_ Modify) IsResponseOp()  {}
func (_ Modify) Kind() string   { return `response` }
func (_ Modify) Choice() string { return nameModifyChoice }
func (_ Modify) Tag() int       { return TagModify }
func (_ Modify) classTag() Tag  { return aTag(classA, true, uint32(TagModify)) }
func (r Modify) Result() Enumerated { return LDAPResult(r).ResultCode }

/*
Encode returns an instance of []byte alongside an error following
an attempt to encode the contents of the receiver instance as an
[APPLICATION 7].
*/
func (r Modify) Encode() ([]byte, error) {
	var enc []byte
	res, err := LDAPResult(r).Encode()
	if err == nil {
		enc, err = wrapTLV(res, r.classTag())
	}

	return enc, err
}

/*
Decode returns an error following an attempt to decode and write the
input encoding to the receiver instance. The encoding must not be
truncated, and must bear the [APPLICATION 7] tag.
*/
func (r *Modify) Decode(enc []byte) error {
	payload, err := unwrapTLV(enc, r.classTag())
	if err == nil {
		var dec LDAPResult
		if err = dec.Decode(payload); err == nil {
			*r = Modify(dec)
		}
	}

	return err
}
