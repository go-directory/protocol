package response

/*
	CompareResponse ::= [APPLICATION 15] LDAPResult

Compare implements [§ 4.10 of RFC4511].

[§ 4.10 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.10
*/
type Compare LDAPResult

func (_ Compare) Kind() string   { return `response` }
func (_ Compare) Choice() string { return nameCompareChoice }
func (_ Compare) Tag() int       { return TagCompare }
func (_ Compare) IsProtocolOp()  {}
func (_ Compare) IsResponseOp()  {}
func (_ Compare) classTag() Tag  { return aTag(classA, true, uint32(TagCompare)) }
func (r Compare) Result() Enumerated { return LDAPResult(r).ResultCode }

/*
Encode returns an instance of []byte alongside an error following
an attempt to encode the contents of the receiver instance as an
[APPLICATION 15], circumscribing an [LDAPResult].
*/
func (r Compare) Encode() ([]byte, error) {
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
an [LDAPResult].
*/
func (r *Compare) Decode(enc []byte) error {
	payload, err := unwrapTLV(enc, r.classTag()) // [APPLICATION 15]
	if err == nil {
		var dec LDAPResult
		if err = dec.Decode(payload); err == nil { // LDAPResult SEQUENCE
			*r = Compare(dec)
		}
	}

	return err
}
