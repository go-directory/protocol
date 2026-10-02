package response

/*
	ModifyDNResponse ::= [APPLICATION 13] LDAPResult

ModifyDN implements [§ 4.9 of RFC4511], circumscribing an [LDAPResult].

[§ 4.9 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.9
*/
type ModifyDN LDAPResult

func (_ ModifyDN) Kind() string   { return `response` }
func (_ ModifyDN) Choice() string { return nameModifyDNChoice }
func (_ ModifyDN) Tag() int       { return TagModifyDN }
func (_ ModifyDN) IsProtocolOp()  {}
func (_ ModifyDN) IsResponseOp()  {}
func (_ ModifyDN) classTag() Tag  { return aTag(classA, true, uint32(TagModifyDN)) }
func (r ModifyDN) Result() Enumerated { return LDAPResult(r).ResultCode }

/*
Encode returns an instance of []byte alongside an error following
an attempt to encode the contents of the receiver instance as an
[APPLICATION 13].
*/
func (r ModifyDN) Encode() ([]byte, error) {
	var enc []byte
	res, err := LDAPResult(r).Encode() // LDAPResult SEQUENCE
	if err == nil {
		enc, err = wrapTLV(res, r.classTag()) // [APPLICATION 13]
	}

	return enc, err
}

/*
Decode returns an error following an attempt to decode and write the
input encoding to the receiver instance. The encoding must not be
truncated, and must bear the [APPLICATION 13] tag.
*/
func (r *ModifyDN) Decode(enc []byte) error {
	payload, err := unwrapTLV(enc, r.classTag()) // [APPLICATION 13]
	if err == nil {
		var dec LDAPResult
		if err = dec.Decode(payload); err == nil { // LDAPResult SEQUENCE
			*r = ModifyDN(dec)
		}
	}

	return err
}
