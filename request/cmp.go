package request

/*
	Compare ::= [APPLICATION 14] SEQUENCE {
	     entry           LDAPDN,
	     ava             AttributeValueAssertion }

Compare implements [§ 4.10 of RFC4511].

[§ 4.10 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.10
*/
type Compare struct {
	Entry LDAPDN
	AVA   AttributeValueAssertion
}

func (_ Compare) Kind() string   { return `request` }
func (_ Compare) Choice() string { return nameCompareChoice }
func (_ Compare) Tag() int       { return TagCompare }
func (_ Compare) IsProtocolOp()  {}
func (_ Compare) IsRequestOp()   {}
func (_ Compare) classTag() Tag  { return aTag(classA, true, uint32(TagCompare)) }

/*
Encode returns an instance of []byte alongside an error following
an attempt to encode the contents of the receiver instance as
[APPLICATION 14].
*/
func (r Compare) Encode() ([]byte, error) {
	var outer []byte
	ldn, err := r.Entry.Encode()
	if err == nil {
		var attrs []byte
		if attrs, err = r.AVA.Encode(); err == nil {
			outer, err = wrapTLV(append(ldn, attrs...),
				r.classTag()) // [APPLICATION 14]
		}
	}

	return outer, err
}

/*
Decode returns an error following an attempt to decode and write
the input encoding to the receiver instance. The encoding must
not be truncated, and must bear the [APPLICATION 14] tag.
*/
func (r *Compare) Decode(enc []byte) error {
	payload, err := unwrapTLV(enc, r.classTag()) // [APPLICATION 14]

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
