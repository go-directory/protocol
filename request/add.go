package request

/*
	AddRequest ::= [APPLICATION 8] SEQUENCE {
	     entry           LDAPDN,
	     attributes      AttributeList }

Add implements [§ 4.7 of RFC4511].

[§ 4.7 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.7
*/
type Add struct {
	Entry      LDAPDN
	Attributes AttributeList
}

func (_ Add) IsProtocolOp()  {}
func (_ Add) IsRequestOp()   {}
func (_ Add) Kind() string   { return `request` }
func (_ Add) Choice() string { return nameAddChoice }
func (_ Add) Tag() int       { return TagAdd }
func (_ Add) classTag() Tag  { return aTag(classA, true, uint32(TagAdd)) }

func (r *Add) Attribute(at AttributeDescription, av ...AttributeValue) {
	idx := r.Attributes.IndexOf(at)
	if idx == -1 {
		idx = len(r.Attributes)
		r.Attributes = append(r.Attributes, Attribute{Type: at})
	}
	r.Attributes[idx].Vals = append(r.Attributes[idx].Vals, av...)

	return
}

func (r Add) Encode() ([]byte, error) {
	var outer []byte
	ldn, err := r.Entry.Encode()
	if err == nil {
		var attrs []byte
		if attrs, err = r.Attributes.Encode(); err == nil {
			outer, err = wrapTLV(append(ldn, attrs...),
				r.classTag()) // [APPLICATION 8]
		}
	}

	return outer, err
}

func (r *Add) Decode(enc []byte) error {
	payload, err := unwrapTLV(enc, r.classTag()) // [APPLICATION 8]

	if err == nil {
		p := 0
		var dnPayload []byte
		dnPayload, err = readEPTLV(payload, &p, classU, uint32(tOct))

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
