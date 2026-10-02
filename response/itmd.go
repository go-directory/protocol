package response

/*
	IntermediateResponse ::= [APPLICATION 25] SEQUENCE {
	     responseName     [0] LDAPOID OPTIONAL,
	     responseValue    [1] OCTET STRING OPTIONAL }

Intermediate implements [§ 4.13 of RFC4511].

[§ 4.13 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.13
*/
type Intermediate struct {
	ResponseName  *LDAPOID
	ResponseValue *OctetString
}

func (_ Intermediate) Kind() string   { return `response` }
func (_ Intermediate) Choice() string { return nameIntermediateChoice }
func (_ Intermediate) Tag() int       { return TagIntermediate }
func (_ Intermediate) IsProtocolOp()  {}
func (_ Intermediate) IsResponseOp()  {}
func (_ Intermediate) classTag() Tag {
	return aTag(classA, true, uint32(TagIntermediate))
}
func (r Intermediate) Result() Enumerated { return 0 }

/*
Encode returns an instance of []byte alongside an error following
an attempt to encode the contents of the receiver instance as
[APPLICATION 25].
*/
func (r Intermediate) Encode() ([]byte, error) {
	var enc []byte
	var err error
	if r.ResponseName != nil {
		var cmpnt []byte
		cmpnt, err = r.ResponseName.Encode()
		if err == nil {
			cmpnt, err = wrapTLV(cmpnt,
				aTag(classC, false,
					uint32(TagIntermediateName)))
			if err == nil {
				enc = append(enc, cmpnt...)
			}
		}
	}

	if r.ResponseValue != nil && err == nil {
		var cmpnt []byte
		cmpnt, err = r.ResponseValue.Encode()
		if err == nil {
			cmpnt, err = wrapTLV(cmpnt,
				aTag(classC, false,
					uint32(TagIntermediateValue)))
			if err == nil {
				enc = append(enc, cmpnt...)
			}
		}
	}

	if err == nil {
		enc, err = wrapTLV(enc,	r.classTag()) // [APPLICATION 23]
	}

	return enc, err
}

/*
Decode returns an error following an attempt to decode and write the
input encoding to the receiver instance
*/
func (r *Intermediate) Decode(enc []byte) error {
	payload, err := unwrapTLV(enc, r.classTag()) // [APPLICATION 23]

	ct := 0
	if len(payload) > 0 && err == nil {
		p := 0
		for p < len(payload) && ct < 2 && err == nil {
			var val []byte
			val, err = readEPTLV(payload,
				&p, classC, uint32(ct))

			if err == nil {
				if ct == TagIntermediateName {
					var loid LDAPOID
					err = loid.Decode(val)
					r.ResponseName = &loid
				} else if ct == TagIntermediateValue {
					var rval OctetString
					err = rval.Decode(val)
					r.ResponseValue = &rval
				}
				ct++
			}
		}
	}

	return err
}

/*
Intermediate Response tags.
*/
const (
	TagIntermediateName  = 0
	TagIntermediateValue = 1
)
