package request

/*
	Abandon ::= [APPLICATION 16] MessageID

Abandon request implements [§ 4.11 of RFC4511], circumscribing a [MessageID].

Note that there is no response counterpart definition for this type.

[§ 4.11 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.11
*/
type Abandon MessageID

func (_ Abandon) Kind() string   { return `request` }
func (_ Abandon) Choice() string { return nameAbandonChoice }
func (_ Abandon) Tag() int       { return TagAbandon }
func (_ Abandon) IsProtocolOp()  {}
func (_ Abandon) IsRequestOp()   {}
func (_ Abandon) classTag() Tag  { return aTag(classA, false, uint32(TagAbandon)) }

/*
Encode returns an instance of []byte alongside an error following
an attempt to encode the contents of the receiver instance as an
[APPLICATION 16] wrapped [MessageID].
*/
func (r Abandon) Encode() ([]byte, error) {
	enc, err := MessageID(r).Encode()
	if err == nil {
		enc, err = wrapTLV(enc, r.classTag())
	}

	return enc, err
}

/*
Decode returns an error following an attempt to decode and write
the input encoding to the receiver instance. The encoding must not
be truncated and must bear a tag of [APPLICATION 16].
*/
func (r *Abandon) Decode(enc []byte) error {
	var err error
	enc, err = unwrapTLV(enc, r.classTag())
	if err == nil {
		var dec MessageID
		if err = dec.Decode(enc); err == nil {
			*r = Abandon(dec)
		}
	}

	return err
}
