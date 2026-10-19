package response

/*
	AddResponse ::= [APPLICATION 9] LDAPResult

Add implements [§ 4.7 of RFC4511].

[§ 4.7 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.7
*/
type Add LDAPResult

func (_ Add) IsProtocolOp()      {}
func (_ Add) IsResponseOp()      {}
func (_ Add) Kind() string       { return `response` }
func (_ Add) Choice() string     { return nameAddChoice }
func (_ Add) Tag() int           { return TagAdd }
func (_ Add) classTag() Tag      { return aTag(classA, true, uint32(TagAdd)) }
func (r Add) Result() Enumerated { return LDAPResult(r).ResultCode }

func NewAdd(rc Enumerated) Add { return Add{ResultCode: rc} }

func (r Add) Encode() ([]byte, error) {
	enc, err := LDAPResult(r).Encode() // LDAPResult SEQUENCE
	enc, _  = unwrapTLV(enc, uSeqTag())
	if err == nil {
		enc, err = wrapTLV(enc, r.classTag()) // [APPLICATION 9]
	}

	return enc, err
}

/*
Decode returns an error following an attempt to decode and write
the input encoding to the receiver instance. The encoding must
not be truncated, and must bear the [APPLICATION 5] SEQUENCE tag.
*/
func (r *Add) Decode(enc []byte) error {
        payload, err := unwrapTLV(enc, r.classTag()) // [APPLICATION 9]
        if err == nil {
                payload, err = wrapTLV(payload, uSeqTag()) // SEQUENCE
                var dec LDAPResult
                if err = dec.Decode(payload); err == nil {
                        *r = Add(dec)
                }
        }

        return err
}
