package request

import (
	"github.com/go-directory/syntax"
)

/*
	Del ::= [APPLICATION 10] LDAPDN

Del implements [§ 4.8 of RFC4511].

[§ 4.8 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.8
*/
type Del syntax.LDAPDN

func (_ Del) Kind() string   { return `request` }
func (_ Del) Choice() string { return nameDelChoice }
func (_ Del) Tag() int       { return TagDel }
func (_ Del) IsProtocolOp()  {}
func (_ Del) IsRequestOp()   {}
func (_ Del) classTag() Tag  { return aTag(classA, false, uint32(TagDel)) }

/*
Encode returns an instance of []byte alongside an error following
an attempt to encode the contents of the receiver instance as an
[APPLICATION 10] [LDAPDN].
*/
func (r Del) Encode() ([]byte, error) {
	return wrapTLV(OctetString(r), r.classTag()) // [APPLICATION 10]
}

/*
Decode returns an error following an attempt to decode and write
the input encoding to the receiver instance. The encoding must not
be truncated, and must bear the [APPLICATION 10] tag.
*/
func (r *Del) Decode(enc []byte) error {
	dec, err := unwrapTLV(enc, r.classTag()) // [APPLICATION 10]
	if err == nil {
		*r = Del(dec)
	}

	return err
}
