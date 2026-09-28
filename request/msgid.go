package request

/*
	MessageID ::= INTEGER (0 ..  maxInt)

MessageID implements [§ 4.1.1 of RFC4511], and serves the "messageID"
component of the [LDAPMessage] SEQUENCE.

Note that instances of this type are constrained to the unsigned portion
of int32:

	(0 ..  maxInt)
	maxInt INTEGER ::= 2147483647 -- (2^^31 - 1) --

[§ 4.1.1 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.1.1
*/
type MessageID int32

/*
Upper bounds (UB) definitions.
*/
const (
	UBMessageID = MaxInt // 0 .. 2147483647
)

/*
Encode returns an instance of []byte alongside an error following an attempt to
encode the contents of the receiver instance as an ASN.1 INTEGER.
*/
func (r MessageID) Encode() ([]byte, error) {
	if int32(r) < 0 {
		return nil, errMsgIDOOB
	}
	enc := encInt[int32](int32(r))
	return enc, nil
}

/*
Decode returns an error following an attempt to decode and write the
input encoding to the receiver instance. The encoding must not be
truncated and must bear the ASN.1 INTEGER tag (0x02).
*/
func (r *MessageID) Decode(enc []byte) error {
	dec, err := decInt[int32](enc)
	if err == nil {
		if !(0 <= dec && dec <= UBMessageID) {
			return errMsgIDOOB
		}
		*r = MessageID(int32(dec))
	}

	return err
}

var (
	errMsgIDOOB = constraintViolation("MessageID: ", "out of bounds; must be 0 .. 2147483647")
)
