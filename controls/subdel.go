package controls

/*
SubtreeDelete implements the Subtree Delete Control, as defined in
[draft-armijo-ldap-treedelete] and is identified by the controlType
[OIDSubtreeDelete].

[draft-armijo-ldap-treedelete]: https://datatracker.ietf.org/doc/html/draft-armijo-ldap-treedelete-02
*/
type SubtreeDelete struct{}

/*
Type returns the [LDAPOID] by which this [Control] is recognized.
*/
func (_ SubtreeDelete) Type() LDAPOID { return OIDSubtreeDelete }

/*
Critical returns a fixed [Boolean] value of true, indicative of the [Control] criticality.
*/
func (_ SubtreeDelete) Critical() Boolean { return Boolean(true) }

/*
Value returns a zero [RawValue] instance, as this particular [Control] type implementation
does not use the "controlValue" component.
*/
func (_ SubtreeDelete) Value() RawValue { return RawValue{} }

/*
Encode returns an instance of []byte alongside an error following an attempt
to encode the receiver instance as a UNIVERSAL SEQUENCE.
*/
func (r SubtreeDelete) Encode() ([]byte, error) {
	var enc []byte
	payload, err := OIDSubtreeDelete.Encode() // LDAPOID
	if err == nil {
		enc = append(enc, payload...)
		payload, _ = r.Critical().Encode() // BOOLEAN
		enc = append(enc, payload...)
		enc, err = wrapTLV(enc, uSeqTag()) // SEQUENCE
	}

	return enc, err
}

/*
Decode returns an error following an attempt to decode and write the input
encoding to the receiver instance.  The encoding must not be truncated and
must bear the UNIVERSAL SEQUENCE tag (0x30).
*/
func (r *SubtreeDelete) Decode(enc []byte) error {
	payload, err := unwrapTLV(enc, uSeqTag()) // SEQUENCE
	if err == nil {
		p := 0

		var ctrlType []byte
		ctrlType, err = readEPTLV(payload, &p, classU, uint32(tOct))
		if err == nil {
			if LDAPOID(ctrlType).Equal(OIDSubtreeDelete) {
				_, err = readEPTLV(payload, &p, classU, uint32(tBool))
				// we really don't need to process the criticality bool,
				// only verify it decoded normally. We hard code it to
				// true anyways.
			} else {
				err = ErrorUnexpectedControlType(OIDSubtreeDelete, ctrlType)
			}
		}
	}

	return err
}
