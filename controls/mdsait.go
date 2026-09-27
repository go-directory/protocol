package controls

/*
ManageDsaIT implements [§ 3 of RFC3296] and is identified by the
controlType [OIDManageDsaIT].

[§ 3 of RFC3296]: https://datatracker.ietf.org/doc/html/rfc3296#section-3
*/
type ManageDsaIT struct {
	Criticality Boolean
}

/*
Encode returns an instance of []byte alongside an error following an
attempt to encode the contents of the receiver instance as a UNIVERSAL
SEQUENCE.
*/
func (r ManageDsaIT) Encode() ([]byte, error) {
	var enc []byte
	payload, _ := OIDManageDsaIT.Encode() // LDAPOID
	enc = append(enc, payload...)
	payload, _ = r.Criticality.Encode() // BOOLEAN
	enc = append(enc, payload...)

	var err error
	enc, err = wrapTLV(enc, uSeqTag()) // SEQUENCE

	return enc, err
}

/*
Decode returns an error following an attempt to decode and write the
input encoding to the receiver instance. The encoding must not be
truncated and must bear the UNIVERSAL SEQUENCE tag (0x30).
*/
func (r *ManageDsaIT) Decode(enc []byte) error {
	payload, err := unwrapTLV(enc, uSeqTag()) // SEQUENCE
	if err == nil {
		p := 0

		var ctrlType []byte
		ctrlType, err = readEPTLV(payload, &p, classU, uint32(tOct)) // LDAPOID
		if err == nil {
			if LDAPOID(ctrlType).Equal(OIDManageDsaIT) {
				var crit []byte
				crit, err = readEPTLV(payload, &p, classU, uint32(tBool)) // BOOLEAN
				r.Criticality = crit[0] == 0xFF
			} else {
				err = ErrorUnexpectedControlType(OIDManageDsaIT, ctrlType)
			}
		}
	}

	return err
}

/*
Type returns the [LDAPOID] by which this [Control] is recognized.
*/
func (r ManageDsaIT) Type() LDAPOID { return OIDManageDsaIT }

/*
Critical returns a [Boolean] value indictive of the [Control] criticality.
*/
func (r ManageDsaIT) Critical() Boolean { return r.Criticality }

/*
Value returns a zero [RawValue] instance, as this particular [Control] type implementation
does not use the "controlValue" component.
*/
func (r ManageDsaIT) Value() RawValue { return RawValue{} }
