package controls

/*
	Control ::= SEQUENCE {
	        controlType  LDAPOID,
	        criticality  BOOLEAN DEFAULT FALSE,
	        controlValue OCTET STRING OPTIONAL }

Standard implements the Control SEQUENCE, per [§ 4.1.11 of RFC4511]. Instances of
this type serve as a fallback measure for handling controls for which there is not a
dedicated type.

[§ 4.1.11 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.1.11
*/
type Standard struct {
	ControlType  LDAPOID
	Criticality  Boolean     `asn1:"default:false"`
	ControlValue OctetString `asn1:"optional"`
}

/*
Type returns the [LDAPOID] by which this [Control] is recognized.
*/
func (r Standard) Type() LDAPOID { return r.ControlType }

/*
Critical returns a [Boolean] value indictive of the [Control] criticality.
*/
func (r Standard) Critical() Boolean { return r.Criticality }

/*
Value returns the underlying "controlValue" component as an instance of [RawValue].
*/
func (r Standard) Value() RawValue {
	enc, _ := r.ControlValue.Encode()
	tag, _ := readTag(enc)
	l, n := readLen(enc[1:])
	oenc := enc[1+n : 1+n+l]
	return RawValue{
		Tag:       tag,
		Bytes:     oenc,
		FullBytes: enc,
	}
}

/*
Encode returns an instance of []byte alongside an error following an attempt
to encode the receiver instance as a UNIVERSAL SEQUENCE.
*/
func (r Standard) Encode() ([]byte, error) {
	var enc []byte
	payload, err := r.ControlType.Encode()
	if err == nil {
		enc = append(enc, payload...)
		payload, _ = r.Criticality.Encode()
		enc = append(enc, payload...)
		if len(r.ControlValue) > 0 {
			if payload, err = r.ControlValue.Encode(); err == nil {
				enc = append(enc, payload...)
			}
		}

		if err == nil {
			enc, err = wrapTLV(enc, uSeqTag()) // SEQUENCE
		}
	}

	return enc, err
}

/*
Decode returns an error following an attempt to decode and write the input
encoding to the receiver instance.  The encoding must not be truncated and
must bear the UNIVERSAL SEQUENCE tag (0x30).
*/
func (r *Standard) Decode(enc []byte) error {
	payload, err := unwrapTLV(enc, uSeqTag()) // SEQUENCE
	if err == nil {
		p := 0
		r.ControlType, err = readEPTLV(payload, &p, classU, uint32(tOct))

		if err == nil {
			var critPayload []byte
			critPayload, err = readEPTLV(payload, &p, classU, uint32(tBool))
			if err == nil {
				r.Criticality = critPayload[0] == 0xFF

				if p < len(payload) {
					// OPTIONAL control value detected
					r.ControlValue, err = readEPTLV(payload,
						&p, classU, uint32(tOct))
				}
			}
		}
	}

	return err
}
