package protocol

/*
	Control ::= SEQUENCE {
		controlType  LDAPOID,
		criticality  BOOLEAN DEFAULT FALSE,
		controlValue OCTET STRING OPTIONAL }

Control implements [§ 4.1.11 of RFC4511], and serves as the slice type
in an instance of [Controls].

[§ 4.1.11 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.1.11
*/
type Control struct {
	ControlType  LDAPOID
	Criticality  Boolean     `asn1:"default:false"`
	ControlValue OctetString `asn1:"optional"`
}

/*
NewControl returns an instance of [Control] alongside an error following
an attempt to read the input controlType (typ) and criticality (crit)
values and marshal them.

An optional controlValue may be supplied.
*/
func NewControl[T Text](typ T, crit Boolean, value ...T) (Control, error) {
	// NewControl NOTE: I am testing generics
	// over string/[]byte assertion

	var ctrl Control
	loid, err := NewLDAPOID([]byte(typ))
	if err == nil {
		ctrl.ControlType = loid
		ctrl.Criticality = crit
		if len(value) > 0 {
			ctrl.ControlValue = []byte(value[0])
		}
	}

	return ctrl, err
}

/*
Encode returns an instance of []byte alongside an error
following an attempt to encode the receiver instance
as an ASN.1 SEQUENCE.
*/
func (r Control) Encode() ([]byte, error) {
	var t, c, v, payload []byte
	var err error

	if t, err = r.ControlType.Encode(); err == nil {
		payload = append(payload, t...)
		if c, err = r.Criticality.Encode(); err == nil {
			payload = append(payload, c...)
			if len(r.ControlValue) > 0 {
				if v, err = r.ControlValue.Encode(); err == nil {
					payload = append(payload, v...)
				}
			}
		}
	}

	var out []byte
	if err == nil {
		out, err = wrapTLV(payload, uSeqTag()) // SEQUENCE
	}

	return out, err
}

/*
Decode returns an error following an attempt to decode
and write the input encoding to the receiver instance.
The encoding must not be truncated and must bear the
ASN.1 UNIVERSAL SEQUENCE tag (0x30).
*/
func (r *Control) Decode(enc []byte) error {
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

/*
	SEQUENCE OF control Control

Controls implements [§ 4.1.11 of RFC4511], containing slices of
individual [Control] instances.

[§ 4.1.11 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.1.11
*/
type Controls []Control

/*
Encode returns an instance of []byte alongside an error
following an attempt to encode the receiver instance as
an ASN.1 SEQUENCE OF.
*/
func (r Controls) Encode() ([]byte, error) {
	var err error
	var out []byte
	for i := 0; i < len(r) && err == nil; i++ {
		var enc []byte
		if enc, err = r[i].Encode(); err == nil {
			out = append(out, enc...)
		}
	}

	if len(out) == 0 {
		err = protocolError("Controls: failed to encode one or more Control SEQUENCE members")
	}

	if err == nil {
		out, err = wrapTLV(out, uSeqTag()) // SEQUENCE OF
	}

	return out, err
}

/*
Decode returns an error following an attempt to decode
and write the input encoding to the receiver instance.
The encoding must not be truncated and must bear the
SEQUENCE OF tag.
*/
func (r *Controls) Decode(enc []byte) error {
	// unwrap SEQUENCE OF Control
	payload, err := unwrapTLV(enc, uSeqTag()) // SEQUENCE OF
	if err == nil {
		p := 0
		// Iterate individual Control elements
		// for the length of the payload.
		for p < len(payload) && err == nil {
			var cb []byte
			cb, err = readECTLV(payload, &p, classU, uint32(tSeq))

			if err == nil {
				// Decode individual Control
				var ctrl Control
				if err = ctrl.Decode(cb); err == nil {
					*r = append(*r, ctrl)
				}
			}
		}
	}

	return err
}
