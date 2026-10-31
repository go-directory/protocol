package controls

/*
	Control ::= SEQUENCE {
		controlType             LDAPOID,
		criticality             BOOLEAN DEFAULT FALSE,
		controlValue            OCTET STRING OPTIONAL }

Control implements [§ 4.1.11 of RFC4511] and serves as the slice type
in an instance of [Controls].

[§ 4.1.11 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.1.11
*/
type Control interface {
	Type() LDAPOID
	Critical() Boolean
	Value() RawValue
	Encode() ([]byte, error)
	String() string
}

/*
	SEQUENCE OF control Control

Controls implements [§ 4.1.11 of RFC4511], containing slices of individual [Control]
implementation type instances.

[§ 4.1.11 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.1.11
*/
type Controls []Control

func (r Controls) Get(typ LDAPOID) (Control, bool) {
	var (
		ctrl  Control
		found bool
	)

	idx := r.IndexOf(typ)
	if found = idx != -1; found {
		ctrl = r[idx]
	}

	return ctrl, found
}

func (r Controls) IndexOf(typ LDAPOID) int {
	var idx int = -1
	for i := 0; i < len(r) && idx == -1; i++ {
		if r[i].Type().Equal(typ) {
			idx = i
		}
	}

	return idx
}

/*
Append appends the input variadic [Control] argument(s) to the receiver instance.

Note that "controlType" uniqueness checking is not performed.
*/
func (r *Controls) Append(ctrl ...Control) { *r = append(*r, ctrl...) }

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
		err = protocolError("Controls: failed to encode one or more control members")
	}

	//if err == nil {
	//	out, err = wrapTLV(out, uSeqTag()) // SEQUENCE OF
	//}

	return out, err
}

/*
Decode returns an error following an attempt to decode
and write the input encoding to the receiver instance.
The encoding must not be truncated and must bear the
SEQUENCE OF tag.
*/
func (r *Controls) Decode(enc []byte) error {

	var err error
	p := 0
	L := len(enc)
	for p < L {
		var payload []byte
		// Each control is its own SEQUENCE. Contrary to what
		// it *appears* to convey in RFC 4511, there is no "outer"
		// SEQUENCE OF envelope. Instead, its just a series of one
		// or more back-to-back CONTROL SEQUENCE (not "OF") payloads.
		//
		// The first step in every iteration is to unwrap each of
		// the individual SEQUENCEs, meaning that each loop iteration
		// is a single Control payload.
		payload, err = readECTLV(enc, &p, classU, uint32(tSeq), false) // SEQUENCE
		if err == nil {
			var (
				oct []byte
				p2  int
				c   Control
			)

			// Peek at LDAPOID (OCTET STRING). Use tmp p2
			// because we don't want to actually advance
			// the real cursor yet. We need to peek at the
			// OID to determine (1) that this is even a
			// valid Control and (2) that it has an OID we
			// may be able to use to identify the Control.
			oct, err = readEPTLV(payload, &p2, classU, uint32(tOct))
			if err == nil {
				if funk, found := decoders[string(oct)]; found {
					// We know this OID, it probably originates
					// from a standard and we know it requires
					// special handling. Call its "special func"
					// here.
					c, err = funk(payload)
				} else {
					// Either this OID is not known to us, or
					// its merely a control OID and nothing else.
					// use the standard control type here.
					var std Standard
					err = std.Decode(payload)
					c = std
				}

				if err == nil && c != nil {
					// Whatever control this is, it seemed to
					// decode properly. Append it to receiver.
					*r = append(*r, c)
				}
			}
		}
	}

	return err
}
