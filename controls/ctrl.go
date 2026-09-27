package controls

/*
Control implements [§ 4.1.11 of RFC4511] and serves as the slice type
in an instance of [Controls].

[§ 4.1.11 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.1.11
*/
type Control interface {
	Type() LDAPOID
	Critical() Boolean
	Value() RawValue
	Encode() ([]byte, error)
}

/*
	SEQUENCE OF control Control

Controls implements [§ 4.1.11 of RFC4511], containing slices of individual [Control]
implementation type instances.

[§ 4.1.11 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.1.11
*/
type Controls []Control

/*
Append appends the input variadic [Control] argument(s) to the receiver instance.

Note that "controlType" uniqueness checking is not performed. Instead, the receiver
of an [LDAPMessage] which contains any number of [Control] instances should process
the contents of [Controls] using a "seen table", e.g.:

	seen := make(map[string]struct{})
	for i := 0; i < len(myCtrls); i++ {
	    ctrl := myCtrls[i]                // the Control slice
	    ctrlType := ctrl.Type().String()  // LDAPOID string representation
	    if _, saw := seen[ctrlType]; saw {
	      continue
	    }
	    seen[ctrlType] = struct{}{} // record that we've now seen this Control
	    // ... continue processing ctrl as a unique instance
	}
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
			cb, err = readECTLV(payload, &p, classU, uint32(tSeq)) // SEQUENCE
			if err == nil {
				p2 := 0
				// peek at the ControlType OID
				ct, _ := readEPTLV(payload[p:], &p2, classU, uint32(tOct)) // LDAPOID
				var c Control
				if funk, found := decoders[string(ct)]; found {
					c, err = funk(cb)
				} else {
					var std Standard
					err = std.Decode(cb)
					c = std
				}
				if err == nil {
					*r = append(*r, c)
				}
			}
		}
	}

	return err
}
