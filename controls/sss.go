package controls

/*
	SortKey ::= SEQUENCE {
	        attributeType   AttributeDescription,
	        orderingRule    [0] MatchingRuleId OPTIONAL,
	        reverseOrder    [1] BOOLEAN DEFAULT FALSE }

SortKey implements [§ 1.1 of RFC2891], and serves as a "controlValue" slice
component in an instance of [SortKeyList].

[§ 1.1 of RFC2891]: https://datatracker.ietf.org/doc/html/rfc2891#section-1.1
*/
type SortKey struct {
	AttributeType AttributeDescription
	OrderingRule  *MatchingRuleID
	ReverseOrder  Boolean
}

/*
Encode returns an instance of []byte alongside an error following an attempt to
encode the contents of the receiver as a UNIVERSAL SEQUENCE.
*/
func (r SortKey) Encode() ([]byte, error) {
	var enc []byte
	payload, err := r.AttributeType.Encode() // LDAPString
	if err == nil {
		enc = append(enc, payload...)
		if r.OrderingRule != nil {
			payload, err = OctetString((*r.OrderingRule)).Encode() // LDAPString
			if err == nil {
				enc = append(enc, payload...)
			}
		}

		if err == nil {
			payload, _ = r.ReverseOrder.Encode() // BOOLEAN
			enc = append(enc, payload...)

			enc, err = wrapTLV(enc, uSeqTag()) // SEQUENCE
		}
	}

	return enc, err
}

/*
Decode returns an error following an attempt to decode and write the input
encoding to the receiver instance. The encoding must not be truncated, and
must bear the UNIVERSAL SEQUENCE tag (0x30).
*/
func (r *SortKey) Decode(enc []byte) error {
	payload, err := unwrapTLV(enc, uSeqTag()) // SEQUENCE
	if err == nil {
		p := 0
		var val []byte
		oct := uint32(tOct)
		val, err = readEPTLV(payload, &p, classU, oct) // LDAPString
		if err == nil {
			r.AttributeType = val

			tag, _ := readTag(payload[p:])
			if tag.Tag == oct {
				// OrderingRule is present
				val, err = readEPTLV(payload, &p, classU, uint32(tOct)) // LDAPString
				if err == nil {
					ord := MatchingRuleID(val)
					r.OrderingRule = &ord
				}
			}

			if err == nil {
				val, err = readEPTLV(payload, &p, classU, uint32(tBool)) // BOOLEAN
				if err == nil {
					r.ReverseOrder = val[0] == 0xFF
				}
			}
		}
	}

	return err
}

/*
	SortKeyList ::= SEQUENCE OF sortKey SortKey

SortKeyList implements [§ 1.1 of RFC2891], and serves as a "controlValue" component
in an instance of [ServerSideSorting]. Instances of this type contain [SortKey]
slice instances.

[§ 1.1 of RFC2891]: https://datatracker.ietf.org/doc/html/rfc2891#section-1.1
*/
type SortKeyList []SortKey

/*
Encode returns an instance of []byte alongside an error following an attempt to encode
the contents of the receiver as a UNIVERSAL SEQUENCE OF sortKey SortKey.
*/
func (r SortKeyList) Encode() ([]byte, error) {
	var enc []byte
	var err error

	for i := 0; i < len(r) && err == nil; i++ {
		var payload []byte
		payload, err = r[i].Encode()
		if err == nil {
			enc = append(enc, payload...)
		}
	}

	if err == nil {
		enc, err = wrapTLV(enc, uSeqTag()) // SEQUENCE OF
	}

	return enc, err
}

/*
Decode returns an error following an attempt to decode and wrote the contents of the
input encoding to the receiver instance. The encoding must not be truncated and must
bear the UNIVERSAL SEQUENCE OF tag (0x30).
*/
func (r *SortKeyList) Decode(enc []byte) error {
	payload, err := unwrapTLV(enc, uSeqTag()) // SEQUENCE OF
	if err == nil {
		l, p := 0, 0
		for p < len(payload) && err == nil {
			_, err = readECTLV(payload, &p, classU, uint32(tSeq)) // SEQUENCE
			if err == nil {
				val := payload[l:p]
				var csk SortKey
				if err = csk.Decode(val); err == nil {
					l = p
					*r = append(*r, csk)
				}
			}
		}
	}

	return err
}

/*
	ServerSideSorting ::= SEQUENCE {
	        controlType     LDAPOID,
	        criticality     BOOLEAN DEFAULT FALSE,
	        controlValue    SortKeyList }

	SortKeyList ::= SEQUENCE OF sortKey SortKey

	SortKey ::= SEQUENCE {
	        attributeType   AttributeDescription,
	        orderingRule    [0] MatchingRuleId OPTIONAL,
	        reverseOrder    [1] BOOLEAN DEFAULT FALSE }

ServerSideSorting implements [§ 1.1 of RFC2891], and is identified by the controlType
[OIDServerSideSorting].

[§ 1.1 of RFC2891]: https://datatracker.ietf.org/doc/html/rfc2891#section-1.1
*/
type ServerSideSorting struct {
	Criticality  Boolean
	ControlValue SortKeyList
}

/*
Type returns the [LDAPOID] by which this [Control] is recognized.
*/
func (r ServerSideSorting) Type() LDAPOID { return OIDServerSideSorting }

/*
Critical returns a [Boolean] value indictive of the [Control] criticality.
*/
func (r ServerSideSorting) Critical() Boolean { return r.Criticality }

/*
Value returns the BER encoded [SortKeyList] instance encapsulated as a [RawValue].
*/
func (r ServerSideSorting) Value() RawValue {
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
Encode returns an instance of []byte alongside an error following an
attempt to encode the contents of the receiver instance as a UNIVERSAL
SEQUENCE.
*/
func (r ServerSideSorting) Encode() ([]byte, error) {
	var enc []byte
	var err error

	val, _ := OIDServerSideSorting.Encode()
	enc = append(enc, val...)
	val, _ = r.Criticality.Encode()
	enc = append(enc, val...)

	if val, err = r.ControlValue.Encode(); err == nil {
		enc = append(enc, val...)
	}

	if err == nil {
		enc, err = wrapTLV(enc, uSeqTag()) // SEQUENCE
	}

	return enc, err
}

/*
Decode returns an error following an attempt to decode and write the
input encoding to the receiver instance. The encoding must not be
truncated and must bear the UNIVERSAL SEQUENCE tag (0x30).
*/
func (r *ServerSideSorting) Decode(enc []byte) error {
	payload, err := unwrapTLV(enc, uSeqTag()) // SEQUENCE
	if err == nil {
		p := 0
		var val []byte
		val, err = readEPTLV(payload, &p, classU, uint32(tOct)) // LDAPOID
		if err == nil {
			if LDAPOID(val).Equal(OIDServerSideSorting) {
				if err == nil {
					val, err = readEPTLV(payload, &p, classU, uint32(tBool)) // BOOLEAN
					if err == nil {
						r.Criticality = val[0] == 0xFF

						// this controlValue must not be zero
						err = r.ControlValue.Decode(payload[p:])
					}
				}
			} else {
				err = ErrorUnexpectedControlType(OIDServerSideSorting, val)
			}
		}
	}

	return err
}
