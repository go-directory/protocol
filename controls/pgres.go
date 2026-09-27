package controls

/*
	pagedResultsControl ::= SEQUENCE {
	        controlType     1.2.840.113556.1.4.319,
	        criticality     BOOLEAN DEFAULT FALSE,
	        controlValue    searchControlValue }

PagedResults implements [§ 2 of RFC2696] and is identified by the
controlType [OIDPagedResults]. Note that because the controlType is
fixed per the specification, the "ControlType" field is omitted from this
implementation. The encoding, however, must remain faithful to the above
ASN.1 definition.

[§ 2 of RFC2696]: https://datatracker.ietf.org/doc/html/rfc2696#section-2
*/
type PagedResults struct {
	Criticality  Boolean
	ControlValue PagedResultsSearchValue
}

/*
Encode returns an instance of []byte alongside an error following an
attempt to encode the contents of the receiver instance as a UNIVERSAL
SEQUENCE.
*/
func (r PagedResults) Encode() ([]byte, error) {
	var enc []byte
	var err error

	val, _ := OIDPagedResults.Encode()
	enc = append(enc, val...)
	val, _ = r.Criticality.Encode()
	enc = append(enc, val...)

	if val, err = r.ControlValue.Encode(); err == nil {
		enc = append(enc, val...)
		enc, err = wrapTLV(enc, uSeqTag()) // SEQUENCE
	}

	return enc, err
}

/*
Decode returns an error following an attempt to decode and write the
input encoding to the receiver instance. The encoding must not be
truncated and must bear the UNIVERSAL SEQUENCE tag (0x30).
*/
func (r *PagedResults) Decode(enc []byte) error {
	payload, err := unwrapTLV(enc, uSeqTag()) // SEQUENCE
	if err == nil {
		p := 0
		var ctrlType []byte
		ctrlType, err = readEPTLV(payload, &p, classU, uint32(tOct))
		if err == nil {
			if LDAPOID(ctrlType).Equal(OIDPagedResults) {
				if err == nil {
					var critPayload []byte
					critPayload, err = readEPTLV(payload, &p, classU, uint32(tBool))
					if err == nil {
						r.Criticality = critPayload[0] == 0xFF

						// this controlValue must not be zero
						err = r.ControlValue.Decode(payload[p:])
					}
				}
			} else {
				err = ErrorUnexpectedControlType(OIDPagedResults, ctrlType)
			}
		}
	}

	return err
}

/*
Type returns the [LDAPOID] by which this [Control] is recognized.
*/
func (r PagedResults) Type() LDAPOID { return OIDPagedResults }

/*
Critical returns a [Boolean] value indictive of the [Control] criticality.
*/
func (r PagedResults) Critical() Boolean { return r.Criticality }

/*
Value returns the BER encoded [PagedResultsSearchValue] instance.  Note that
unlike other [Control] implementation types, calling this method will trigger a call
to the [PagedResultsSearchValue.Encode] method in order to return the proper
value per the [Control] signature ([OctetString]).
*/
func (r PagedResults) Value() RawValue {
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
	SearchControlValue ::= SEQUENCE {
	        size   INTEGER (0..maxInt),
	                -- requested page size from client
	                -- result set size estimate from server
	        cookie OCTET STRING }

PagedResultsSearchValue implements [§ 2 of RFC2696], and serves as the
"controlValue" component in an instance of [PagedResults].

[§ 2 of RFC2696]: https://datatracker.ietf.org/doc/html/rfc2696#section-2
*/
type PagedResultsSearchValue struct {
	Size   Integer
	Cookie OctetString
}

/*
Encode returns an instance of []byte alongside an error following an attempt
to encode the receiver instance as a UNIVERSAL SEQUENCE.
*/
func (r PagedResultsSearchValue) Encode() ([]byte, error) {
	var enc []byte
	payload, err := r.Size.Encode()
	if err == nil {
		enc = append(enc, payload...)
		payload, err = r.Cookie.Encode()
		if err == nil {
			enc = append(enc, payload...)
			enc, err = wrapTLV(enc, uSeqTag())
		}
	}

	return enc, err
}

/*
Decode returns an error following an attempt to decode and write the input
encoding to the receiver instance.  The encoding must not be truncated and
must bear the UNIVERSAL SEQUENCE tag (0x30).
*/
func (r *PagedResultsSearchValue) Decode(enc []byte) error {
	payload, err := unwrapTLV(enc, uSeqTag())
	if err == nil {
		p := 0
		_, err = readEPTLV(payload, &p, classU, uint32(tInt))
		if err == nil {
			val := payload[:p]
			if err = r.Size.Decode(val); err == nil {
				r.Size, _ = NewInteger(r.Size.Native())
				payload = payload[p:]
				p = 0
				_, err = readEPTLV(payload, &p, classU, uint32(tOct))
				if err == nil {
					val = payload[:p]
					err = r.Cookie.Decode(val)
				}
			}
		}
	}

	return err
}
