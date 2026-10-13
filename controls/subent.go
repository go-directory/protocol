package controls

/*
Encode returns an instance of []byte alongside an error following an
attempt to encode the contents of the receiver instance as a UNIVERSAL
SEQUENCE.
*/
func (r Subentries) Encode() ([]byte, error) {
	var enc []byte
	var err error

	var bite byte = 0x00
	if r {
		bite = 0xFF
	}

	val, _ := OIDSubentries.Encode()
	enc = append(enc, val...)
	enc = append(enc, []byte{tBool, 0x01, bite}...)
	enc, err = wrapTLV(enc, uSeqTag()) // SEQUENCE

	return enc, err
}

/*
Decode returns an error following an attempt to decode and write the
input encoding to the receiver instance. The encoding must not be
truncated and must bear the UNIVERSAL SEQUENCE tag (0x30).
*/
func (r *Subentries) Decode(enc []byte) error {
	payload, err := unwrapTLV(enc, uSeqTag()) // SEQUENCE
	if err == nil {
		p := 0
		var ctrlType []byte
		ctrlType, err = readEPTLV(payload, &p, classU, uint32(tOct))
		if err == nil {
			if LDAPOID(ctrlType).Equal(OIDSubentries) {
				if err == nil {
					var critPayload []byte
					critPayload, err = readEPTLV(payload, &p, classU, uint32(tBool))
					if err == nil {
						*r = Subentries(critPayload[0] == 0xFF)
					}
				}
			} else {
				err = ErrorUnexpectedControlType(OIDSubentries, ctrlType)
			}
		}
	}

	return err
}

/*
Type returns the [LDAPOID] by which this [Control] is recognized.
*/
func (r Subentries) Type() LDAPOID { return OIDSubentries }

/*
Critical returns a [Boolean] value indictive of the [Control] criticality.
*/
func (r Subentries) Critical() Boolean { return Boolean(false) }

/*
Value returns the BER encoded [PagedResultsSearchValue] instance.  Note that
unlike other [Control] implementation types, calling this method will trigger a call
to the [PagedResultsSearchValue.Encode] method in order to return the proper
value per the [Control] signature ([OctetString]).
*/
func (r Subentries) Value() RawValue {
	var bite byte = 0x00
	if r {
		bite = 0xFF
	}
	return RawValue{
		Tag:       Tag{classU, true, uint32(tBool)},
		Bytes:     []byte{bite},
		FullBytes: []byte{tBool, 0x01, bite},
	}
}
