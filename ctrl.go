package protocol

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
	isControl()
}

/*
	Control ::= SEQUENCE {
		controlType  LDAPOID,
		criticality  BOOLEAN DEFAULT FALSE,
		controlValue OCTET STRING OPTIONAL }

ControlStandard implements the Control SEQUENCE, per [§ 4.1.11 of RFC4511]. Instances of
this type serve as a fallback measure for handling controls for which there is not a
dedicated type.

[§ 4.1.11 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.1.11
*/
type ControlStandard struct {
	ControlType  LDAPOID
	Criticality  Boolean     `asn1:"default:false"`
	ControlValue OctetString `asn1:"optional"`
}

/*
Type returns the [LDAPOID] by which this [Control] is recognized.
*/
func (r ControlStandard) Type() LDAPOID { return r.ControlType }

/*
Critical returns a [Boolean] value indictive of the [Control] criticality.
*/
func (r ControlStandard) Critical() Boolean { return r.Criticality }

/*
Value returns the underlying "controlValue" component as an instance of [RawValue].
*/
func (r ControlStandard) Value() RawValue {
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

func (_ ControlStandard) isControl() {}

/*
Encode returns an instance of []byte alongside an error following an attempt
to encode the receiver instance as a UNIVERSAL SEQUENCE.
*/
func (r ControlStandard) Encode() ([]byte, error) {
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
func (r *ControlStandard) Decode(enc []byte) error {
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
individual [Control] implementation type instances.

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
			cb, err = readECTLV(payload, &p, classU, uint32(tSeq))

			if err == nil {
				// Decode individual Control into a ControlStandard
				// instance at first. If we recognize the contrl oid
				// and have a type for it, marshal it into that instead.
				// Else, preserve ControlStandard as-is.
				var ctrl ControlStandard
				if err = ctrl.Decode(cb); err == nil {
					// TODO - lookup table w/ closures?
					if ctrl.ControlType.Equal(OIDControlTypeManageDsaIT) {
						*r = append(*r, ControlManageDsaIT{Criticality: ctrl.Criticality})
					} else if ctrl.ControlType.Equal(OIDControlTypeServerSideSorting) {
						sss := ControlServerSideSorting{
							Criticality: ctrl.Critical(),
						}
						err = sss.ControlValue.Decode(ctrl.Value().FullBytes)
						*r = append(*r, sss)
					} else if ctrl.ControlType.Equal(OIDControlTypePaging) {
						paged := ControlPagedResults{
							Criticality: ctrl.Critical(),
						}
						err = paged.ControlValue.Decode(ctrl.Value().FullBytes)
						*r = append(*r, paged)
					} else if ctrl.ControlType.Equal(OIDControlTypeSubtreeDelete) {
						*r = append(*r, ControlSubtreeDelete{})
					} else {
						*r = append(*r, ctrl)
					}
				}
			}
		}
	}

	return err
}

/*
ControlManageDsaIT implements [§ 3 of RFC3296] and is identified by the
controlType [OIDControlTypeManageDsaIT].

[§ 3 of RFC3296]: https://datatracker.ietf.org/doc/html/rfc3296#section-3
*/
type ControlManageDsaIT struct {
	Criticality Boolean
}

/*
Encode returns an instance of []byte alongside an error following an
attempt to encode the contents of the receiver instance as a UNIVERSAL
SEQUENCE.
*/
func (r ControlManageDsaIT) Encode() ([]byte, error) {
	var enc []byte
	payload, _ := OIDControlTypeManageDsaIT.Encode() // LDAPOID
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
func (r *ControlManageDsaIT) Decode(enc []byte) error {
	payload, err := unwrapTLV(enc, uSeqTag()) // SEQUENCE
	if err == nil {
		p := 0

		var ctrlType []byte
		ctrlType, err = readEPTLV(payload, &p, classU, uint32(tOct)) // LDAPOID
		if err == nil {
			if LDAPOID(ctrlType).Equal(OIDControlTypeManageDsaIT) {
				var crit []byte
				crit, err = readEPTLV(payload, &p, classU, uint32(tBool)) // BOOLEAN
				r.Criticality = crit[0] == 0xFF
			} else {
				err = errUnexpectedControlType(OIDControlTypeManageDsaIT, ctrlType)
			}
		}
	}

	return err
}

/*
Type returns the [LDAPOID] by which this [Control] is recognized.
*/
func (r ControlManageDsaIT) Type() LDAPOID { return OIDControlTypeManageDsaIT }

/*
Critical returns a [Boolean] value indictive of the [Control] criticality.
*/
func (r ControlManageDsaIT) Critical() Boolean { return r.Criticality }

/*
Value returns a zero [RawValue] instance, as this particular [Control] type implementation
does not use the "controlValue" component.
*/
func (r ControlManageDsaIT) Value() RawValue { return RawValue{} }
func (_ ControlManageDsaIT) isControl()      {}

/*
	pagedResultsControl ::= SEQUENCE {
		controlType     1.2.840.113556.1.4.319,
		criticality     BOOLEAN DEFAULT FALSE,
		controlValue    searchControlValue }

ControlPagedResults implements [§ 2 of RFC2696] and is identified by the
controlType [OIDControlTypePaging]. Note that because the controlType is
fixed per the specification, the "ControlType" field is omitted from this
implementation. The encoding, however, must remain faithful to the above
ASN.1 definition.

[§ 2 of RFC2696]: https://datatracker.ietf.org/doc/html/rfc2696#section-2
*/
type ControlPagedResults struct {
	Criticality  Boolean
	ControlValue ControlPagedResultsSearchValue
}

/*
Encode returns an instance of []byte alongside an error following an
attempt to encode the contents of the receiver instance as a UNIVERSAL
SEQUENCE.
*/
func (r ControlPagedResults) Encode() ([]byte, error) {
	var enc []byte
	var err error

	val, _ := OIDControlTypePaging.Encode()
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
func (r *ControlPagedResults) Decode(enc []byte) error {
	payload, err := unwrapTLV(enc, uSeqTag()) // SEQUENCE
	if err == nil {
		p := 0
		var ctrlType []byte
		ctrlType, err = readEPTLV(payload, &p, classU, uint32(tOct))
		if err == nil {
			if LDAPOID(ctrlType).Equal(OIDControlTypePaging) {
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
				err = errUnexpectedControlType(OIDControlTypePaging, ctrlType)
			}
		}
	}

	return err
}

/*
Type returns the [LDAPOID] by which this [Control] is recognized.
*/
func (r ControlPagedResults) Type() LDAPOID { return OIDControlTypePaging }

/*
Critical returns a [Boolean] value indictive of the [Control] criticality.
*/
func (r ControlPagedResults) Critical() Boolean { return r.Criticality }

/*
Value returns the BER encoded [ControlPagedResultsSearchValue] instance.  Note that
unlike other [Control] implementation types, calling this method will trigger a call
to the [ControlPagedResultsSearchValue.Encode] method in order to return the proper
value per the [Control] signature ([OctetString]).
*/
func (r ControlPagedResults) Value() RawValue {
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

func (_ ControlPagedResults) isControl() {}

/*
	SearchControlValue ::= SEQUENCE {
		size   INTEGER (0..maxInt),
			-- requested page size from client
			-- result set size estimate from server
		cookie OCTET STRING }

ControlPagedResultsSearchValue implements [§ 2 of RFC2696], and serves as the
"controlValue" component in an instance of [ControlPagedResults].

[§ 2 of RFC2696]: https://datatracker.ietf.org/doc/html/rfc2696#section-2
*/
type ControlPagedResultsSearchValue struct {
	Size   Integer
	Cookie OctetString
}

/*
Encode returns an instance of []byte alongside an error following an attempt
to encode the receiver instance as a UNIVERSAL SEQUENCE.
*/
func (r ControlPagedResultsSearchValue) Encode() ([]byte, error) {
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
func (r *ControlPagedResultsSearchValue) Decode(enc []byte) error {
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

/*
ControlSubtreeDelete implements the Subtree Delete Control, as defined in
[draft-armijo-ldap-treedelete] and is identified by the controlType
[OIDControlTypeSubtreeDelete].

[draft-armijo-ldap-treedelete]: https://datatracker.ietf.org/doc/html/draft-armijo-ldap-treedelete-02
*/
type ControlSubtreeDelete struct{}

/*
Type returns the [LDAPOID] by which this [Control] is recognized.
*/
func (_ ControlSubtreeDelete) Type() LDAPOID { return OIDControlTypeSubtreeDelete }

/*
Critical returns a fixed [Boolean] value of true, indicative of the [Control] criticality.
*/
func (_ ControlSubtreeDelete) Critical() Boolean { return Boolean(true) }

/*
Value returns a zero [RawValue] instance, as this particular [Control] type implementation
does not use the "controlValue" component.
*/
func (_ ControlSubtreeDelete) Value() RawValue { return RawValue{} }
func (_ ControlSubtreeDelete) isControl()      {}

/*
Encode returns an instance of []byte alongside an error following an attempt
to encode the receiver instance as a UNIVERSAL SEQUENCE.
*/
func (r ControlSubtreeDelete) Encode() ([]byte, error) {
	var enc []byte
	payload, err := OIDControlTypeSubtreeDelete.Encode() // LDAPOID
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
func (r *ControlSubtreeDelete) Decode(enc []byte) error {
	payload, err := unwrapTLV(enc, uSeqTag()) // SEQUENCE
	if err == nil {
		p := 0

		var ctrlType []byte
		ctrlType, err = readEPTLV(payload, &p, classU, uint32(tOct))
		if err == nil {
			if LDAPOID(ctrlType).Equal(OIDControlTypeSubtreeDelete) {
				_, err = readEPTLV(payload, &p, classU, uint32(tBool))
				// we really don't need to process the criticality bool,
				// only verify it decoded normally. We hard code it to
				// true anyways.
			} else {
				err = errUnexpectedControlType(OIDControlTypeSubtreeDelete, ctrlType)
			}
		}
	}

	return err
}

/*
	SortKey ::= SEQUENCE {
		attributeType   AttributeDescription,
		orderingRule    [0] MatchingRuleId OPTIONAL,
		reverseOrder    [1] BOOLEAN DEFAULT FALSE }

ControlSortKey implements [§ 1.1 of RFC2891], and serves as a "controlValue" slice
component in an instance of [ControlSortKeyList].

[§ 1.1 of RFC2891]: https://datatracker.ietf.org/doc/html/rfc2891#section-1.1
*/
type ControlSortKey struct {
	AttributeType AttributeDescription
	OrderingRule  *MatchingRuleID
	ReverseOrder  Boolean
}

/*
Encode returns an instance of []byte alongside an error following an attempt to
encode the contents of the receiver as a UNIVERSAL SEQUENCE.
*/
func (r ControlSortKey) Encode() ([]byte, error) {
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
func (r *ControlSortKey) Decode(enc []byte) error {
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

ControlSortKeyList implements [§ 1.1 of RFC2891], and serves as a "controlValue" component
in an instance of [ControlServerSideSorting]. Instances of this type contain [ControlSortKey]
slice instances.

[§ 1.1 of RFC2891]: https://datatracker.ietf.org/doc/html/rfc2891#section-1.1
*/
type ControlSortKeyList []ControlSortKey

/*
Encode returns an instance of []byte alongside an error following an attempt to encode
the contents of the receiver as a UNIVERSAL SEQUENCE OF sortKey SortKey.
*/
func (r ControlSortKeyList) Encode() ([]byte, error) {
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
func (r *ControlSortKeyList) Decode(enc []byte) error {
	payload, err := unwrapTLV(enc, uSeqTag()) // SEQUENCE OF
	if err == nil {
		l, p := 0, 0
		for p < len(payload) && err == nil {
			_, err = readECTLV(payload, &p, classU, uint32(tSeq)) // SEQUENCE
			if err == nil {
				val := payload[l:p]
				var csk ControlSortKey
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

ControlServerSideSorting implements [§ 1.1 of RFC2891], and is identified by the controlType
[OIDControlTypeServerSideSorting].

[§ 1.1 of RFC2891]: https://datatracker.ietf.org/doc/html/rfc2891#section-1.1
*/
type ControlServerSideSorting struct {
	Criticality  Boolean
	ControlValue ControlSortKeyList
}

/*
Type returns the [LDAPOID] by which this [Control] is recognized.
*/
func (r ControlServerSideSorting) Type() LDAPOID { return OIDControlTypeServerSideSorting }

/*
Critical returns a [Boolean] value indictive of the [Control] criticality.
*/
func (r ControlServerSideSorting) Critical() Boolean { return r.Criticality }

/*
Value returns the BER encoded [ControlSortKeyList] instance encapsulated as a [RawValue].
*/
func (r ControlServerSideSorting) Value() RawValue {
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

func (_ ControlServerSideSorting) isControl() {}

/*
Encode returns an instance of []byte alongside an error following an
attempt to encode the contents of the receiver instance as a UNIVERSAL
SEQUENCE.
*/
func (r ControlServerSideSorting) Encode() ([]byte, error) {
	var enc []byte
	var err error

	val, _ := OIDControlTypeServerSideSorting.Encode()
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
func (r *ControlServerSideSorting) Decode(enc []byte) error {
	payload, err := unwrapTLV(enc, uSeqTag()) // SEQUENCE
	if err == nil {
		p := 0
		var val []byte
		val, err = readEPTLV(payload, &p, classU, uint32(tOct)) // LDAPOID
		if err == nil {
			if LDAPOID(val).Equal(OIDControlTypeServerSideSorting) {
				if err == nil {
					val, err = readEPTLV(payload, &p, classU, uint32(tBool)) // BOOLEAN
					if err == nil {
						r.Criticality = val[0] == 0xFF

						// this controlValue must not be zero
						err = r.ControlValue.Decode(payload[p:])
					}
				}
			} else {
				err = errUnexpectedControlType(OIDControlTypeServerSideSorting, val)
			}
		}
	}

	return err
}

/*
Control OIDs associated with [Control] definitions supported by this package.
*/
var (
	OIDControlTypePaging                  = LDAPOID("1.2.840.113556.1.4.319")  // RFC2696
	OIDControlTypeManageDsaIT             = LDAPOID("2.16.840.1.113730.3.4.2") // RFC3296
	OIDControlTypeWhoAmI                  = LDAPOID("1.3.6.1.4.1.4203.1.11.3") // RFC4532
	OIDControlTypeSubtreeDelete           = LDAPOID("1.2.840.113556.1.4.805")  // draft-armijo-ldap-treedelete
	OIDControlTypeServerSideSorting       = LDAPOID("1.2.840.113556.1.4.473")  // RFC2891
	OIDControlTypeServerSideSortingResult = LDAPOID("1.2.840.113556.1.4.474")  // RFC2891
)

/*
var (
        // ControlTypeBeheraPasswordPolicy - https://tools.ietf.org/html/draft-behera-ldap-password-policy-10
        OIDControlTypeBeheraPasswordPolicy = "1.3.6.1.4.1.42.2.27.8.5.1"
        // ControlTypeVChuPasswordMustChange - https://tools.ietf.org/html/draft-vchu-ldap-pwd-policy-00
        OIDControlTypeVChuPasswordMustChange = "2.16.840.1.113730.3.4.4"
        // ControlTypeVChuPasswordWarning - https://tools.ietf.org/html/draft-vchu-ldap-pwd-policy-00
        OIDControlTypeVChuPasswordWarning = "2.16.840.1.113730.3.4.5"
)
*/

func errUnexpectedControlType(want, got LDAPOID) error {
	return protocolError("Control: type OID unexpected; want ",
		want.String(), ", got ", got.String())
}
