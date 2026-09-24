package protocol

/*
	scope ::= ENUMERATED {
	    baseObject       (0),
	    singleLevel      (1),
	    wholeSubtree     (2),
	    ...  },

Search Scope constants, per [SearchRequest], defined in [§ 4.5.1 of RFC4511].

[§ 4.5.1 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.5.1
*/
const (
	ScopeBaseObject   Enumerated = iota // 0
	ScopeSingleLevel                    // 1
	ScopeWholeSubtree                   // 2
)

/*
	derefAliases ::= ENUMERATED {
	     neverDerefAliases       (0),
	     derefInSearching        (1),
	     derefFindingBaseObj     (2),
	     derefAlways             (3) },

Alias Dereferencing constants, per [SearchRequest], defined in [§ 4.5.1 of RFC4511].

[§ 4.5.1 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.5.1
*/
const (
	DerefAliasesNever   Enumerated = iota // 0
	DerefInSearching                      // 1
	DerefFindingBaseObj                   // 2
	DerefAlways                           // 3
)

/*
	SearchRequest ::= [APPLICATION 3] SEQUENCE {
	     baseObject      LDAPDN,
	     scope           ENUMERATED {
	          baseObject              (0),
	          singleLevel             (1),
	          wholeSubtree            (2),
	          ...  },
	     derefAliases    ENUMERATED {
	          neverDerefAliases       (0),
	          derefInSearching        (1),
	          derefFindingBaseObj     (2),
	          derefAlways             (3) },
	     sizeLimit       INTEGER (0 ..  maxInt),
	     timeLimit       INTEGER (0 ..  maxInt),
	     typesOnly       BOOLEAN,
	     filter          Filter,
	     attributes      AttributeSelection }

SearchRequest implements [§ 4.5.1 of RFC4511].

[§ 4.5.1 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.5.1
*/
type SearchRequest struct {
	BaseObject   LDAPDN
	Scope        Enumerated
	DerefAliases Enumerated
	SizeLimit    Integer
	TimeLimit    Integer
	TypesOnly    Boolean
	Filter       Filter
	Attributes   AttributeSelection
}

func (_ SearchRequest) Kind() string   { return `request` }
func (_ SearchRequest) Choice() string { return nameSearchRequestChoice }
func (_ SearchRequest) Tag() int       { return TagSearchRequest }

/*
Encode returns an instance of []byte alongside an error following
an attempt to encode the contents of the receiver instance as an
[APPLICATION 3] SEQUENCE.
*/
func (r SearchRequest) Encode() ([]byte, error) {
	var enc []byte
	err := r.checkComponents()
	if err == nil {
		var base []byte
		base, err = r.BaseObject.Encode()
		if err == nil {
			enc = append(enc, base...)

			var encDigits, typesOnly []byte
			encDigits, _ = r.encodeDigits()
			typesOnly, _ = r.TypesOnly.Encode()
			enc = append(enc, encDigits...)
			enc = append(enc, typesOnly...)

			if r.Filter != nil {
				var flt []byte
				if flt, err = r.Filter.Encode(); err == nil {
					enc = append(enc, flt...)
				}
			}

			if err == nil && len(r.Attributes) > 0 {
				var sel []byte
				if sel, err = r.Attributes.Encode(); err == nil {
					enc = append(enc, sel...)
				}
			}

			if err == nil {
				enc, err = wrapTLV(enc,
					uSeqTag(),    // SEQUENCE
					r.classTag()) // [APPLICATION 3]
			}
		}
	}

	return enc, err
}

/*
Decode returns an error following an attempt to decode and write
the input encoding to the receiver instance. The encoding must
not be truncated, and must bear the [APPLICATION 3] SEQUENCE tag.
*/
func (r *SearchRequest) Decode(enc []byte) error {
	payload, err := unwrapTLV(enc,
		r.classTag(), // [APPLICATION 3]
		uSeqTag())    // SEQUENCE

	if err == nil {
		p := 0

		// BaseObject
		for _, err = range []error{
			r.decodeBase(&p, payload),
			r.decodeScope(&p, payload),
			r.decodeDeref(&p, payload),
			r.decodeSizeLimit(&p, payload),
			r.decodeTimeLimit(&p, payload),
			r.decodeTypesOnly(&p, payload),
			r.decodeFilter(&p, payload),
			r.decodeAttributes(&p, payload),
		} {
			if err != nil {
				break
			}
		}
	}

	return err
}

func (r *SearchRequest) decodeBase(c *int, payload []byte) (err error) {
	var val []byte

	val, err = readEPTLV(payload, c,
		classU, uint32(tOct))

	if err == nil {
		r.BaseObject = LDAPDN(val)
	}

	return
}

func (r *SearchRequest) decodeScope(c *int, payload []byte) (err error) {
	p2 := 0
	p := *c
	_, err = readEPTLV(payload[p:], &p2,
		classU, uint32(tEnum))

	if err == nil {
		p2 += p
		*c = p2
		err = r.Scope.Decode(payload[p:p2])
	}

	return
}

func (r *SearchRequest) decodeDeref(c *int, payload []byte) (err error) {
	p2 := 0
	p := *c
	_, err = readEPTLV(payload[p:], &p2,
		classU, uint32(tEnum))

	if err == nil {
		p2 += p
		*c = p2
		err = r.DerefAliases.Decode(payload[p:p2])
	}

	return
}

func (r *SearchRequest) decodeSizeLimit(c *int, payload []byte) (err error) {
	p2 := 0
	p := *c
	_, err = readEPTLV(payload[p:], &p2,
		classU, uint32(tInt))

	if err == nil {
		p2 += p
		*c = p2
		err = r.SizeLimit.Decode(payload[p:p2])
	}

	return
}

func (r *SearchRequest) decodeTimeLimit(c *int, payload []byte) (err error) {
	if tag, _ := readTag(payload); tag.Tag != uint32(tInt) {
		return
	}

	p2 := 0
	p := *c
	_, err = readEPTLV(payload[p:], &p2,
		classU, uint32(tInt))

	if err == nil {
		p2 += p
		*c = p2
		err = r.TimeLimit.Decode(payload[p:p2])
	}

	return
}

func (r *SearchRequest) decodeTypesOnly(c *int, payload []byte) (err error) {
	p2 := 0
	p := *c
	_, err = readEPTLV(payload[p:], &p2,
		classU, uint32(tBool))

	if err == nil {
		p2 += p
		*c = p2
		err = r.TypesOnly.Decode(payload[p:p2])
	}

	return
}

func (r *SearchRequest) decodeFilter(c *int, payload []byte) (err error) {
	p2 := 0
	p := *c

	// Unlike previous components of this type, filter
	// can start with any one of ten possible tags, so
	// we can't rely on targeting any specific one.
	tag, _ := readTag(payload[p:])
	if !(0 <= tag.Tag && tag.Tag <= 9) {
		// not a filter ...
		return
	}

	_, err = readECTLV(payload[p:], &p2,
		classC, tag.Tag)

	if err == nil {
		p2 += p
		*c = p2
		r.Filter, err = FilterDecode(payload[p:p2])
	}

	return
}

func (r *SearchRequest) decodeAttributes(c *int, payload []byte) (err error) {
	p2 := 0
	p := *c

	seqTag := uint32(tSeq) // SEQUENCE *OF*
	tag, _ := readTag(payload[p:])
	if tag.Tag != seqTag {
		// not a SEQUENCE OF LDAPString ...
		return
	}

	_, err = readECTLV(payload[p:], &p2,
		classU, seqTag)

	if err == nil {
		p2 += p
		*c = p2
		err = r.Attributes.Decode(payload[p:p2])
	}

	return
}

func (r SearchRequest) encodeDigits() (enc []byte, err error) {
	enum := []Enumerated{r.Scope, r.DerefAliases}
	ints := []Integer{r.SizeLimit, r.TimeLimit}

	for i := 0; i < len(enum) && err == nil; i++ {
		var e []byte
		if e, err = enum[i].Encode(); err == nil {
			enc = append(enc, e...)
		}
	}

	if err == nil {
		for i := 0; i < len(ints) && err == nil; i++ {
			var e []byte
			if e, err = ints[i].Encode(); err == nil {
				enc = append(enc, e...)
			}
		}
	}

	return
}

func (r SearchRequest) checkComponents() (err error) {
	if len(r.BaseObject) == 0 {
		err = errSearchDN
		return
	}

	sc := int(r.Scope)
	if !(0 <= sc && sc <= 2) {
		err = errScopeOOB
		return
	}

	da := int(r.DerefAliases)
	if !(0 <= da && da <= 3) {
		err = errDerefOOB
		return
	}

	sl := r.SizeLimit
	if !(sl.Ge(0) && sl.Le(UBSizeLimit)) {
		err = errSizeLimitOOB
		return
	}

	tl := r.TimeLimit
	if !(tl.Ge(0) && tl.Le(UBTimeLimit)) {
		err = errTimeLimitOOB
	}

	return
}

func (_ SearchRequest) isProtocolOp() {}
func (_ SearchRequest) isRequestOp()  {}

/*
	SearchResultEntry ::= [APPLICATION 4] SEQUENCE {
	    objectName LDAPDN,
	    attributes PartialAttributeList }

SearchResultEntry implements [§ 4.5.2 of RFC4511].

[§ 4.5.2 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.5.2
*/
type SearchResultEntry struct {
	ObjectName LDAPDN
	Attributes PartialAttributeList
}

func (_ SearchResultEntry) Kind() string   { return `response` }
func (_ SearchResultEntry) Choice() string { return nameSearchResultEntryChoice }
func (_ SearchResultEntry) isProtocolOp()  {}
func (_ SearchResultEntry) isResponseOp()  {}
func (_ SearchResultEntry) Tag() int       { return TagSearchResultEntry }

/*
Encode returns an instance of []byte alongside an error following
an attempt to encode the contents of the receiver instance as an
[APPLICATION 4] SEQUENCE.
*/
func (r SearchResultEntry) Encode() ([]byte, error) {
	var enc []byte
	name, err := r.ObjectName.Encode()
	if err == nil {
		enc = append(enc, name...)
		var attrs []byte
		attrs, err = r.Attributes.Encode()
		if err == nil {
			enc = append(enc, attrs...)
			enc, err = wrapTLV(enc,
				uSeqTag(),    // SEQUENCE
				r.classTag()) // [APPLICATION 4]
		}
	}

	return enc, err
}

/*
Decode returns an error following an attempt to decode and write
the input encoding to the receiver instance. The encoding must
not be truncated, and must bear the [APPLICATION 4] SEQUENCE tag.
*/
func (r *SearchResultEntry) Decode(enc []byte) error {
	payload, err := unwrapTLV(enc,
		r.classTag(), // [APPLICATION 4]
		uSeqTag())    // SEQUENCE

	if err == nil {
		p := 0
		var name []byte
		name, err = readEPTLV(payload, &p,
			classU, uint32(tOct))

		if err == nil {
			r.ObjectName = LDAPDN(name)
			err = r.Attributes.Decode(payload[p:])
		}
	}

	return err
}

/*
	SearchResultReference ::= [APPLICATION 19] SEQUENCE SIZE (1..MAX) OF uri URI

SearchResultReference implements [§ 4.5.2 of RFC4511].

[§ 4.5.2 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.5.2
*/
type SearchResultReference []URI

func (_ SearchResultReference) Kind() string   { return `response` }
func (_ SearchResultReference) Choice() string { return nameSearchResultReferenceChoice }
func (_ SearchResultReference) isProtocolOp()  {}
func (_ SearchResultReference) isResponseOp()  {}
func (_ SearchResultReference) Tag() int       { return TagSearchResultReference }

/*
Encode returns an instance of []byte alongside an error following
an attempt to encode the contents of the receiver instance as an
[APPLICATION 19], circumscribing a SEQUENCE OF [LDAPString] ([URI]).

Note that this method uses the same underlying code as [LDAPResult],
given that [Referral] is a [][URI] like [SearchResultReference].
*/
func (r SearchResultReference) Encode() ([]byte, error) {
	enc, err := Referral(r).Encode() // SEQUENCE OF URI
	if err == nil {
		enc, err = wrapTLV(enc, r.classTag()) // [APPLICATION 19]
	}

	return enc, err
}

/*
Decode returns an error following an attempt to decode and write the
input encoding to the receiver instance. The encoding must not be
truncated, and must bear the [APPLICATION 19] SEQUENCE OF tag.
*/
func (r *SearchResultReference) Decode(enc []byte) error {
	payload, err := unwrapTLV(enc, r.classTag()) // [APPLICATION 19]
	if err == nil {
		// Unwrap SEQUENCE OF for payload, then decode
		// the individual LDAPString (URI) slices.
		var ref Referral
		if err = ref.Decode(payload); err == nil {
			// Cast Referral as plain []URI. We do it
			// this way merely to reduce code bloat.
			*r = []URI(ref)
		}
	}

	return err
}

/*
	SearchResultDone ::= [APPLICATION 5] LDAPResult

SearchResultDone implements [§ 4.5.2 of RFC4511], circumscribing
an [LDAPResult] SEQUENCE.

[§ 4.5.2 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.5.2
*/
type SearchResultDone LDAPResult

func (_ SearchResultDone) Kind() string   { return `response` }
func (_ SearchResultDone) Choice() string { return nameSearchResultDoneChoice }
func (_ SearchResultDone) isProtocolOp()  {}
func (_ SearchResultDone) isResponseOp()  {}
func (_ SearchResultDone) Tag() int       { return TagSearchResultDone }

/*
Encode returns an instance of []byte alongside an error following
an attempt to encode the contents of the receiver instance as an
[APPLICATION 5], circumscribing an [LDAPResult] SEQUENCE.
*/
func (r SearchResultDone) Encode() ([]byte, error) {
	enc, err := LDAPResult(r).Encode() // SEQUENCE
	if err == nil {
		enc, err = wrapTLV(enc, r.classTag()) // [APPLICATION 5]
	}

	return enc, err
}

/*
Decode returns an error following an attempt to decode and write
the input encoding to the receiver instance. The encoding must
not be truncated, and must bear the [APPLICATION 5] SEQUENCE tag.
*/
func (r *SearchResultDone) Decode(enc []byte) error {
	payload, err := unwrapTLV(enc, r.classTag()) // [APPLICATION 5]
	if err == nil {
		var dec LDAPResult
		if err = dec.Decode(payload); err == nil { // SEQUENCE
			*r = SearchResultDone(dec)
		}
	}

	return err
}

var (
	errSearchDN     = protocolError("SearchRequest: baseObject required")
	errSizeLimitOOB = protocolError("SearchRequest: size limit out of bounds; want 0 .. UBSizeLimit")
	errTimeLimitOOB = protocolError("SearchRequest: time limit out of bounds; want 0 .. UBTimeLimit")
	errScopeOOB     = protocolError("SearchRequest: scope out of bounds; want baseObject(0), singleLevel(1), wholeSubtree(2)")
	errDerefOOB     = protocolError("SearchRequest: alias dereferencing out of bounds; want neverDerefAliases(0), derefInSearching(1), derefFindingBaseObj(2), derefAlways(3)")
)
