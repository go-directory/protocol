package request

/*
	scope ::= ENUMERATED {
	    baseObject       (0),
	    singleLevel      (1),
	    wholeSubtree     (2),
	    ...  },

Search Scope constants, per [Search], defined in [§ 4.5.1 of RFC4511].

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

Alias Dereferencing constants, per [Search], defined in [§ 4.5.1 of RFC4511].

[§ 4.5.1 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.5.1
*/
const (
	DerefAliasesNever   Enumerated = iota // 0
	DerefInSearching                      // 1
	DerefFindingBaseObj                   // 2
	DerefAlways                           // 3
)

/*
	Search ::= [APPLICATION 3] SEQUENCE {
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

Search implements [§ 4.5.1 of RFC4511].

[§ 4.5.1 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.5.1
*/
type Search struct {
	BaseObject   LDAPDN
	Scope        Enumerated
	DerefAliases Enumerated
	SizeLimit    Integer
	TimeLimit    Integer
	TypesOnly    Boolean
	Filter       Filter
	Attributes   AttributeSelection
}

func (_ Search) Kind() string   { return `request` }
func (_ Search) Choice() string { return nameSearchChoice }
func (_ Search) Tag() int       { return TagSearch }
func (_ Search) classTag() Tag  { return aTag(classA, true, uint32(TagSearch)) }

func NewSearch(
	base LDAPDN,
	scope, deref, sizelimit, timelimit int,
	typesOnly bool,
	filter []byte,
	attrs ...LDAPString,
) Search {

	var srch Search

	srch.SetBaseObject(base)
	srch.SetScope(Enumerated(scope))
	srch.SetDeref(Enumerated(deref))
	srch.SetTypesOnly(Boolean(typesOnly))
	srch.SetSizeLimit(sizelimit)
	srch.SetTimeLimit(timelimit)
	srch.SetFilter(filter)
	srch.AppendAttribute(attrs...)

	return srch
}

func (r *Search) SetBaseObject(base LDAPDN) { r.BaseObject = base }

func (r *Search) SetScope(scope Enumerated) {
	if ScopeBaseObject <= scope && scope <= ScopeWholeSubtree {
		r.Scope = scope
	}
}

func (r *Search) SetDeref(deref Enumerated) {
	if DerefAliasesNever <= deref && deref <= DerefAlways {
		r.DerefAliases = deref
	}
}

func (r *Search) SetTypesOnly(t Boolean) { r.TypesOnly = t }

func (r *Search) SetSizeLimit(limit int) {
	size, _ := NewInteger(limit)
	if size.Ge(0) && size.Le(UBSizeLimit) {
		r.SizeLimit = size
	}
}

func (r *Search) SetTimeLimit(limit int) {
	thyme, _ := NewInteger(limit)
	if thyme.Ge(0) && thyme.Le(UBTimeLimit) {
		r.TimeLimit = thyme
	}
}

func (r *Search) SetFilter(filter []byte) {
	if filt, err := NewFilter(filter); err == nil {
		r.Filter = filt
	}
}

func (r *Search) SetAllUserAttributes() {
	r.Attributes = AttributeSelection{LDAPString(`*`)}
}

func (r *Search) SetAllOperationalAttributes() {
	r.Attributes = AttributeSelection{LDAPString(`+`)}
}

func (r *Search) SetAllAttributes() {
	r.Attributes = AttributeSelection{
		LDAPString(`+`), LDAPString(`*`)}
}

func (r *Search) SetDefaultFilter() {
	r.Filter = defaultFilter
}

func (r *Search) AppendAttribute(at ...LDAPString) {
	if r.Attributes == nil {
		r.Attributes = make(AttributeSelection, 0)
	}

	for i := 0; i < len(at); i++ {
		r.Attributes = append(r.Attributes, at[i])
	}
}

/*
Encode returns an instance of []byte alongside an error following
an attempt to encode the contents of the receiver instance as
[APPLICATION 3].
*/
func (r Search) Encode() ([]byte, error) {
	var enc []byte
	err := r.checkComponents()
	if err == nil {
		var base []byte
		base, err = r.BaseObject.Encode()
		if err == nil {
			var encDigits, typesOnly []byte
			encDigits, err = r.encodeDigits()
			if err != nil {
				return enc, err
			}
			typesOnly, err = r.TypesOnly.Encode()
			if err != nil {
				return enc, err
			}

			enc = append(enc, base...)
			enc = append(enc, encDigits...)
			enc = append(enc, typesOnly...)

			flt := filterDefaultEncoding
			if r.Filter != nil {
				flt, err = r.Filter.Encode()
			}

			if err == nil {
				enc = append(enc, flt...)
				var sel []byte
				if sel, err = r.Attributes.Encode(); err == nil {
					enc = append(enc, sel...)
					enc, err = wrapTLV(enc, r.classTag()) // [APPLICATION 3]
				}
			}
		}
	}

	return enc, err
}

/*
Decode returns an error following an attempt to decode and write
the input encoding to the receiver instance. The encoding must
not be truncated, and must bear the [APPLICATION 3] tag.
*/
func (r *Search) Decode(enc []byte) error {
	payload, err := unwrapTLV(enc, r.classTag()) // [APPLICATION 3]

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

		// set defaults wherever appropriate
		if err == nil {
			if r.Filter == nil {
				r.SetDefaultFilter()
			}
			if len(r.Attributes) == 0 {
				r.SetAllUserAttributes()
			}
		}
	}

	return err
}

func (r *Search) decodeBase(c *int, payload []byte) (err error) {
	if tag, _ := readTag(payload); tag.Tag != uint32(tOct) {
		return
	}

	var val []byte

	val, err = readEPTLV(payload, c,
		classU, uint32(tOct))

	if err == nil {
		r.BaseObject = LDAPDN(val)
	}

	return
}

func (r *Search) decodeScope(c *int, payload []byte) (err error) {
	p2 := 0
	p := *c
	if tag, _ := readTag(payload[p:]); tag.Tag != uint32(tEnum) {
		return
	}
	_, err = readEPTLV(payload[p:], &p2,
		classU, uint32(tEnum))

	if err == nil {
		p2 += p
		*c = p2
		err = r.Scope.Decode(payload[p:p2])
	}

	return
}

func (r *Search) decodeDeref(c *int, payload []byte) (err error) {
	p2 := 0
	p := *c
	if tag, _ := readTag(payload[p:]); tag.Tag != uint32(tEnum) {
		return
	}

	_, err = readEPTLV(payload[p:], &p2,
		classU, uint32(tEnum))

	if err == nil {
		p2 += p
		*c = p2
		err = r.DerefAliases.Decode(payload[p:p2])
	}

	return
}

func (r *Search) decodeSizeLimit(c *int, payload []byte) (err error) {
	p2 := 0
	p := *c
	if tag, _ := readTag(payload[p:]); tag.Tag != uint32(tInt) {
		return
	}

	_, err = readEPTLV(payload[p:], &p2,
		classU, uint32(tInt))

	if err == nil {
		p2 += p
		*c = p2
		err = r.SizeLimit.Decode(payload[p:p2])
	}

	return
}

func (r *Search) decodeTimeLimit(c *int, payload []byte) (err error) {
	p2 := 0
	p := *c
	if tag, _ := readTag(payload[p:]); tag.Tag != uint32(tInt) {
		return
	}

	_, err = readEPTLV(payload[p:], &p2,
		classU, uint32(tInt))

	if err == nil {
		p2 += p
		*c = p2
		err = r.TimeLimit.Decode(payload[p:p2])
	}

	return
}

func (r *Search) decodeTypesOnly(c *int, payload []byte) (err error) {
	p2 := 0
	p := *c
	if tag, _ := readTag(payload[p:]); tag.Tag != uint32(tBool) {
		return
	}

	_, err = readEPTLV(payload[p:], &p2,
		classU, uint32(tBool))

	if err == nil {
		p2 += p
		*c = p2
		err = r.TypesOnly.Decode(payload[p:p2])
	}

	return
}

func (r *Search) decodeFilter(c *int, payload []byte) (err error) {
	p := *c

	// Unlike previous components of this type, filter
	// can start with any one of ten possible tags, so
	// we can't rely on targeting any specific one.
	tag, _ := readTag(payload[p:])
	if !(0 <= tag.Tag && tag.Tag <= 9) {
		// not a filter ...
		return
	}

        l, n := readLen(payload[p+1:])
        filt := payload[p : 1+p+n+l]

		*c += len(filt)
		r.Filter, err = filterDecode(filt)

	return err
}

func (r *Search) decodeAttributes(c *int, payload []byte) (err error) {
	err = r.Attributes.Decode(payload[*c:])
	return
}

func (r Search) encodeDigits() (enc []byte, err error) {
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
		if err != nil {
			panic("slice: " + itoa(5) + " " + err.Error())
		}
	}

	return
}

func (r Search) checkComponents() (err error) {
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

func (_ Search) IsProtocolOp() {}
func (_ Search) IsRequestOp()  {}

const (
	UBSizeLimit = MaxInt
	UBTimeLimit = MaxInt
)

var (
	errSearchDN     = protocolError("Search: baseObject required")
	errSizeLimitOOB = protocolError("Search: size limit out of bounds; want 0 .. UBSizeLimit")
	errTimeLimitOOB = protocolError("Search: time limit out of bounds; want 0 .. UBTimeLimit")
	errScopeOOB     = protocolError("Search: scope out of bounds; want baseObject(0), singleLevel(1), wholeSubtree(2)")
	errDerefOOB     = protocolError("Search: alias dereferencing out of bounds; want neverDerefAliases(0), derefInSearching(1), derefFindingBaseObj(2), derefAlways(3)")
)
