package response

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
func (_ SearchResultEntry) IsProtocolOp()  {}
func (_ SearchResultEntry) IsResponseOp()  {}
func (_ SearchResultEntry) Tag() int       { return TagSearchResultEntry }
func (_ SearchResultEntry) classTag() Tag {
	return aTag(classA, true, uint32(TagSearchResultEntry))
}

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
func (_ SearchResultReference) IsProtocolOp()  {}
func (_ SearchResultReference) IsResponseOp()  {}
func (_ SearchResultReference) Tag() int       { return TagSearchResultReference }
func (_ SearchResultReference) classTag() Tag {
	return aTag(classA, true, uint32(TagSearchResultReference))
}

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
func (_ SearchResultDone) IsProtocolOp()  {}
func (_ SearchResultDone) IsResponseOp()  {}
func (_ SearchResultDone) Tag() int       { return TagSearchResultDone }
func (_ SearchResultDone) classTag() Tag  { return aTag(classA, true, uint32(TagSearchResultDone)) }

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
