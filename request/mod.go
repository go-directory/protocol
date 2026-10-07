package request

/*
	Modify ::= [APPLICATION 6] SEQUENCE {
		object          LDAPDN,
		changes         SEQUENCE OF change SEQUENCE {
			operation       ENUMERATED {
				add     (0),
				delete  (1),
				replace (2),
				...  },
			modification    PartialAttribute } }

Modify implements [§ 4.6 of RFC4511].

[§ 4.6 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.6
*/
type Modify struct {
	Object  LDAPDN
	Changes []ModifyChange
}

/*
	change ::= SEQUENCE {
		operation       ENUMERATED {
			add     (0),
			delete  (1),
			replace (2),
			...  },
		modification    PartialAttribute }

ModifyChange describes a single modification to the directory. Instances of
this kind are found as slice values within the "Changes" field of a [Modify]
instance.

See [§ 4.6 of RFC4511] for details.

[§ 4.6 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.6
*/
type ModifyChange struct {
	Operation    Enumerated
	Modification PartialAttribute
}

func (_ Modify) IsProtocolOp()  {}
func (_ Modify) IsRequestOp()   {}
func (_ Modify) Kind() string   { return `request` }
func (_ Modify) Choice() string { return nameModifyChoice }
func (_ Modify) Tag() int       { return TagModify }
func (_ Modify) classTag() Tag  { return aTag(classA, true, uint32(TagModify)) }
func (r Modify) DN() LDAPDN     { return r.Object }

/*
Add appends an "add changetype" directive to the receiver using the provided
[AttributeDescription] and [AttributeValue] instances.

In most scenarios, at least one (1) [AttributeValue] is required.
*/
func (r *Modify) Add(at AttributeDescription, av ...AttributeValue) {
	idx := r.IndexOf(at, ModifyChangeOperationAdd)
	if idx == -1 {
		idx = r.allocateChange(at, ModifyChangeOperationAdd)
	}

	if len(av) > 0 {
		r.Changes[idx].Modification.Vals = append(r.Changes[idx].Modification.Vals, av...)
	} else {
		// the request defines a zero-length value, probably
		// of the OCTET STRING syntax.
		r.Changes[idx].Modification.Vals = append(r.Changes[idx].Modification.Vals, AttributeValue(``))
	}
}

/*
Delete appends a "delete changetype" directive to the receiver using the provided
[AttributeDescription] and (optional) [AttributeValue] instances.

Providing no [AttributeValue] instances means that the receiving DSA will delete
*ALL* values assigned to [AttributeDescription] from the entry in question, as
opposed to only specific values.
*/
func (r *Modify) Delete(at AttributeDescription, av ...AttributeValue) {
	idx := r.IndexOf(at, ModifyChangeOperationDelete)
	if idx == -1 {
		idx = r.allocateChange(at, ModifyChangeOperationDelete)
	}

	if len(av) > 0 {
		r.Changes[idx].Modification.Vals = append(r.Changes[idx].Modification.Vals, av...)
	} else {
		// the request defines a zero-length value, probably
		// of the OCTET STRING syntax.
		r.Changes[idx].Modification.Vals = append(r.Changes[idx].Modification.Vals, AttributeValue(``))
	}
}

/*
Replace appends a "replace changetype" directive to the receiver using the provided
[AttributeDescription] and [AttributeValue] instances.

In most scenarios, at least one (1) [AttributeValue] is required.
*/
func (r *Modify) Replace(at AttributeDescription, av ...AttributeValue) {
	idx := r.IndexOf(at, ModifyChangeOperationReplace)
	if idx == -1 {
		idx = r.allocateChange(at, ModifyChangeOperationReplace)
	}

	if len(av) > 0 {
		r.Changes[idx].Modification.Vals = append(r.Changes[idx].Modification.Vals, av...)
	} else {
		// the request defines a zero-length value, probably
		// of the OCTET STRING syntax.
		r.Changes[idx].Modification.Vals = append(r.Changes[idx].Modification.Vals, AttributeValue(``))
	}
}

func (r *Modify) allocateChange(at AttributeDescription, op Enumerated) (idx int) {
	idx = len(r.Changes)
	r.Changes = append(r.Changes, ModifyChange{
		Operation:    op,
		Modification: PartialAttribute{Type: at},
	})
	return
}

/*
Encode returns an instance of []byte alongside an error following
an attempt to encode the contents of the receiver instance as an
[APPLICATION 6].
*/
func (r Modify) Encode() ([]byte, error) {
	var out []byte
	obj, err := r.Object.Encode()
	if err == nil {
		var payload, changes []byte
		payload = append(payload, obj...)

		for i := 0; i < len(r.Changes) && err == nil; i++ {
			var chg []byte
			if chg, err = r.Changes[i].Encode(); err == nil {
				changes = append(changes, chg...)
			}
		}

		if err == nil {
			var seqOf []byte
			if seqOf, err = wrapTLV(changes, uSeqTag()); err == nil {
				payload = append(payload, seqOf...)
				out, err = wrapTLV(payload, r.classTag()) // [APPLICATION 6]
			}
		}
	}

	return out, err
}

/*
Encode returns an instance of []byte alongside an error following
an attempt to encode the contents of the receiver instance as a
SEQUENCE.
*/
func (r ModifyChange) Encode() ([]byte, error) {
	var out []byte
	// Enumerated
	op, err := r.Operation.Encode()
	if err == nil {
		out = append(out, op...)
		var mod []byte
		// PartialAttribute
		mod, err = r.Modification.Encode()
		if err == nil {
			out = append(out, mod...)
			// outer SEQUENCE wrapping
			out, err = wrapTLV(out, uSeqTag())
		}
	}

	return out, err
}

/*
Decode returns an error following an attempt to decode and write
the input encoding to the receiver instance. The encoding must
not be truncated, and must bear the [APPLICATION 6] SEQUENCE tag.
*/
func (r *Modify) Decode(enc []byte) error {
	payload, err := unwrapTLV(enc, r.classTag()) // [APPLICATION 6]

	if err == nil {
		p := 0
		r.Object, err = readEPTLV(payload,
			&p, classU, uint32(tOct))

		if err == nil {
			p2 := 0
			var chgs []byte
			chgs, err = readECTLV(payload[p:], &p2,
				classU, uint32(tSeq))

			p3 := 0
			for p3 < len(chgs) && err == nil {
				var chg []byte
				chg, err = readECTLV(chgs, &p3,
					classU, uint32(tSeq))
				if err == nil {
					var mrc ModifyChange
					if err = mrc.Decode(chg); err == nil {
						r.Changes = append(r.Changes, mrc)
					}
				}
			}
		}
	}

	return err
}

/*
Decode returns an error following an attempt to decode and write
the input encoding to the receiver instance. The encoding must
not be truncated, and must bear the SEQUENCE tag.
*/
func (r *ModifyChange) Decode(enc []byte) error {
	payload, err := unwrapTLV(enc, uSeqTag())
	if err == nil {
		p := 0
		_, err = readEPTLV(payload, &p,
			classU, uint32(tEnum))

		if err == nil {
			if err = r.Operation.Decode(payload[:p]); err == nil {
				if err = r.validOperation(); err == nil {
					var chg []byte
					chg, err = readECTLV(payload, &p,
						classU, uint32(tSeq))

					if err == nil {
						err = r.Modification.Decode(chg)
					}
				}
			}
		}
	}

	return err
}

func (r ModifyChange) validOperation() (err error) {
	if !(0 <= r.Operation && r.Operation <= 2) {
		err = protocolError("Modify change operation: invalid ENUMERATED value; want add(0), delete(1) or replace(2), got ",
			itoa(int(r.Operation)))
	}

	return
}

/*
IndexOf returns the integer index occupied by the [ModifyChange] instance bearing
a [AttributeDescription] and [Enumerated] instance matching the provided input.  If not
found, -1 is returned.

Case-folding is not significant in the matching process.
*/
func (r Modify) IndexOf(at AttributeDescription, op Enumerated) int {
	var idx int = -1
	for i := 0; i < len(r.Changes) && idx == -1; i++ {
		if r.Changes[i].Modification.Type.EqualFold(at) &&
			r.Changes[i].Operation == op {
			idx = i
		}
	}

	return idx
}

/*
Modify Change Operation tags.
*/
const (
	ModifyChangeOperationAdd     Enumerated = iota // 0
	ModifyChangeOperationDelete                    // 1
	ModifyChangeOperationReplace                   // 2
)

var enumeratedModifyChangeOperation = map[Enumerated]string{
	ModifyChangeOperationAdd:     "add",
	ModifyChangeOperationDelete:  "delete",
	ModifyChangeOperationReplace: "replace",
}
