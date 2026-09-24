package protocol

/*
	ModifyRequest ::= [APPLICATION 6] SEQUENCE {
		object          LDAPDN,
		changes         SEQUENCE OF change SEQUENCE {
			operation       ENUMERATED {
				add     (0),
				delete  (1),
				replace (2),
				...  },
		modification    PartialAttribute } }

ModifyRequest implements [§ 4.6 of RFC4511].

[§ 4.6 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.6
*/
type ModifyRequest struct {
	Object  LDAPDN
	Changes []ModifyRequestChange
}

/*
	change ::= SEQUENCE {
		operation       ENUMERATED {
			add     (0),
			delete  (1),
			replace (2),
			...  },
		modification    PartialAttribute }

ModifyRequestChange describes a single modification to the directory.
Instances of this kind are found as slice values within the "Changes"
field of a [ModifyRequest] instance.

See [§ 4.6 of RFC4511] for details.

[§ 4.6 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.6
*/
type ModifyRequestChange struct {
	Operation    Enumerated
	Modification PartialAttribute
}

func (_ ModifyRequest) isProtocolOp()  {}
func (_ ModifyRequest) isRequestOp()   {}
func (_ ModifyRequest) Kind() string   { return `request` }
func (_ ModifyRequest) Choice() string { return nameModifyRequestChoice }
func (_ ModifyRequest) Tag() int       { return TagModifyRequest }

/*
Encode returns an instance of []byte alongside an error following
an attempt to encode the contents of the receiver instance as an
[APPLICATION 6] SEQUENCE.
*/
func (r ModifyRequest) Encode() ([]byte, error) {
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
func (r ModifyRequestChange) Encode() ([]byte, error) {
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
func (r *ModifyRequest) Decode(enc []byte) error {
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
					var mrc ModifyRequestChange
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
func (r *ModifyRequestChange) Decode(enc []byte) error {
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

func (r ModifyRequestChange) validOperation() (err error) {
	if !(0 <= r.Operation && r.Operation <= 2) {
		err = protocolError("ModifyRequestChange.Operation: invalid ENUMERATED value; want add(0), delete(1) or replace(2), got ",
			itoa(int(r.Operation)))
	}

	return
}

/*
	ModifyResponse ::= [APPLICATION 7] LDAPResult

ModifyResponse implements [§ 4.6 of RFC4511], circumscribing an [LDAPResult].

[§ 4.6 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.6
*/
type ModifyResponse LDAPResult

func (_ ModifyResponse) isProtocolOp()  {}
func (_ ModifyResponse) isResponseOp()  {}
func (_ ModifyResponse) Kind() string   { return `response` }
func (_ ModifyResponse) Choice() string { return nameModifyResponseChoice }
func (_ ModifyResponse) Tag() int       { return TagModifyResponse }

/*
Encode returns an instance of []byte alongside an error following
an attempt to encode the contents of the receiver instance as an
[APPLICATION 7].
*/
func (r ModifyResponse) Encode() ([]byte, error) {
	var enc []byte
	res, err := LDAPResult(r).Encode()
	if err == nil {
		enc, err = wrapTLV(res, r.classTag())
	}

	return enc, err
}

/*
Decode returns an error following an attempt to decode and write the
input encoding to the receiver instance. The encoding must not be
truncated, and must bear the [APPLICATION 7] tag.
*/
func (r *ModifyResponse) Decode(enc []byte) error {
	payload, err := unwrapTLV(enc, r.classTag())
	if err == nil {
		var dec LDAPResult
		if err = dec.Decode(payload); err == nil {
			*r = ModifyResponse(dec)
		}
	}

	return err
}
