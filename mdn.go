package protocol

/*
	ModifyDNRequest ::= [APPLICATION 12] SEQUENCE {
		entry           LDAPDN,
		newrdn          RelativeLDAPDN,
		deleteoldrdn    BOOLEAN,
		newSuperior     [0] LDAPDN OPTIONAL }

ModifyDNRequest implements [§ 4.9 of RFC4511]. Instances of this type can be
assembled using the [RenameEntry], [MoveEntry] and [RenameAndMoveEntry] functions.

[§ 4.9 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.9
*/
type ModifyDNRequest struct {
	Entry        LDAPDN
	NewRDN       RelativeLDAPDN
	DeleteOldRDN Boolean
	NewSuperior  *LDAPDN
}

/*
RenameEntry returns an instance of [ModifyDNRequest] with instructions to replace
the current relative distinguished name with a new one. The current superior DN
(the parent) remains unchanged.

That is we can change this ...

	cn=old,ou=people,o=acme

... to something like this ...

	uid=new,ou=people,o=acme

The variadic 'delOldRDN' Boolean will instruct the DSA as to whether or not the
old RDN value(s) should be deleted.
*/
func RenameEntry(dn LDAPDN, newRDN RelativeLDAPDN, delOldRDN ...Boolean) ModifyDNRequest {
	return ModifyDNRequest{
		Entry:        dn,
		NewRDN:       newRDN,
		DeleteOldRDN: Boolean(len(delOldRDN) > 0 && delOldRDN[0]),
	}
}

/*
MoveEntry returns an instance of [ModifyDNRequest] with instructions to relocate,
not rename, the entry. The current relative distinguished name remains unchanged,
only the superior (parent) DN changes.

That is, we can change this ...

	cn=same,ou=people,o=acme

... to something like this ...

	cn=same,ou=accounts,o=acme
*/
func MoveEntry(dn, newSuperior LDAPDN) ModifyDNRequest {
	return ModifyDNRequest{
		Entry:        dn,
		NewRDN:       dn.RDN(),
		DeleteOldRDN: false,
		NewSuperior:  &newSuperior,
	}
}

/*
RenameAndMoveEntry returns an instance of [ModifyDNRequest] with instructions to
both relocate and rename the entry. The current RDN will be replaced with the
specified 'newRDN' value, and the current superior (parent) DN will be replaced
with the specified 'newSuperior' DN.

That is, we change this ...

	cn=old,ou=people,o=acme

... to something like this ...

	uid=new,ou=accounts,o=acme

The variadic 'delOldRDN' Boolean will instruct the DSA as to whether or not the
old RDN value(s) should be deleted.
*/
func RenameAndMoveEntry(dn, newSuperior LDAPDN, newRDN RelativeLDAPDN, delOldRDN ...Boolean) ModifyDNRequest {
	return ModifyDNRequest{
		Entry:        dn,
		NewRDN:       newRDN,
		DeleteOldRDN: Boolean(len(delOldRDN) > 0 && delOldRDN[0]),
		NewSuperior:  &newSuperior,
	}
}

func (_ ModifyDNRequest) Kind() string   { return `request` }
func (_ ModifyDNRequest) Choice() string { return nameModifyDNRequestChoice }
func (_ ModifyDNRequest) Tag() int       { return TagModifyDNRequest }
func (_ ModifyDNRequest) isProtocolOp()  {}
func (_ ModifyDNRequest) isRequestOp()   {}

/*
Encode returns an instance of []byte alongside an error following
an attempt to encode the contents of the receiver instance as an
[APPLICATION 12] SEQUENCE.
*/
func (r ModifyDNRequest) Encode() ([]byte, error) {
	var enc []byte
	var err error

	encoders := []func() ([]byte, error){
		r.Entry.Encode,
		r.NewRDN.Encode,
		r.DeleteOldRDN.Encode,
		// OPTIONAL NewSuperior not included
	}

	for i := 0; i < len(encoders) && err == nil; i++ {
		var payload []byte
		if payload, err = encoders[i](); err == nil {
			enc = append(enc, payload...)
		}
	}

	if err == nil && r.NewSuperior != nil {
		// OPTIONAL NewSuperior
		var payload []byte
		if payload, err = r.NewSuperior.Encode(); err == nil {
			enc = append(enc, payload...)
		}
	}

	if err == nil {
		enc, err = wrapTLV(enc,
			uSeqTag(),    // SEQUENCE
			r.classTag()) // [APPLICATION 12]
	}

	return enc, err
}

/*
Decode returns an error following an attempt to decode and write the
input encoding to the receiver instance. The encoding must not be
truncated, and must bear the [APPLICATION 12] SEQUENCE tag.
*/
func (r *ModifyDNRequest) Decode(enc []byte) error {
	payload, err := unwrapTLV(enc,
		r.classTag(), // [APPLICATION 12]
		uSeqTag())    // SEQUENCE

	if err == nil {
		p := 0

		decoders := []func([]byte) error{
			r.Entry.Decode,
			r.NewRDN.Decode,
			r.DeleteOldRDN.Decode,
			// OPTIONAL NewSuperior not included
		}

		dtags := []byte{tOct, tOct, tBool}

		var last int
		for i := 0; i < len(decoders) && err == nil; i++ {
			_, err = readEPTLV(payload, &p,
				classU, uint32(dtags[i]))
			if err == nil {
				err = decoders[i](payload[last:p])
			}
			last = p
		}

		if err == nil && p < len(payload) {
			// OPTIONAL NewSuperior
			_, err = readEPTLV(payload, &p,
				classU, uint32(tOct))
			if err == nil {
				var ldn LDAPDN
				err = ldn.Decode(payload[last:p])
				r.NewSuperior = &ldn
			}
		}
	}

	return err
}

/*
	ModifyDNResponse ::= [APPLICATION 13] LDAPResult

ModifyDNResponse implements [§ 4.9 of RFC4511], circumscribing an [LDAPResult].

[§ 4.9 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.9
*/
type ModifyDNResponse LDAPResult

func (_ ModifyDNResponse) Kind() string   { return `response` }
func (_ ModifyDNResponse) Choice() string { return nameModifyDNResponseChoice }
func (_ ModifyDNResponse) Tag() int       { return TagModifyDNResponse }
func (_ ModifyDNResponse) isProtocolOp()  {}
func (_ ModifyDNResponse) isResponseOp()  {}

/*
Encode returns an instance of []byte alongside an error following
an attempt to encode the contents of the receiver instance as an
[APPLICATION 13].
*/
func (r ModifyDNResponse) Encode() ([]byte, error) {
	var enc []byte
	res, err := LDAPResult(r).Encode() // LDAPResult SEQUENCE
	if err == nil {
		enc, err = wrapTLV(res, r.classTag()) // [APPLICATION 13]
	}

	return enc, err
}

/*
Decode returns an error following an attempt to decode and write the
input encoding to the receiver instance. The encoding must not be
truncated, and must bear the [APPLICATION 13] tag.
*/
func (r *ModifyDNResponse) Decode(enc []byte) error {
	payload, err := unwrapTLV(enc, r.classTag()) // [APPLICATION 13]
	if err == nil {
		var dec LDAPResult
		if err = dec.Decode(payload); err == nil { // LDAPResult SEQUENCE
			*r = ModifyDNResponse(dec)
		}
	}

	return err
}
