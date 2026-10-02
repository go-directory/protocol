package response

/*
	BindResponse ::= [APPLICATION 1] SEQUENCE {
		COMPONENTS OF LDAPResult,
		serverSaslCreds    [7] OCTET STRING OPTIONAL }

Bind implements [§ 4.2.2 of RFC4511].

[§ 4.2.2 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.2.2
*/
type Bind struct {
	LDAPResult
	ServerSaslCreds *OctetString
}

func (_ Bind) IsProtocolOp()  {}
func (_ Bind) IsResponseOp()  {}
func (_ Bind) Tag() int       { return TagBind }
func (_ Bind) Kind() string   { return `response` }
func (_ Bind) Choice() string { return nameBindChoice }
func (_ Bind) classTag() Tag  { return aTag(classA, true, uint32(TagBind)) }
func (r Bind) Result() Enumerated { return r.LDAPResult.ResultCode }

/*
Encode returns an instance of []byte alongside an error following
an attempt to encode the contents of the receiver instance within
an [APPLICATION 1] tag.
*/
func (r Bind) Encode() ([]byte, error) {
	var enc []byte
	res, err := r.LDAPResult.Encode()
	if err == nil {
		// COMPONENTS OF: get rid of the
		// outer SEQUENCE layer, leaving
		// just the component values.
		// Those are what we keep.
		res, err = unwrapTLV(res, uSeqTag())
		if err == nil {
			enc = append(enc, res...)
			if len((*r.ServerSaslCreds)) > 0 {
				res, err = r.ServerSaslCreds.Encode()
				if err == nil {
					res, err = wrapTLV(res,
						aTag(classC, false,
							uint32(TagBindServerSaslCreds)))
					if err == nil {
						enc = append(enc, res...)
					}
				}
			}

			if err == nil {
				enc, err = wrapTLV(enc,	r.classTag()) // [APPLICATION 1]
			}
		}
	}

	return enc, err
}

/*
Decode returns an error following an attempt to decode and write
the input encoding to the receiver instance.  The encoding must
not be truncated and must bear the [APPLICATION 1] tag.
*/
func (r *Bind) Decode(enc []byte) error {
	payload, err := unwrapTLV(enc, r.classTag()) // [APPLICATION 1]

	if err == nil {
		var p int
		if p, err = r.LDAPResult.setComponentsOf(payload); err == nil {
			rest := payload[p:]
			if len(rest) > 0 {
				var res []byte
				res, err = unwrapTLV(rest,
					aTag(classC, false,
						uint32(TagBindServerSaslCreds)))

				if err == nil {
					var creds OctetString
					if err = creds.Decode(res); err == nil {
						r.ServerSaslCreds = &creds
					}
				}
			}
		}
	}

	return err
}

const TagBindServerSaslCreds = 7
