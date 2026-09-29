package request

/*
Authentication Choice tags.
*/
const (
	TagAuthenticationChoiceSimple          = 0
	TagAuthenticationChoiceSaslCredentials = 3
)

/*
	BindRequest ::= [APPLICATION 0] SEQUENCE {
		version                 INTEGER (1 ..  127),
		name                    LDAPDN,
		authentication          AuthenticationChoice }

Bind implements [§ 4.2 of RFC4511].

[§ 4.2 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.2
*/
type Bind struct {
	Version        Integer
	Name           LDAPDN
	Authentication AuthenticationChoice
}

func (_ Bind) IsProtocolOp()  {}
func (_ Bind) IsRequestOp()   {}
func (_ Bind) Kind() string   { return `request` }
func (_ Bind) Choice() string { return nameBindChoice }
func (_ Bind) Tag() int       { return TagBind }
func (_ Bind) classTag() Tag  { return aTag(classA, true, uint32(TagBind)) }

/*
Encode returns an instance of []byte alongside an error following
an attempt to encode the contents of the receiver instance as an
[APPLICATION 0] SEQUENCE.
*/
func (r Bind) Encode() ([]byte, error) {
	if r.Version.Lt(1) || r.Version.Gt(127) {
		return nil, protocolError("Bind Request: Version out of bounds;",
			"\t\nwant: (1 .. 127)\n\tgot:  ", r.Version.String())
	}

	var enc []byte
	payload, err := r.Version.Encode()
	if err == nil {
		enc = append(enc, payload...)
		payload, err = r.Name.Encode()
		if err == nil {
			enc = append(enc, payload...)
			payload, err = r.Authentication.Encode()
			if err == nil {
				enc = append(enc, payload...)
				enc, err = wrapTLV(enc,
					uSeqTag(),    // SEQUENCE
					r.classTag()) // [APPLICATION 0]
			}
		}
	}

	return enc, err
}

/*
Decode returns an error following an attempt to decode and write
the input encoding to the receiver instance. The encoding must
not be truncated, and must bear the [APPLICATION 0] SEQUENCE tag.
*/
func (r *Bind) Decode(enc []byte) error {
	payload, err := unwrapTLV(enc,
		r.classTag(), // [APPLICATION 0]
		uSeqTag())    // SEQUENCE

	if err == nil {
		p := 0
		_, err = readEPTLV(payload, &p, classU, uint32(tInt))
		if err == nil {
			val := payload[:p]
			if err = r.Version.Decode(val); err == nil {
				payload = payload[p:]
				p = 0
				_, err = readEPTLV(payload, &p, classU, uint32(tOct))
				if err == nil {
					val = payload[:p]
					if err = r.Name.Decode(val); err == nil {
						err = r.setAuthChoice(payload[p:])
					}
				}
			}
		}
	}

	return err
}

func (r *Bind) setAuthChoice(payload []byte) (err error) {
	tag, _ := readTag(payload)
	if tag.Tag == TagAuthenticationChoiceSaslCredentials {
		creds := &SaslCredentials{}
		err = creds.Decode(payload)
		r.Authentication = creds
	} else if tag.Tag == TagAuthenticationChoiceSimple {
		creds := &SimpleCredentials{}
		err = creds.Decode(payload)
		r.Authentication = creds
	} else {
		err = protocolError("Bind Request: unknown AuthenticationChoice tag [",
			itoa(int(tag.Tag)), "]")
	}

	return
}

/*
	AuthenticationChoice ::= CHOICE {
		simple [0] OCTET STRING,
		-- 1 and 2 reserved
		sasl   [3] SaslCredentials,
		...  }

AuthenticationChoice implements [§ 4.2 of RFC4511] and serves as the
ASN.1 CHOICE component of a [Bind].

[§ 4.2 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.2
*/
type AuthenticationChoice interface {
	Encode() ([]byte, error)
	Choice() string
	isAuthChoice()
}

/*
	SaslCredentials ::= SEQUENCE {
		mechanism    LDAPString,
		credentials  OCTET STRING OPTIONAL }

SaslCredentials implements [§ 4.2 of RFC4511] and serves as the "sasl"
CHOICE of [AuthenticationChoice].

[§ 4.2 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.2
*/
type SaslCredentials struct {
	Mechanism   LDAPString
	Credentials *OctetString
}

func (_ SaslCredentials) Tag() int       { return TagAuthenticationChoiceSaslCredentials }
func (_ SaslCredentials) Choice() string { return "sasl" }
func (_ SaslCredentials) isAuthChoice()  {}

/*
Encode returns an instance of []byte alongside an error following
an attempt to encode the contents of the receiver instance within
a CONTEXT-SPECIFIC tag of [3], per [AuthenticationChoice].
*/
func (r SaslCredentials) Encode() ([]byte, error) {
	var enc []byte
	payload, err := OctetString(r.Mechanism).Encode()
	if err == nil {
		enc = append(enc, payload...)
		if r.Credentials != nil {
			payload, err = r.Credentials.Encode()
			if err == nil {
				enc = append(enc, payload...)
			}
		}

		enc, err = wrapTLV(enc,
			uSeqTag(),    // SEQUENCE
			r.classTag()) // CONTEXT-SPECIFIC [3]
	}

	return enc, err
}

/*
Decode returns an error following an attempt to decode and write
the input encoding to the receiver instance.  The encoding must
not be truncated and must bear the CONTEXT-SPECIFIC tag of [3],
circumscribing a SEQUENCE.
*/
func (r *SaslCredentials) Decode(enc []byte) error {
	payload, err := unwrapTLV(enc,
		r.classTag(), // CONTEXT-SPECIFIC [3]
		uSeqTag())    // SEQUENCE

	if err == nil {
		p := 0
		var val []byte
		val, err = readEPTLV(payload, &p, classU, uint32(tOct))

		if err == nil {
			r.Mechanism = val
			if p < len(payload) {
				var dec OctetString
				if err = dec.Decode(payload[p:]); err == nil {
					r.Credentials = &dec
				}
			}
		}
	}

	return err
}

/*
	[0] OCTET STRING

SimpleCredentials wraps an [OctetString] within a CONTEXT-SPECIFIC tag of [0], and
and serves as the "simple" CHOICE of [AuthenticationChoice].

Generally, instances of this store the simple bind password value, while the envelope
[Bind] request contains the associated bind distinguished name.
*/
type SimpleCredentials OctetString

func (_ SimpleCredentials) Tag() int       { return TagAuthenticationChoiceSimple }
func (_ SimpleCredentials) Choice() string { return "simple" }
func (_ SimpleCredentials) isAuthChoice()  {}

/*
Encode returns an instance of []byte alongside an error following
an attempt to encode the contents of the receiver instance within
a CONTEXT-SPECIFIC tag of [0], per [AuthenticationChoice].
*/
func (r SimpleCredentials) Encode() ([]byte, error) {
	enc, err := OctetString(r).Encode()
	if err == nil {
		enc, err = wrapTLV(enc, r.classTag()) // CONTEXT-SPECIFIC [0]
	}

	return enc, err
}

/*
Decode returns an error following an attempt to decode and write
the input encoding to the receiver instance.  The encoding must
not be truncated and must bear the CONTEXT-SPECIFIC tag of [0],
circumscribing an [OctetString] encoding.
*/
func (r *SimpleCredentials) Decode(enc []byte) error {
	payload, err := unwrapTLV(enc, r.classTag()) // CONTEXT-SPECIFIC [0]

	if err == nil {
		var dec OctetString
		if err = dec.Decode(payload); err == nil {
			*r = SimpleCredentials(dec)
		}
	}

	return err
}

func (_ SaslCredentials) classTag() Tag {
	return aTag(classC, true, uint32(TagAuthenticationChoiceSaslCredentials))
}
func (_ SimpleCredentials) classTag() Tag {
	return aTag(classC, false, uint32(TagAuthenticationChoiceSimple))
}

/*
	UnbindRequest ::= [APPLICATION 2] NULL

Unbind implements [§ 4.3 of RFC4511].

Note that there is no response counterpart definition for this type.

[§ 4.3 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.3
*/
type Unbind Null

func (_ Unbind) IsProtocolOp()  {}
func (_ Unbind) IsRequestOp()   {}
func (_ Unbind) Kind() string   { return `request` }
func (_ Unbind) Choice() string { return nameUnbindChoice }
func (_ Unbind) Tag() int       { return TagUnbind }
func (_ Unbind) classTag() Tag  { return aTag(classA, false, uint32(TagUnbind)) }

/*
Encode returns an instance of []byte alongside an error following an
attempt to encode the contents of the receiver instance as an
[APPLICATION 2] NULL context.
*/
func (r Unbind) Encode() ([]byte, error) { return Null(r).cast().Encode() }

/*
Decode returns an error following an attempt to decode and write the
input encoding to the receiver instance. The encoding must not be
truncated, and must bear the [APPLICATION 2] NULL tag.
*/
func (r *Unbind) Decode(enc []byte) error {
	N := Null(*r).cast()
	return N.Decode(enc)
}
