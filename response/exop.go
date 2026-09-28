package response

/*
	ExtendedResponse ::= [APPLICATION 24] SEQUENCE {
		COMPONENTS OF LDAPResult,
		responseName     [10] LDAPOID OPTIONAL,
		responseValue    [11] OCTET STRING OPTIONAL }

Extended implements [§ 4.12 of RFC4511].

[§ 4.12 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.12
*/
type Extended struct {
	LDAPResult
	ResponseName  *LDAPOID
	ResponseValue *OctetString
}

/*
Encode returns an instance of []byte alongside an error following
an attempt to encode the contents of the receiver instance as an
[APPLICATION 24] tag, circumscribing a SEQUENCE.
*/
func (r Extended) Encode() ([]byte, error) {
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
			if r.ResponseName != nil {
				res, err = r.ResponseName.Encode()
				if err == nil {
					res, err = wrapTLV(res,
						aTag(classC, false,
							uint32(TagExtendedName)))
					if err == nil {
						enc = append(enc, res...)
					}
				}
			}

			if r.ResponseValue != nil {
				res, err = r.ResponseValue.Encode()
				if err == nil {
					res, err = wrapTLV(res,
						aTag(classC, false,
							uint32(TagExtendedValue)))
					if err == nil {
						enc = append(enc, res...)
					}
				}
			}

			if err == nil {
				enc, err = wrapTLV(enc,
					uSeqTag(),    // SEQUENCE
					r.classTag()) // [APPLICATION 24]
			}
		}
	}

	return enc, err
}

/*
Decode returns an error following an attempt to decode and write the
input encoding to the receiver instance.  The encoding must not be
truncated and must bear the [APPLICATION 24] tag, circumscribing a
SEQUENCE.
*/
func (r *Extended) Decode(enc []byte) error {
	payload, err := unwrapTLV(enc,
		r.classTag(), // [APPLICATION 24]
		uSeqTag())    // SEQUENCE

	if err == nil {
		var p int
		p, err = r.LDAPResult.setComponentsOf(payload)
		for p < len(payload) && err == nil {
			tag, _ := readTag(payload[p:])
			var res []byte
			res, err = readEPTLV(payload, &p,
				classC, tag.Tag)

			if err == nil {
				switch tag.Tag {
				case TagExtendedName:
					var loid LDAPOID
					err = loid.Decode(res)
					r.ResponseName = &loid

				case TagExtendedValue:
					var val OctetString
					err = val.Decode(res)
					r.ResponseValue = &val
				}
			}
		}
	}

	return err
}

func (_ Extended) Kind() string   { return `response` }
func (_ Extended) Choice() string { return nameExtendedChoice }
func (_ Extended) Tag() int       { return TagExtended }
func (_ Extended) IsProtocolOp()  {}
func (_ Extended) IsResponseOp()  {}
func (_ Extended) classTag() Tag  { return aTag(classA, true, uint32(TagExtended)) }

/*
Extended Response tags.
*/
const (
	TagExtendedName  = 10
	TagExtendedValue = 11
)

/*
StartTLS implements the [Extended] [Response] type per [§ 4.14.2 of RFC4511].

This function is intended for a server to use to when responsing to a client's
request that TLS be used for the session.

[§ 4.14.2 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.14.2
*/
func StartTLS() Extended {
        return Extended{
                ResponseName: &NoticeOfStartTLS,
        }
}


/*
Response notice identifiers.
*/
var (
	NoticeOfDisconnection   = LDAPOID("1.3.6.1.4.1.1466.2003")
	NoticeOfCancel          = LDAPOID("1.3.6.1.1.8")
	NoticeOfStartTLS        = LDAPOID("1.3.6.1.4.1.1466.20037")
	NoticeOfWhoAmI          = LDAPOID("1.3.6.1.4.1.4203.1.11.3")
	NoticeOfGetConnectionID = LDAPOID("1.3.6.1.4.1.26027.1.6.2")
	NoticeOfPasswordModify  = LDAPOID("1.3.6.1.4.1.4203.1.11.1")
)
