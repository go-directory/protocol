package request

/*
	Extended ::= [APPLICATION 23] SEQUENCE {
	     requestName      [0] LDAPOID,
	     requestValue     [1] OCTET STRING OPTIONAL }

Extended implements [§ 4.12 of RFC4511].

[§ 4.12 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.12
*/
type Extended struct {
	RequestName  LDAPOID
	RequestValue *OctetString
}

func (_ Extended) Kind() string   { return `request` }
func (_ Extended) Choice() string { return nameExtendedChoice }
func (_ Extended) Tag() int       { return TagExtended }
func (_ Extended) IsProtocolOp()  {}
func (_ Extended) IsRequestOp()   {}
func (_ Extended) classTag() Tag  { return aTag(classA, true, uint32(TagExtended)) }

/*
Encode returns an instance of []byte alongside an error following
an attempt to encode the contents of the receiver instance as an
[APPLICATION 23] tag, circumscribing a SEQUENCE.
*/
func (r Extended) Encode() ([]byte, error) {
	var enc []byte
	cmpnt, err := r.RequestName.Encode()
	if err == nil {
		cmpnt, err = wrapTLV(cmpnt,
			aTag(classC,
				false, uint32(TagExtendedName)))

		if err == nil {
			enc = append(enc, cmpnt...)
			if r.RequestValue != nil {
				cmpnt, err = r.RequestValue.Encode()
				if err == nil {
					cmpnt, err = wrapTLV(cmpnt,
						aTag(classC, false,
							uint32(TagExtendedValue)))
					if err == nil {
						enc = append(enc, cmpnt...)
					}
				}
			}
			if err == nil {
				enc, err = wrapTLV(enc,
					uSeqTag(),    // SEQUENCE
					r.classTag()) // [APPLICATION 23]
			}
		}
	}

	return enc, err
}

/*
Decode returns an error following an attempt to decode and write the
input encoding to the receiver instance. The encoding must not be
truncated and must bear the [APPLICATION 23] tag, circumscribing a
SEQUENCE.
*/
func (r *Extended) Decode(enc []byte) error {
	var err error
	enc, err = unwrapTLV(enc,
		r.classTag(), // [APPLICATION 23]
		uSeqTag())    // SEQUENCE

	if err == nil {
		p := 0
		var payload []byte
		payload, err = readEPTLV(enc, &p,
			classC,
			uint32(TagExtendedName))

		var value []byte
		if err == nil {
			p2 := 0
			value, err = readEPTLV(payload,
				&p2, classU, uint32(tOct))
		}

		if err == nil {
			r.RequestName = value
			if len(payload) < len(enc) {
				rest := enc[len(payload)+2:] // 2 == header

				p = 0
				payload, err = readEPTLV(rest,
					&p, classC,
					uint32(TagExtendedValue))

				if err == nil {
					p = 0
					value, err = readEPTLV(payload, &p,
						classU, uint32(tOct))

					if err == nil {
						val := OctetString(value)
						r.RequestValue = &val
					}
				}
			}
		}
	}

	return err
}

/*
StartTLS implements the [Extended] [Request] type per [§ 4.14.1 of RFC4511].

This function is intended for a client to use to request the use of TLS for
the session.

[§ 4.14.1 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.14.1
*/
func StartTLS() Extended {
	return Extended{
		RequestName: NoticeOfStartTLS,
	}
}

/*
Request and Response notice identifiers.
*/
var (
	NoticeOfDisconnection   = LDAPOID("1.3.6.1.4.1.1466.2003")
	NoticeOfCancel          = LDAPOID("1.3.6.1.1.8")
	NoticeOfStartTLS        = LDAPOID("1.3.6.1.4.1.1466.20037")
	NoticeOfWhoAmI          = LDAPOID("1.3.6.1.4.1.4203.1.11.3")
	NoticeOfGetConnectionID = LDAPOID("1.3.6.1.4.1.26027.1.6.2")
	NoticeOfPasswordModify  = LDAPOID("1.3.6.1.4.1.4203.1.11.1")
)

/*
Extended Request tags.
*/
const (
	TagExtendedName  = 0
	TagExtendedValue = 1
)
