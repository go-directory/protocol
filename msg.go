package protocol

/*
ProtocolOp implements [§ 4.1.1 of RFC4511], and serves as the ASN.1
CHOICE component of the [LDAPMessage] SEQUENCE.

This type is a superset of the [Request] and [Response] interface
types.

[§ 4.1.1 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.1.1
*/
type ProtocolOp interface {
	Encode() ([]byte, error)
	Choice() string
	Kind() string
	Tag() int
	IsProtocolOp()
}

/*
	LDAPMessage ::= SEQUENCE {
	     messageID       MessageID,
	     protocolOp      CHOICE {
	          bindRequest           BindRequest,
	          bindResponse          BindResponse,
	          unbindRequest         UnbindRequest,
	          searchRequest         SearchRequest,
	          searchResEntry        SearchResultEntry,
	          searchResDone         SearchResultDone,
	          searchResRef          SearchResultReference,
	          modifyRequest         ModifyRequest,
	          modifyResponse        ModifyResponse,
	          addRequest            AddRequest,
	          addResponse           AddResponse,
	          delRequest            DelRequest,
	          delResponse           DelResponse,
	          modDNRequest          ModifyDNRequest,
	          modDNResponse         ModifyDNResponse,
	          compareRequest        CompareRequest,
	          compareResponse       CompareResponse,
	          abandonRequest        AbandonRequest,
	          extendedReq           ExtendedRequest,
	          extendedResp          ExtendedResponse,
	          ...,
	          intermediateResponse  IntermediateResponse },
	     controls       [0] Controls OPTIONAL }

LDAPMessage implements [§ 4.1.1 of RFC4511].

[§ 4.1.1 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.1.1
*/
type LDAPMessage struct {
	MessageID  MessageID
	ProtocolOp ProtocolOp
	Controls   *Controls
}

/*
NewLDAPMessage initializes and returns an instance of *[LDAPMessage].

At a minimum, the [MessageID] must be provided when this constructor is called. If
the [MessageID] is not yet known to the caller, simply allocate a new instance of
*[LDAPMessage] directly, e.g.:

	msg := &LDAPMessage{}

The optional variadic [ProtocolOp] argument will result in the provided instance
being assigned to the underlying "ProtocolOp" component. Depending on the sender
of this message, the [ProtocolOp] will be of the [Request] or [Response] subset.
*/
func NewLDAPMessage(id MessageID, op ...ProtocolOp) *LDAPMessage {
	m := &LDAPMessage{MessageID: id}
	if len(op) > 0 && op[0] != nil {
		m.ProtocolOp = op[0]
	}

	return m
}

/*
Encode returns an instance of []byte alongside an error following an attempt
to encode the contents of the receiver as a UNIVERSAL SEQUENCE.
*/
func (r LDAPMessage) Encode() ([]byte, error) {
	var enc []byte

	mid, _ := r.MessageID.Encode() // INTEGER
	enc = append(enc, mid...)
	pop, err := r.ProtocolOp.Encode() // ProtocolOp==Response|Request
	if err == nil {
		enc = append(enc, pop...)
		if len((*r.Controls)) > 0 {
			var ctrl []byte
			if ctrl, err = r.Controls.Encode(); err == nil { // SEQUENCE OF control Control
				var wrap []byte
				wrap, err = wrapTLV(ctrl, aTag(classC, true, uint32(0)))

				if err == nil {
					enc = append(enc, wrap...)
				}
			}
		}
		if err == nil {
			enc, err = wrapTLV(enc, uSeqTag()) // SEQUENCE
		}
	}

	return enc, err
}

/*
Decode returns an error following an attempt to decode and write the
input encoding value to the receiver instance. The encoding must not
be truncated and must bear the UNIVERSAL SEQUENCE (0x30) tag.
*/
func (r *LDAPMessage) Decode(enc []byte) error {
	payload, err := unwrapTLV(enc, uSeqTag()) // SEQUENCE
	if err == nil {
		p := 0
		_, err = readEPTLV(payload, &p, classU, uint32(tInt))
		if err == nil {
			if err = r.MessageID.Decode(payload[:p]); err == nil { // INTEGER
				rest := payload[p:]
				p = 0
				tag, _, _ := readCTLV(rest, &p)
				r.ProtocolOp, err = readProtocolOp(tag, rest[:p]) // ProtocolOp==Response|Request
				if err == nil && len(rest) > p {
					var unwrap []byte
					unwrap, err = unwrapTLV(rest[p:],
						aTag(classC, true, uint32(0)))

					if err == nil {
						var dec Controls
						if err = dec.Decode(unwrap); err == nil { // SEQUENCE OF control Control
							r.Controls = &dec
						}
					}
				}
			}
		}
	}

	return err
}

func readProtocolOp(tag Tag, payload []byte) (ret ProtocolOp, err error) {
	if tag.Class != classA {
		err = protocolError("class mismatch; want 2, got ", itoa(int(tag.Class)))
		return
	}

	switch tag.Tag {
	case TagBindRequest, TagUnbindRequest,
		TagSearchRequest, TagExtendedRequest,
		TagModifyRequest, TagAddRequest,
		TagDelRequest, TagModifyDNRequest,
		TagCompareRequest, TagAbandonRequest:
		ret, err = requestDecodeByTag(tag, payload)

	case TagBindResponse, TagModifyResponse,
		TagAddResponse, TagDelResponse,
		TagModifyDNResponse, TagCompareResponse,
		TagExtendedResponse, TagIntermediateResponse,
		TagSearchResultEntry, TagSearchResultDone,
		TagSearchResultReference:
		ret, err = responseDecodeByTag(tag, payload)

	default:
		err = protocolError("readProtocolOp: invalid tag value ",
			itoa(int(tag.Tag)), " for protocolOp")
	}

	return
}
