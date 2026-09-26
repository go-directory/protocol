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
	isProtocolOp()
}

/*
Request implements a subset of [ProtocolOp], encompassing only the *request*
types defined throughout the subsections of [§ 4.1 of RFC4511].

[§ 4.1 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.1
*/
type Request interface {
	Encode() ([]byte, error)
	Choice() string
	Kind() string
	Tag() int
	isProtocolOp()
	isRequestOp()
}

/*
Response implements a subset of [ProtocolOp], encompassing only the *response*
types defined throughout the subsections of [§ 4.1 of RFC4511].

[§ 4.1 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.1
*/
type Response interface {
	Encode() ([]byte, error)
	Choice() string
	Kind() string
	Tag() int
	isProtocolOp()
	isResponseOp()
}

// request CHOICE names
const (
	nameAbandonRequestChoice  = `abandonRequest`
	nameAddRequestChoice      = `addRequest`
	nameBindRequestChoice     = `bindRequest`
	nameCompareRequestChoice  = `compareRequest`
	nameDelRequestChoice      = `delRequest`
	nameExtendedRequestChoice = `extendedReq`
	nameModifyRequestChoice   = `modifyRequest`
	nameModifyDNRequestChoice = `modDNRequest`
	nameSearchRequestChoice   = `searchRequest`
	nameUnbindRequestChoice   = `unbindRequest`
)

// response CHOICE names
const (
	nameAddResponseChoice           = `addResponse`
	nameBindResponseChoice          = `bindResponse`
	nameCompareResponseChoice       = `compareResponse`
	nameDelResponseChoice           = `delResponse`
	nameIntermediateResponseChoice  = `intermediateResponse`
	nameExtendedResponseChoice      = `extendedResp`
	nameModifyResponseChoice        = `modifyResponse`
	nameModifyDNResponseChoice      = `modDNResponse`
	nameSearchResponseChoice        = `searchResponse`
	nameSearchResultEntryChoice     = `searchResEntry`
	nameSearchResultDoneChoice      = `searchResDone`
	nameSearchResultReferenceChoice = `searchResRef`
)

/*
	MessageID ::= INTEGER (0 ..  maxInt)

MessageID implements [§ 4.1.1 of RFC4511], and serves the "messageID"
component of the [LDAPMessage] SEQUENCE.

Note that instances of this type are constrained to the unsigned portion
of int32:

	(0 ..  maxInt)
	maxInt INTEGER ::= 2147483647 -- (2^^31 - 1) --

[§ 4.1.1 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.1.1
*/
type MessageID int32

func (r MessageID) Encode() ([]byte, error) {
	if int32(r) < 0 {
		return nil, errMsgIDOOB
	}
	enc := encInt[int64](int64(r))
	return enc, nil
}

/*
Decode returns an error following an attempt to decode and write the
input encoding to the receiver instance. The encoding must not be
truncated and must bear the ASN.1 INTEGER tag (0x02).
*/
func (r *MessageID) Decode(enc []byte) error {
	dec, err := decInt[int64](enc)
	if err == nil {
		if !(0 <= dec && dec <= UBMessageID) {
			return errMsgIDOOB
		}
		*r = MessageID(int32(dec))
	}

	return err
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
NewLDAPMessage initializes and returns an instance of *[LDAPMessage]. The
optional variadic [ProtocolOp] argument will result in the provided instance
being assigned to the underlying "ProtocolOp" component.
*/
func NewLDAPMessage(op ...ProtocolOp) *LDAPMessage {
	m := &LDAPMessage{}
	if len(op) > 0 && op[0] != nil {
		m.ProtocolOp = op[0]
	}

	return m
}

/*
Encode returns an instance of []byte alongside an error following
an attempt to encode the contents of the receiver as a SEQUENCE.
*/
func (r LDAPMessage) Encode() ([]byte, error) {
	var enc []byte

	mid := encInt[uint](uint(r.MessageID))
	enc = append(enc, mid...)
	pop, err := r.ProtocolOp.Encode()
	if err == nil {
		enc = append(enc, pop...)
		if r.Controls != nil {
			var ctrl []byte
			if ctrl, err = r.Controls.Encode(); err == nil {
				var wrap []byte
				wrap, err = wrapTLV(ctrl, aTag(classC, true, uint32(0)))

				if err == nil {
					enc = append(enc, wrap...)
				}
			}
		}
		if err == nil {
			enc, err = wrapTLV(enc, uSeqTag())
		}
	}

	return enc, err
}

/*
Decode returns an error following an attempt to decode and write the
input encoding value to the receiver instance. The encoding must not
be truncated and must bear the SEQUENCE (0x10) tag.
*/
func (r *LDAPMessage) Decode(enc []byte) error {
	payload, err := unwrapTLV(enc, uSeqTag())
	if err == nil {
		p := 0
		_, err = readEPTLV(payload, &p, classU, uint32(tInt))
		if err == nil {
			var uu int64
			if uu, err = decInt[int64](payload[:p]); err == nil {
				r.MessageID = MessageID(uu)
				rest := payload[p:]
				if err == nil {
					p = 0
					tag, _, _ := readCTLV(rest, &p)
					r.ProtocolOp, err = readProtocolOp(tag, rest[:p])
					if err == nil && len(rest) > p {
						var unwrap []byte
						unwrap, err = unwrapTLV(rest[p:],
							aTag(classC, true, uint32(0)))

						if err == nil {
							var dec Controls
							if err = dec.Decode(unwrap); err == nil {
								r.Controls = &dec
							}
						}
					}
				}
			}
		}
	}

	return err
}

func readRequestOp(tag Tag, payload []byte) (ret ProtocolOp, err error) {
	switch tag.Tag {
	case TagBindRequest:
		var dec BindRequest
		err = dec.Decode(payload)
		ret = dec
	case TagUnbindRequest:
		var dec UnbindRequest
		err = dec.Decode(payload)
		ret = dec
	case TagSearchRequest:
		var dec SearchRequest
		err = dec.Decode(payload)
		ret = dec
	case TagModifyRequest:
		var dec ModifyRequest
		err = dec.Decode(payload)
		ret = dec
	case TagAddRequest:
		var dec AddRequest
		err = dec.Decode(payload)
		ret = dec
	case TagDelRequest:
		var dec DelRequest
		err = dec.Decode(payload)
		ret = dec
	case TagModifyDNRequest:
		var dec ModifyDNRequest
		err = dec.Decode(payload)
		ret = dec
	case TagCompareRequest:
		var dec DelRequest
		err = dec.Decode(payload)
		ret = dec
	case TagAbandonRequest:
		var dec AbandonRequest
		err = dec.Decode(payload)
		ret = dec
	case TagExtendedRequest:
		var dec ExtendedRequest
		err = dec.Decode(payload)
		ret = dec
	}

	return
}

func readResponseOp(tag Tag, payload []byte) (ret ProtocolOp, err error) {
	switch tag.Tag {
	case TagBindResponse:
		var dec BindResponse
		err = dec.Decode(payload)
		ret = dec
	case TagSearchResultEntry:
		var dec SearchResultEntry
		err = dec.Decode(payload)
		ret = dec
	case TagSearchResultDone:
		var dec SearchResultDone
		err = dec.Decode(payload)
		ret = dec
	case TagSearchResultReference:
		var dec SearchResultReference
		err = dec.Decode(payload)
		ret = dec
	case TagModifyResponse:
		var dec ModifyResponse
		err = dec.Decode(payload)
		ret = dec
	case TagAddResponse:
		var dec AddResponse
		err = dec.Decode(payload)
		ret = dec
	case TagDelResponse:
		var dec DelResponse
		err = dec.Decode(payload)
		ret = dec
	case TagModifyDNResponse:
		var dec ModifyDNResponse
		err = dec.Decode(payload)
		ret = dec
	case TagCompareResponse:
		var dec CompareResponse
		err = dec.Decode(payload)
		ret = dec
	case TagExtendedResponse:
		var dec ExtendedResponse
		err = dec.Decode(payload)
		ret = dec
	case TagIntermediateResponse:
		var dec IntermediateResponse
		err = dec.Decode(payload)
		ret = dec
	}

	return
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
		ret, err = readRequestOp(tag, payload)

	case TagBindResponse, TagModifyResponse,
		TagAddResponse, TagDelResponse,
		TagModifyDNResponse, TagCompareResponse,
		TagExtendedResponse, TagIntermediateResponse,
		TagSearchResultEntry, TagSearchResultDone,
		TagSearchResultReference:
		ret, err = readResponseOp(tag, payload)

	default:
		err = protocolError("readProtocolOp: invalid tag value ",
			itoa(int(tag.Tag)), " for protocolOp")
	}

	return
}

var (
	errMsgIDOOB = constraintViolation("MessageID: ", errTextMaxIntOutOfBounds)
)
