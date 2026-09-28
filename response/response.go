package response

/*
Response implements a subset of LDAPMessage.ProtocolOp, encompassing only the *response*
types defined throughout the subsections of [§ 4.1 of RFC4511].

[§ 4.1 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.1
*/
type Response interface {
	Encode() ([]byte, error)
	Choice() string
	Kind() string
	Tag() int
	IsProtocolOp()
	IsResponseOp()
}

func Decode(tag Tag, payload []byte) (ret Response, err error) {
	switch tag.Tag {
	case TagBind:
		var dec Bind
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
	case TagModify:
		var dec Modify
		err = dec.Decode(payload)
		ret = dec
	case TagAdd:
		var dec Add
		err = dec.Decode(payload)
		ret = dec
	case TagDel:
		var dec Del
		err = dec.Decode(payload)
		ret = dec
	case TagModifyDN:
		var dec ModifyDN
		err = dec.Decode(payload)
		ret = dec
	case TagCompare:
		var dec Compare
		err = dec.Decode(payload)
		ret = dec
	case TagExtended:
		var dec Extended
		err = dec.Decode(payload)
		ret = dec
	case TagIntermediate:
		var dec Intermediate
		err = dec.Decode(payload)
		ret = dec
	}

	return
}
