package request

/*
Request implements a subset of LDAPMessage.ProtocolOp, encompassing only the *request*
types defined throughout the subsections of [§ 4.1 of RFC4511].

[§ 4.1 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.1
*/
type Request interface {
	Encode() ([]byte, error)
	Choice() string
	Kind() string
	Tag() int
	IsProtocolOp()
	IsRequestOp()
}

/*
Decode returns an instance of [Request] alongside an error following an
attempt to decode and write the input encoding to the appropriate [Request]
implementation type instance.
*/
func Decode(tag Tag, payload []byte) (ret Request, err error) {
	switch tag.Tag {
	case TagBind:
		var dec Bind
		err = dec.Decode(payload)
		ret = dec
	case TagUnbind:
		var dec Unbind
		err = dec.Decode(payload)
		ret = dec
	case TagSearch:
		var dec Search
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
		var dec Del
		err = dec.Decode(payload)
		ret = dec
	case TagAbandon:
		var dec Abandon
		err = dec.Decode(payload)
		ret = dec
	case TagExtended:
		var dec Extended
		err = dec.Decode(payload)
		ret = dec
	}

	return
}
