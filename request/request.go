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
Decode returns an instance of [Request] alongside an error following an attempt to
decode and write the input encoding to the appropriate [Request] implementation
type instance.

This function is used when it is not known what kind of [Request] is defined in
the input encoding.

See also [DecodeByTag] if the
*/
func Decode(enc []byte) (Request, error) {
	p := 0
	tag, _, _ := readCTLV(enc, &p)
	return DecodeByTag(tag, enc[:p])
}

/*
Decode returns an instance of [Request] alongside an error following an attempt to
decode and write the input encoding to the appropriate [Request] implementation
type instance.

The input [Tag] argument instance is used to match the appropriate [APPLICATION X]
tag.
*/
func DecodeByTag(tag Tag, enc []byte) (Request, error) {
	var ret Request
	var err error

	switch tag.Tag {
	case TagBind:
		var dec Bind
		err = dec.Decode(enc)
		ret = dec
	case TagUnbind:
		var dec Unbind
		err = dec.Decode(enc)
		ret = dec
	case TagSearch:
		var dec Search
		err = dec.Decode(enc)
		ret = dec
	case TagModify:
		var dec Modify
		err = dec.Decode(enc)
		ret = dec
	case TagAdd:
		var dec Add
		err = dec.Decode(enc)
		ret = dec
	case TagDel:
		var dec Del
		err = dec.Decode(enc)
		ret = dec
	case TagModifyDN:
		var dec ModifyDN
		err = dec.Decode(enc)
		ret = dec
	case TagCompare:
		var dec Del
		err = dec.Decode(enc)
		ret = dec
	case TagAbandon:
		var dec Abandon
		err = dec.Decode(enc)
		ret = dec
	case TagExtended:
		var dec Extended
		err = dec.Decode(enc)
		ret = dec
	default:
		err = protocolError("Unknown Request tag ", itoa(int(tag.Tag)))
	}

	return ret, err
}
