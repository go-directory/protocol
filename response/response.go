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

/*
Decode returns an instance of [Response] alongside an error following an attempt to
decode and write the input encoding to the appropriate [Response] implementation
type instance.

This function is used when it is not known what kind of [Response] is defined in
the input encoding.

See also [DecodeByTag] if the 
*/
func Decode(enc []byte) (Response, error) {
	p := 0
        tag, _, _ := readCTLV(enc, &p)
	return DecodeByTag(tag, enc[:p])
}

/*
DecodeByTag returns an instance of [Response] alongside an error following an attempt to
decode and write the input encoding to the appropriate [Response] implementation type
instance.

The input [Tag] argument instance is used to match the appropriate [APPLICATION X] tag.
*/
func DecodeByTag(tag Tag, enc []byte) (ret Response, err error) {
	switch tag.Tag {
	case TagBind:
		var dec Bind
		err = dec.Decode(enc)
		ret = dec
	case TagSearchResultEntry:
		var dec SearchResultEntry
		err = dec.Decode(enc)
		ret = dec
	case TagSearchResultDone:
		var dec SearchResultDone
		err = dec.Decode(enc)
		ret = dec
	case TagSearchResultReference:
		var dec SearchResultReference
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
		var dec Compare
		err = dec.Decode(enc)
		ret = dec
	case TagExtended:
		var dec Extended
		err = dec.Decode(enc)
		ret = dec
	case TagIntermediate:
		var dec Intermediate
		err = dec.Decode(enc)
		ret = dec
	default:
		err = protocolError("Unknown Response tag ", itoa(int(tag.Tag)))
	}

	return
}
