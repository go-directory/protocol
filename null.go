package protocol

/*
Null implements the ASN.1 NULL type, which serves as the base type
of [UnbindRequest].
*/
type Null struct{}

func (_ Null) Tag() int                 { return int(tNull) }
func (_ Null) Encode() ([]byte, error)  { return []byte{0x5, 0x0}, nil }
func (_ *Null) Decode(enc []byte) error { return checkNullEncoding(enc) }

func checkNullEncoding(enc []byte) (err error) {
	if L := len(enc); L != 2 {
		err = protocolError("NULL: unexpected encoding length: want 2, got ", itoa(L))
	} else {
		f := int(enc[0])
		s := int(enc[1])
		if f != 5 || s != 0 {
			err = protocolError("NULL: unexpected encoding payload: want [5 0], got [",
				itoa(f), " ", itoa(s), "]")
		}
	}

	return
}
