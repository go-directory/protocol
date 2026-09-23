package protocol

import (
	"github.com/go-directory/encoding/asn1"
)

/*
Text is a convenience type meant to work in situations
where either a string or []byte is acceptable for input.
*/
type Text interface {
	~string | ~[]byte
}

func aTag(class byte, constr bool, tag uint32) asn1.Tag {
	return asn1.Tag{
		Class:       class,
		Constructed: constr,
		Tag:         uint32(tag),
	}
}

func uSeqTag() asn1.Tag { return aTag(0, true, 16) }
