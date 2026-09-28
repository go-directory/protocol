package response

/*
asn1.go serves as an interface to go-directory/encoding/asn1.
*/

import (
	"github.com/go-directory/encoding/asn1"
)

func aTag(class byte, constr bool, tag uint32) Tag {
	return Tag{
		Class:       class,
		Constructed: constr,
		Tag:         uint32(tag),
	}
}

type RawValue = asn1.RawValue
type Tag = asn1.Tag

var (
	readTag   = asn1.ReadTag
	wrapTLV   = asn1.WrapTLV
	unwrapTLV = asn1.UnwrapTLV
	readCTLV  = asn1.ReadConstructedTLV
	readECTLV = asn1.ReadExpectedConstructedTLV
	readEPTLV = asn1.ReadExpectedPrimitiveTLV
	readLen   = asn1.ReadLength
)

/*
quick UNIVERSAL SEQUENCE.
*/
func uSeqTag() Tag { return aTag(classU, true, uint32(tSeq)) }

/*
private asn1.Class<X> aliases because I'm sick of typing them,
but I don't want to hard code the numbers.
*/
const (
	classU = asn1.ClassUniversal       // 0
	classA = asn1.ClassApplication     // 1
	classC = asn1.ClassContextSpecific // 2
)

/*
private asn1.Tag<X> aliases. Same deal as above.
*/
const (
	tOct  = asn1.TagOctetString // 0x04, 4
	tEnum = asn1.TagEnumerated  // 0x0A, 10
	tSeq  = asn1.TagSequence    // 0x10, 16
)
