package controls

import (
	"github.com/go-directory/encoding/asn1"
	"github.com/go-directory/syntax"
)

func aTag(class byte, constr bool, tag uint32) asn1.Tag {
	return asn1.Tag{
		Class:       class,
		Constructed: constr,
		Tag:         uint32(tag),
	}
}

// go-directory/syntax alias type.
type (
	LDAPOID              = syntax.LDAPOID
	Integer              = syntax.Integer
	Boolean              = syntax.Boolean
	OctetString          = syntax.OctetString
	AttributeType        = syntax.AttributeType
	AttributeDescription = syntax.AttributeDescription
	MatchingRuleID       = syntax.MatchingRuleID
)

// go-directory/encoding/asn1 alias type.
type (
	RawValue = asn1.RawValue
	Tag      = asn1.Tag
)

var (
	readTag   = asn1.ReadTag
	wrapTLV   = asn1.WrapTLV
	unwrapTLV = asn1.UnwrapTLV
	readCTLV  = asn1.ReadConstructedTLV
	readECTLV = asn1.ReadExpectedConstructedTLV
	readEPTLV = asn1.ReadExpectedPrimitiveTLV
	readLen   = asn1.ReadLength
)

func encInt[T asn1.INTEGER](x T) []byte          { return asn1.EncodeInteger[T](x) }
func decInt[T asn1.INTEGER](x []byte) (T, error) { return asn1.DecodeInteger[T](x) }
func NewInteger(x any) (Integer, error) {
	i, err := syntax.NewInteger(x)
	return i, err
}

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
	classP = asn1.ClassPrivate         // 3, not really needed ...
)

/*
private asn1.Tag<X> aliases. Same deal as above.
*/
const (
	tBool = asn1.TagBoolean          // 0x01, 1
	tInt  = asn1.TagInteger          // 0x02, 2
	tBit  = asn1.TagBitString        // 0x03, 3
	tOct  = asn1.TagOctetString      // 0x04, 4
	tNull = asn1.TagNull             // 0x05, 5
	tOID  = asn1.TagObjectIdentifier // 0x06, 6
	tEnum = asn1.TagEnumerated       // 0x0A, 10
	tUTF8 = asn1.TagUTF8String       // 0x0c, 12
	tSeq  = asn1.TagSequence         // 0x10, 16
	tSet  = asn1.TagSet              // 0x11, 17
	tNum  = asn1.TagNumericString    // 0x12, 18
	tPS   = asn1.TagPrintableString  // 0x13, 19
	tT61  = asn1.TagT61String        // 0x14, 20
	tIA5  = asn1.TagIA5String        // 0x16, 22
	tUni  = asn1.TagUniversalString  // 0x1C, 28
	tBMP  = asn1.TagBMPString        // 0x1E, 30
)
