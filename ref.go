package protocol

/*
	Referral ::= SEQUENCE SIZE (1..MAX) OF uri URI

Referral implements [§ 4.1.10 of RFC4511].

[§ 4.1.10 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.1.10
*/
type Referral []URI

/*
Tag returns 0x10 (16) for SEQUENCE OF.
*/
func (_ Referral) Tag() int { return int(tSeq) }

func (r Referral) Encode() ([]byte, error) {
	// Create slice of encoded URIs
	var err error
	var enc []byte
	for i := 0; i < len(r) && err == nil; i++ {
		var slice []byte
		slice, err = OctetString(r[i]).Encode()
		enc = append(enc, slice...)
	}

	if err == nil {
		// Wrap as a SEQUENCE OF URI
		enc, err = wrapTLV(enc, uSeqTag())
	}

	return enc, err
}

func (r *Referral) Decode(enc []byte) error {
	payload, err := unwrapTLV(enc, uSeqTag())
	if err == nil {
		p := 0
		for p < len(payload) && err == nil {
			var uriVal []byte
			uriVal, err = readEPTLV(payload, &p,
				classU, uint32(tOct))

			if err == nil {
				*r = append(*r, URI(uriVal))
			}
		}
	}

	return err
}
