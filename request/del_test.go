package request

import (
	"fmt"
)

func ExampleDel_roundTripBER() {
	req := Del("cn=Some Guy,ou=People,o=acme")

	enc, err := req.Encode()
	if err != nil {
		fmt.Println(err)
		return
	}

	var dec Del
	if err = dec.Decode(enc); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s", dec)
	// Output: cn=Some Guy,ou=People,o=acme
}
