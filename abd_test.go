package protocol

import (
	"fmt"
)

func ExampleAbandonRequest_roundTripBER() {
	abd := AbandonRequest(1234)
	enc, err := abd.Encode()
	if err != nil {
		fmt.Println(err)
		return
	}

	var dec AbandonRequest
	if err = dec.Decode(enc); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(dec)
	// Output: 1234
}
