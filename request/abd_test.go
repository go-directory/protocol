package request

import (
	"fmt"
)

func ExampleAbandon_roundTripBER() {
	abd := Abandon(1234)
	enc, err := abd.Encode()
	if err != nil {
		fmt.Println(err)
		return
	}

	var dec Abandon
	if err = dec.Decode(enc); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(dec)
	// Output: 1234
}
