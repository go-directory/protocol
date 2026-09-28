package request

import (
	"fmt"
)

func ExampleExtended_roundTripBER() {
	reqVal := OctetString("This is some kind of value")
	req := Extended{
		RequestName:  LDAPOID(`1.2.3.4.5.6`),
		RequestValue: &reqVal,
	}

	enc, err := req.Encode()
	if err != nil {
		fmt.Println(err)
		return
	}

	var dec Extended
	if err = dec.Decode(enc); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Req. Name:  %s\n", dec.RequestName)
	fmt.Printf("Req. Value: %s\n", dec.RequestValue)
	// Output:
	// Req. Name:  1.2.3.4.5.6
	// Req. Value: This is some kind of value
}
