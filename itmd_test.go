package protocol

import (
	"fmt"
)

func ExampleIntermediateResponse_roundTripBER() {
	name := LDAPOID(`1.2.3.4.5.6`)
	value := OctetString(`a value`)
	resp := IntermediateResponse{
		ResponseName:  &name,
		ResponseValue: &value,
	}

	enc, err := resp.Encode()
	if err != nil {
		fmt.Println(err)
		return
	}

	var dec IntermediateResponse
	if err = dec.Decode(enc); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Name:  %s\n", dec.ResponseName)
	fmt.Printf("Value: %q\n", dec.ResponseValue)
	// Output:
	// Name:  1.2.3.4.5.6
	// Value: "a value"
}
