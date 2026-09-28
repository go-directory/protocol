package response

import (
	"fmt"
)

func ExampleIntermediate_roundTripBER() {
	name := LDAPOID(`1.2.3.4.5.6`)
	value := OctetString(`a value`)
	resp := Intermediate{
		ResponseName:  &name,
		ResponseValue: &value,
	}

	enc, err := resp.Encode()
	if err != nil {
		fmt.Println(err)
		return
	}

	var dec Intermediate
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
