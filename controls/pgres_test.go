package controls

import (
	"fmt"
)

func ExamplePagedResults_roundTripBER() {
	size, _ := NewInteger(1234)
	ctrl := PagedResults{
		Criticality: true,
		ControlValue: PagedResultsSearchValue{
			Size:   size,
			Cookie: OctetString(`some value`),
		},
	}

	enc, err := ctrl.Encode()
	if err != nil {
		fmt.Println(err)
		return
	}

	var dec PagedResults
	if err = dec.Decode(enc); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Type:        %q\n", dec.Type())
	fmt.Printf("Criticality: %t\n", dec.Critical())
	fmt.Printf("Value:       { Size: %d, Cookie: %q }\n",
		dec.ControlValue.Size.Native(),
		dec.ControlValue.Cookie)

	// Output:
	// Type:        "1.2.840.113556.1.4.319"
	// Criticality: true
	// Value:       { Size: 1234, Cookie: "some value" }
}
