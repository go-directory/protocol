package controls

import (
	"fmt"
)

func ExampleSubentries_roundTripBER() {
	ctrl := Subentries(true)
	enc, err := ctrl.Encode()
	if err != nil {
		fmt.Println(err)
		return
	}

	var dec Subentries
	if err = dec.Decode(enc); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Type:            %q\n", dec.Type())
	fmt.Printf("Show Subentries: %t\n", dec)

	// Output:
	// Type:            "1.3.6.1.4.1.4203.1.10.1"
	// Show Subentries: true
}
