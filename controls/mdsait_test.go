package controls

import (
	"fmt"
)

func ExampleManageDsaIT_roundTripBER() {
	ctrl := ManageDsaIT{
		Criticality: true,
	}

	enc, err := ctrl.Encode()
	if err != nil {
		fmt.Println(err)
		return
	}

	var dec ManageDsaIT
	if err = dec.Decode(enc); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("{ Type: %q, Criticality: %t }\n",
		dec.Type(), dec.Critical())
	// Output: { Type: "2.16.840.1.113730.3.4.2", Criticality: true }
}
