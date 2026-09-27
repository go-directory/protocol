package controls

import (
	"fmt"
)

func ExampleStandard_roundTripBER() {
	ctrl := Standard{
		ControlType:  LDAPOID("1.2.3.4.5.6"),
		Criticality:  Boolean(true),
		ControlValue: OctetString("some optional value"),
	}

	enc, err := ctrl.Encode()
	if err != nil {
		fmt.Println(err)
		return
	}

	var dec Standard
	if err = dec.Decode(enc); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("{ Type: %q, Criticality: %t, Value: %s }\n",
		dec.Type(), dec.Critical(), dec.Value().Bytes)
	// Output: { Type: "1.2.3.4.5.6", Criticality: true, Value: some optional value }
}
