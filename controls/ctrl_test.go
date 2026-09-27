package controls

import (
	"fmt"
)

func ExampleControls_roundTripBER() {
	ctrls := Controls{
		Standard{
			ControlType:  LDAPOID("1.2.3.4.5.6"),
			Criticality:  true,
			ControlValue: OctetString("some optional value"),
		},
		SubtreeDelete{},
	}

	enc, err := ctrls.Encode()
	if err != nil {
		fmt.Println(err)
		return
	}

	var dec Controls
	if err = dec.Decode(enc); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("{ Type: %q, Criticality: %t, Value: %q }\n",
		dec[0].Type(), dec[0].Critical(), dec[0].Value().Bytes)
	fmt.Printf("{ Type: %q }\n", dec[1].Type())
	// Output:
	// { Type: "1.2.3.4.5.6", Criticality: true, Value: "some optional value" }
	// { Type: "1.2.840.113556.1.4.805" }
}
