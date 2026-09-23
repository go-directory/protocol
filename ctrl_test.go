package protocol

import (
	"fmt"
)

func ExampleControl_roundTripBER() {
	ctrl := Control{
		ControlType:  LDAPOID("1.2.3.4.5.6"),
		Criticality:  Boolean(true),
		ControlValue: OctetString("some optional value"),
	}

	enc, err := ctrl.Encode()
	if err != nil {
		fmt.Println(err)
		return
	}

	var dec Control
	if err = dec.Decode(enc); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("{ Type: %q, Criticality: %t, Value: %s }\n",
		dec.ControlType, dec.Criticality, dec.ControlValue)
	// Output: { Type: "1.2.3.4.5.6", Criticality: true, Value: some optional value }
}

func ExampleControls_roundTripBER() {
	ctrls := Controls{
		{
			ControlType:  LDAPOID("1.2.3.4.5.6"),
			Criticality:  Boolean(true),
			ControlValue: OctetString("some optional value"),
		},
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

	fmt.Printf("{ Type: %q, Criticality: %t, Value: %s }\n",
		dec[0].ControlType, dec[0].Criticality, dec[0].ControlValue)
	// Output: { Type: "1.2.3.4.5.6", Criticality: true, Value: some optional value }
}

func ExampleNewControl() {
	// new critical control with no values
	ctrl, err := NewControl("1.2.3.4.5.6", true, "a value")
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Type:     %s\n", ctrl.ControlType)
	fmt.Printf("Critical: %t\n", ctrl.Criticality)
	fmt.Printf("Value:    %q\n", ctrl.ControlValue)
	// Output:
	// Type:     1.2.3.4.5.6
	// Critical: true
	// Value:    "a value"
}
