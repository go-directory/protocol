package protocol

import (
	"fmt"
)

func ExampleControlStandard_roundTripBER() {
	ctrl := ControlStandard{
		ControlType:  LDAPOID("1.2.3.4.5.6"),
		Criticality:  Boolean(true),
		ControlValue: OctetString("some optional value"),
	}

	enc, err := ctrl.Encode()
	if err != nil {
		fmt.Println(err)
		return
	}

	var dec ControlStandard
	if err = dec.Decode(enc); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("{ Type: %q, Criticality: %t, Value: %s }\n",
		dec.Type(), dec.Critical(), dec.Value().Bytes)
	// Output: { Type: "1.2.3.4.5.6", Criticality: true, Value: some optional value }
}

func ExampleControlManageDsaIT_roundTripBER() {
	ctrl := ControlManageDsaIT{
		Criticality: true,
	}

	enc, err := ctrl.Encode()
	if err != nil {
		fmt.Println(err)
		return
	}

	var dec ControlManageDsaIT
	if err = dec.Decode(enc); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("{ Type: %q, Criticality: %t }\n",
		dec.Type(), dec.Critical())
	// Output: { Type: "2.16.840.1.113730.3.4.2", Criticality: true }
}

func ExampleControlPagedResults_roundTripBER() {
	size, _ := NewInteger(1234)
	ctrl := ControlPagedResults{
		Criticality: true,
		ControlValue: ControlPagedResultsSearchValue{
			Size:   size,
			Cookie: OctetString(`some value`),
		},
	}

	enc, err := ctrl.Encode()
	if err != nil {
		fmt.Println(err)
		return
	}

	var dec ControlPagedResults
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

func ExampleControlServerSideSorting_Value() {
	genTimeOrder := MatchingRuleID("generalizedTimeOrderingMatch")
	caseIgnore := MatchingRuleID("caseIgnoreOrderingMatch")
	ctrl := ControlServerSideSorting{
		Criticality: true,
		ControlValue: ControlSortKeyList{
			{
				AttributeType: AttributeDescription("createTimestamp"),
				OrderingRule:  &genTimeOrder,
				ReverseOrder:  false,
			},
			{
				AttributeType: AttributeDescription("dnQualifier"),
				OrderingRule:  &caseIgnore,
				ReverseOrder:  true,
			},
		},
	}

	raw := ctrl.Value()
	fmt.Printf("Raw Value:\n")
	fmt.Printf(" - Class:%d, Constructed:%t, Tag:%d\n",
		raw.Tag.Class, raw.Tag.Constructed, raw.Tag.Tag)
	fmt.Printf(" - Bytes:      %v\n", raw.Bytes)
	fmt.Printf(" - Full Bytes: %v\n", raw.FullBytes)

	// Output:
	// Raw Value:
	//  - Class:0, Constructed:true, Tag:16
	//  - Bytes:      [48 50 4 15 99 114 101 97 116 101 84 105 109 101 115 116 97 109 112 4 28 103 101 110 101 114 97 108 105 122 101 100 84 105 109 101 79 114 100 101 114 105 110 103 77 97 116 99 104 1 1 0 48 41 4 11 100 110 81 117 97 108 105 102 105 101 114 4 23 99 97 115 101 73 103 110 111 114 101 79 114 100 101 114 105 110 103 77 97 116 99 104 1 1 255]
	//  - Full Bytes: [48 95 48 50 4 15 99 114 101 97 116 101 84 105 109 101 115 116 97 109 112 4 28 103 101 110 101 114 97 108 105 122 101 100 84 105 109 101 79 114 100 101 114 105 110 103 77 97 116 99 104 1 1 0 48 41 4 11 100 110 81 117 97 108 105 102 105 101 114 4 23 99 97 115 101 73 103 110 111 114 101 79 114 100 101 114 105 110 103 77 97 116 99 104 1 1 255]
}

func ExampleControlServerSideSorting_roundTripBER() {
	genTimeOrder := MatchingRuleID("generalizedTimeOrderingMatch")
	caseIgnore := MatchingRuleID("caseIgnoreOrderingMatch")
	ctrl := ControlServerSideSorting{
		Criticality: true,
		ControlValue: ControlSortKeyList{
			{
				AttributeType: AttributeDescription("createTimestamp"),
				OrderingRule:  &genTimeOrder,
				ReverseOrder:  false,
			},
			{
				AttributeType: AttributeDescription("dnQualifier"),
				OrderingRule:  &caseIgnore,
				ReverseOrder:  true,
			},
		},
	}

	enc, err := ctrl.Encode()
	if err != nil {
		fmt.Println(err)
		return
	}

	var dec ControlServerSideSorting
	if err = dec.Decode(enc); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Type:     %q\n", dec.Type())
	fmt.Printf("Critical: %t\n", dec.Critical())
	fmt.Printf("Sorted Attributes:\n")
	for i := 0; i < len(dec.ControlValue); i++ {
		fmt.Printf(" - %s (%s) [reverse:%t]\n",
			dec.ControlValue[i].AttributeType,
			dec.ControlValue[i].OrderingRule,
			dec.ControlValue[i].ReverseOrder)
	}

	// Output:
	// Type:     "1.2.840.113556.1.4.473"
	// Critical: true
	// Sorted Attributes:
	//  - createTimestamp (generalizedTimeOrderingMatch) [reverse:false]
	//  - dnQualifier (caseIgnoreOrderingMatch) [reverse:true]
}

func ExampleControls_roundTripBER() {
	ctrls := Controls{
		ControlStandard{
			ControlType:  LDAPOID("1.2.3.4.5.6"),
			Criticality:  true,
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
		dec[0].Type(), dec[0].Critical(), dec[0].Value().Bytes)
	// Output: { Type: "1.2.3.4.5.6", Criticality: true, Value: some optional value }
}
