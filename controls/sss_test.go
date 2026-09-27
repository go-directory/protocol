package controls

import (
	"fmt"
)

func ExampleServerSideSorting_Value() {
	genTimeOrder := MatchingRuleID("generalizedTimeOrderingMatch")
	caseIgnore := MatchingRuleID("caseIgnoreOrderingMatch")
	ctrl := ServerSideSorting{
		Criticality: true,
		ControlValue: SortKeyList{
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

func ExampleServerSideSorting_roundTripBER() {
	genTimeOrder := MatchingRuleID("generalizedTimeOrderingMatch")
	caseIgnore := MatchingRuleID("caseIgnoreOrderingMatch")
	ctrl := ServerSideSorting{
		Criticality: true,
		ControlValue: SortKeyList{
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

	var dec ServerSideSorting
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
