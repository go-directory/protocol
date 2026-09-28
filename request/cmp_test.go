package request

import (
	"fmt"
)

func ExampleCompare_roundTripBER() {
	req := Compare{
		Entry: LDAPDN(`uid=username,ou=accounts,o=acme`),
		AVA: AttributeValueAssertion{
			Desc:  AttributeDescription("cn"),
			Value: AssertionValue("Test"),
		},
	}

	enc, err := req.Encode()
	if err != nil {
		fmt.Println(err)
		return
	}

	var dec Compare
	if err = dec.Decode(enc); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("{ Entry: %q, Assertion: %s=%s }\n", dec.Entry, dec.AVA.Desc, dec.AVA.Value)
	// Output: { Entry: "uid=username,ou=accounts,o=acme", Assertion: cn=Test }
}
