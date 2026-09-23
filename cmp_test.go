package protocol

import (
	"fmt"
)

func ExampleCompareRequest_roundTripBER() {
	req := CompareRequest{
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

	var dec CompareRequest
	if err = dec.Decode(enc); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("{ Entry: %q, Assertion: %s=%s }\n", dec.Entry, dec.AVA.Desc, dec.AVA.Value)
	// Output: { Entry: "uid=username,ou=accounts,o=acme", Assertion: cn=Test }
}

func ExampleCompareResponse_roundTripBER() {
	res := CompareResponse{
		ResultCode:        Enumerated(66),
		MatchedDN:         LDAPDN("cn=Some Guy,ou=people,o=acme"),
		DiagnosticMessage: LDAPString("A diagnostic message goes here"),
		Referral: &Referral{
			URI(`ldap:///something`),
			URI(`ldap:///somethingElse`),
		},
	}

	enc, err := res.Encode()
	if err != nil {
		fmt.Println(err)
		return
	}

	var dec CompareResponse
	if err = dec.Decode(enc); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("ResultCode: %d\n", dec.ResultCode)
	fmt.Printf("MatchedDN:  %s\n", dec.MatchedDN)
	fmt.Printf("Message:    %q\n", dec.DiagnosticMessage)
	refs := (*dec.Referral)
	for i := 0; i < len(refs); i++ {
		fmt.Printf("Referral:   %s\n", refs[i])
	}
	// Output:
	// ResultCode: 66
	// MatchedDN:  cn=Some Guy,ou=people,o=acme
	// Message:    "A diagnostic message goes here"
	// Referral:   ldap:///something
	// Referral:   ldap:///somethingElse
}
