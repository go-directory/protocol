package protocol

import (
	"fmt"
)

func ExampleAddRequest_roundTripBER() {
	req := AddRequest{
		Entry: LDAPDN(`uid=username,ou=accounts,o=acme`),
		Attributes: AttributeList{
			PartialAttribute{
				Type: AttributeDescription("uid"),
				Vals: []AttributeValue{
					AttributeValue("username"),
				},
			},
		},
	}

	enc, err := req.Encode()
	if err != nil {
		fmt.Println(err)
		return
	}

	var dec AddRequest
	if err = dec.Decode(enc); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("{ Entry: %q, Attributes: %s }\n", dec.Entry, dec.Attributes[0])
	// Output: { Entry: "uid=username,ou=accounts,o=acme", Attributes: {uid [username]} }
}

func ExampleAddResponse_roundTripBER() {
	res := AddResponse{
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

	var dec AddResponse
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
