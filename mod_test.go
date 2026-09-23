package protocol

import (
	"fmt"
)

func ExampleModifyRequest_roundTripBER() {
	req := ModifyRequest{
		Object: LDAPDN("uid=username,ou=accounts,o=acme"),
		Changes: []ModifyRequestChange{
			{
				Operation: 0, // add
				Modification: PartialAttribute{
					Type: AttributeDescription("cn"),
					Vals: []AttributeValue{
						AttributeValue("Some Guy"),
						AttributeValue("Some T. Guy"),
					},
				},
			},
		},
	}

	enc, err := req.Encode()
	if err != nil {
		fmt.Println(err)
		return
	}

	var dec ModifyRequest
	if err = dec.Decode(enc); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Object:     %s\n", dec.Object)
	fmt.Printf("ChangeType: %d\n", dec.Changes[0].Operation)
	fmt.Printf("Attribute:  %s\n", dec.Changes[0].Modification.Type)
	fmt.Printf("Values:     %s\n", dec.Changes[0].Modification.Vals)
	// Output:
	// Object:     uid=username,ou=accounts,o=acme
	// ChangeType: 0
	// Attribute:  cn
	// Values:     [Some Guy Some T. Guy]

}

func ExampleModifyResponse_roundTripBER() {
	res := ModifyResponse{
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

	var dec ModifyResponse
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
