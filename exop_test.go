package protocol

import (
	"fmt"
)

func ExampleExtendedRequest_roundTripBER() {
	reqVal := OctetString("This is some kind of value")
	req := ExtendedRequest{
		RequestName:  LDAPOID(`1.2.3.4.5.6`),
		RequestValue: &reqVal,
	}

	enc, err := req.Encode()
	if err != nil {
		fmt.Println(err)
		return
	}

	var dec ExtendedRequest
	if err = dec.Decode(enc); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Req. Name:  %s\n", dec.RequestName)
	fmt.Printf("Req. Value: %s\n", dec.RequestValue)
	// Output:
	// Req. Name:  1.2.3.4.5.6
	// Req. Value: This is some kind of value
}

func ExampleExtendedResponse_roundTripBER() {
	name := LDAPOID(`1.2.3.4.5.6`)
	value := OctetString("a value")
	res := ExtendedResponse{
		LDAPResult: LDAPResult{
			ResultCode:        Enumerated(66),
			MatchedDN:         LDAPDN("cn=Some Guy,ou=people,o=acme"),
			DiagnosticMessage: LDAPString("A diagnostic message goes here"),
			Referral: &Referral{
				URI(`ldap:///something`),
				URI(`ldap:///somethingElse`),
			},
		},
		ResponseName:  &name,
		ResponseValue: &value,
	}

	enc, err := res.Encode()
	if err != nil {
		fmt.Println(err)
		return
	}

	var dec ExtendedResponse
	if err = dec.Decode(enc); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("ResultCode: %d\n", dec.ResultCode)
	fmt.Printf("MatchedDN:  %s\n", dec.MatchedDN)
	fmt.Printf("Message:    %q\n", dec.DiagnosticMessage)
	refs := (*dec.Referral)
	fmt.Printf("Referrals:\n")
	for i := 0; i < len(refs); i++ {
		fmt.Printf(" - URI:   %s\n", refs[i])
	}
	fmt.Printf("Response:\n")
	fmt.Printf(" - Name:  %s\n", dec.ResponseName)
	fmt.Printf(" - Value: %q\n", dec.ResponseValue)
	// Output:
	// ResultCode: 66
	// MatchedDN:  cn=Some Guy,ou=people,o=acme
	// Message:    "A diagnostic message goes here"
	// Referrals:
	//  - URI:   ldap:///something
	//  - URI:   ldap:///somethingElse
	// Response:
	//  - Name:  1.2.3.4.5.6
	//  - Value: "a value"
}
