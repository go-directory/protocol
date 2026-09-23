package protocol

import (
	"fmt"
)

func ExampleModifyDNRequest_roundTripBER() {
	newSup := LDAPDN("ou=people,o=acme")
	req := ModifyDNRequest{
		Entry:        LDAPDN("uid=username,ou=accounts,o=acme"),
		NewRDN:       RelativeLDAPDN("cn=Proper Name"),
		DeleteOldRDN: false,
		NewSuperior:  &newSup,
	}

	enc, err := req.Encode()
	if err != nil {
		fmt.Println(err)
		return
	}

	var dec ModifyDNRequest
	if err = dec.Decode(enc); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Entry:     %s\n", dec.Entry)
	fmt.Printf("NewRDN:    %s\n", dec.NewRDN)
	fmt.Printf("DelOldRDN: %t\n", dec.DeleteOldRDN)
	fmt.Printf("NewSup:    %s\n", dec.NewSuperior)
	// Output:
	// Entry:     uid=username,ou=accounts,o=acme
	// NewRDN:    cn=Proper Name
	// DelOldRDN: false
	// NewSup:    ou=people,o=acme
}

func ExampleModifyDNResponse_roundTripBER() {
	res := ModifyDNResponse{
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

	var dec ModifyDNResponse
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
