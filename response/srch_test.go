package response

import (
	"fmt"
)

func ExampleSearchResultEntry_roundTripBER() {
	res := SearchResultEntry{
		ObjectName: LDAPDN("cn=someObject,o=acme"),
		Attributes: PartialAttributeList{
			{
				Type: AttributeDescription("cn"),
				Vals: []AttributeValue{
					AttributeValue("someObject"),
				},
			},
		},
	}

	enc, err := res.Encode()
	if err != nil {
		fmt.Println(err)
		return
	}

	var dec SearchResultEntry
	if err = dec.Decode(enc); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Object:     %q\n", dec.ObjectName)
	fmt.Printf("Attributes:\n")
	fmt.Printf(" - Type: %s, Vals: %v\n", dec.Attributes[0].Type, dec.Attributes[0].Vals)
	// Output:
	// Object:     "cn=someObject,o=acme"
	// Attributes:
	//  - Type: cn, Vals: [someObject]
}

func ExampleSearchResultDone_roundTripBER() {
	// returned after a doomed search for the entry
	// "cn=Some Nonexistent Guy,ou=People,o=acme"
	done := SearchResultDone{
		ResultCode:        Enumerated(32),
		MatchedDN:         LDAPDN("ou=people,o=acme"),
		DiagnosticMessage: LDAPString("Did you take your brain medicine today?"),
		Referral: &Referral{
			URI(`ldap:///something`),
			URI(`ldap:///somethingElse`),
		},
	}

	enc, err := done.Encode()
	if err != nil {
		fmt.Println(err)
		return
	}

	var dec SearchResultDone
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
	// ResultCode: 32
	// MatchedDN:  ou=people,o=acme
	// Message:    "Did you take your brain medicine today?"
	// Referral:   ldap:///something
	// Referral:   ldap:///somethingElse
}

func ExampleSearchResultReference_roundTripBER() {
	srr := SearchResultReference{
		URI(`ldap:///something`),
		URI(`ldap:///somethingElse`),
	}

	enc, err := srr.Encode()
	if err != nil {
		fmt.Println(err)
		return
	}

	var dec SearchResultReference
	if err = dec.Decode(enc); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%v", dec)
	// Output: [ldap:///something ldap:///somethingElse]
}
