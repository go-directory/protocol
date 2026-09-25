package protocol

import (
	"fmt"
)

func ExampleEntry() {
	dn := LDAPDN(`cn=Some Person,ou=Employees,ou=Accounts,o=acme`)
	attrs := map[string][]string{
		`cn`:          {`Some Person`, `Some Distinguished Person`},
		`givenName`:   {`Some`},
		`sn`:          {`Person`},
		`c`:           {`US`},
		`st`:          {`Alaska`},
		`l`:           {`Nome`},
		`objectClass`: {`top`, `person`, `organizationalPerson`},
	}

	entry := NewEntry(dn, attrs)
	fmt.Printf("dn: %s\n", entry.DN)
	classes := entry.GetAttributeValues(AttributeDescription(`objectClass`)) // plain []byte is OK too
	fmt.Printf("objectClass: %v\n", classes)
	firstCN := entry.GetAttributeValue(AttributeDescription(`cn`))
	fmt.Printf("cn: %s\n", firstCN)
	// Output:
	// dn: cn=Some Person,ou=Employees,ou=Accounts,o=acme
	// objectClass: [top person organizationalPerson]
	// cn: Some Person
}

func ExampleSearchRequest_roundTripBER() {
	flt, _ := NewFilter(`(&(objectClass=person)(|(sn=Coretta)(sn=Tolana)))`)
	sizeLimit, _ := NewInteger(500)
	req := SearchRequest{
		BaseObject:   LDAPDN(`ou=people,o=acme`),
		Scope:        ScopeSingleLevel, // 1
		DerefAliases: DerefAlways,      // 3
		TypesOnly:    Boolean(true),
		SizeLimit:    sizeLimit,
		Filter:       flt,
		Attributes: AttributeSelection{
			LDAPString(`sn`),
			LDAPString(`2.5.4.3`), // "cn"
			LDAPString(`givenName`),
			LDAPString(`telephoneNumber`),
		},
	}

	enc, err := req.Encode()
	if err != nil {
		fmt.Println(err)
		return
	}

	var dec SearchRequest
	if err = dec.Decode(enc); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Base:       %q\n", dec.BaseObject)
	fmt.Printf("Scope:      %d\n", dec.Scope)
	fmt.Printf("Deref:      %d\n", dec.DerefAliases)
	fmt.Printf("SizeLimit:  %d\n", dec.SizeLimit.Native())
	fmt.Printf("Types Only: %t\n", dec.TypesOnly)
	fmt.Printf("Filter:     %s\n", dec.Filter)
	fmt.Printf("Attributes: %v\n", dec.Attributes)
	// Output:
	// Base:       "ou=people,o=acme"
	// Scope:      1
	// Deref:      3
	// SizeLimit:  500
	// Types Only: true
	// Filter:     (&(objectClass=person)(|(sn=Coretta)(sn=Tolana)))
	// Attributes: [sn 2.5.4.3 givenName telephoneNumber]
}

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
