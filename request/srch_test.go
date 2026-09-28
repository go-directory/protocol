package request

import (
	"fmt"
)

func ExampleSearch_roundTripBER() {
	flt, _ := NewFilter(`(&(objectClass=person)(|(sn=Coretta)(sn=Tolana)))`)
	sizeLimit, _ := NewInteger(500)
	req := Search{
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

	var dec Search
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
