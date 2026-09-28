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
