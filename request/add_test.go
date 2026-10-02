package request

import (
	"fmt"
)

func ExampleAdd_assembly() {
	req := Add{
		Entry: LDAPDN(`uid=username,ou=accounts,o=acme`),
	}

	req.Attribute([]byte(`cn`), []byte(`Some Guy`), []byte(`Some Distinguished Guy`))

	fmt.Printf("dn: %s\n", req.Entry)
	fmt.Printf("cn: %s, %s\n", req.Attributes[0].Vals[0], req.Attributes[0].Vals[1])
	// Output:
	// dn: uid=username,ou=accounts,o=acme
	// cn: Some Guy, Some Distinguished Guy
}

func ExampleAdd_roundTripBER() {
	req := Add{
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

	var dec Add
	if err = dec.Decode(enc); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("{ Entry: %q, Attributes: %s }\n", dec.Entry, dec.Attributes[0])
	// Output: { Entry: "uid=username,ou=accounts,o=acme", Attributes: {uid [username]} }
}
