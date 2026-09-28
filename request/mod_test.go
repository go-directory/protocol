package request

import (
	"fmt"
)

func ExampleModify_assembly() {
	req := Modify{Object: LDAPDN(`uid=username,ou=accounts,o=acme`)}

	// quick AttributeDescription and AttributeValue "casters" for readability
	ad := func(x string) AttributeDescription { return AttributeDescription(x) }
	av := func(x string) AttributeValue { return AttributeValue(x) }

	// Add two 'cn' values
	req.Add(ad(`cn`),
		av(`Some Guy`),
		av(`Some Distinguished Guy`))

	// replace current title with a new one
	req.Replace(ad(`title`), av(`Bottom Feeder`))

	// Delete every telephoneNumber from this entry
	req.Delete(ad(`telephoneNumber`))

	// Delete a specific mobile number from this entry
	req.Delete(ad(`mobile`), av(`+1 555 555 1234`))

	// Quick-and-dirty LDIF approximation
	fmt.Printf("dn: %s\n", req.Object)
	fmt.Printf("changetype: modify\n")
	fmt.Printf("add: %s\n", req.Changes[0].Modification.Type)
	fmt.Printf("%s: %s\n", req.Changes[0].Modification.Type,
		req.Changes[0].Modification.Vals[0])
	fmt.Printf("%s: %s\n", req.Changes[0].Modification.Type,
		req.Changes[0].Modification.Vals[1])
	fmt.Printf("-\n")
	fmt.Printf("replace: %s\n", req.Changes[1].Modification.Type)
	fmt.Printf("%s: %s\n", req.Changes[1].Modification.Type,
		req.Changes[1].Modification.Vals[0])
	fmt.Printf("-\n")
	fmt.Printf("delete: %s\n", req.Changes[2].Modification.Type)
	fmt.Printf("-\n")
	fmt.Printf("delete: %s\n", req.Changes[3].Modification.Type)
	fmt.Printf("%s: %s\n", req.Changes[3].Modification.Type,
		req.Changes[3].Modification.Vals[0])

	// Output:
	// dn: uid=username,ou=accounts,o=acme
	// changetype: modify
	// add: cn
	// cn: Some Guy
	// cn: Some Distinguished Guy
	// -
	// replace: title
	// title: Bottom Feeder
	// -
	// delete: telephoneNumber
	// -
	// delete: mobile
	// mobile: +1 555 555 1234
}

func ExampleModify_roundTripBER() {
	req := Modify{
		Object: LDAPDN("uid=username,ou=accounts,o=acme"),
		Changes: []ModifyChange{
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

	var dec Modify
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
