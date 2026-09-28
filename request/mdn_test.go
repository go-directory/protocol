package request

import (
	"fmt"
)

func ExampleModifyDN_options() {
	dn := LDAPDN("uid=username,ou=accounts,o=acme")

	// Only *move* our entry
	newSup := LDAPDN("ou=people,o=acme")
	move := MoveEntry(dn, newSup)

	// Only *rename* our entry
	newRDN := RelativeLDAPDN("uid=coolUsername")
	rename := RenameEntry(dn, newRDN) // keep old RDN values
	//rename := RenameEntry(dn, newRDN, true) // delete old RDN values

	// Rename *and* move our entry
	both := RenameAndMoveEntry(dn, newSup, newRDN) // keep old RDN values
	//both := RenameAndMoveEntry(dn, newSup, newRDN, true) // delete old RDN values

	fmt.Printf("Move only::\n")
	fmt.Printf("dn: %s\n", move.Entry)
	fmt.Printf("newSup: %s\n", move.NewSuperior)
	fmt.Printf("newRDN: %s\n\n", move.NewRDN) // current RDN remains unchanged

	fmt.Printf("Rename only::\n")
	fmt.Printf("dn: %s\n", rename.Entry)
	fmt.Printf("newRDN: %s\n\n", rename.NewRDN)

	fmt.Printf("Rename and move::\n")
	fmt.Printf("dn: %s\n", both.Entry)
	fmt.Printf("newSup: %s\n", both.NewSuperior)
	fmt.Printf("newRDN: %s\n\n", both.NewRDN)

	// Output:
	// Move only::
	// dn: uid=username,ou=accounts,o=acme
	// newSup: ou=people,o=acme
	// newRDN: uid=username
	//
	// Rename only::
	// dn: uid=username,ou=accounts,o=acme
	// newRDN: uid=coolUsername
	//
	// Rename and move::
	// dn: uid=username,ou=accounts,o=acme
	// newSup: ou=people,o=acme
	// newRDN: uid=coolUsername
}

func ExampleModifyDN_roundTripBER() {
	newSup := LDAPDN("ou=people,o=acme")
	req := ModifyDN{
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

	var dec ModifyDN
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
