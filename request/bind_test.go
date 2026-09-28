package request

import (
	"fmt"
)

func ExampleBind_roundTripBER() {
	vers, _ := NewInteger(1)
	name, _ := NewLDAPDN([]byte("uid=someone,ou=people,o=acme"))
	req := Bind{
		Version: vers,
		Name:    name,
		Authentication: SaslCredentials{
			Mechanism: LDAPString("EXTERNAL"),
		},
	}

	enc, err := req.Encode()
	if err != nil {
		fmt.Println(err)
		return
	}

	var dec Bind
	if err = dec.Decode(enc); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("{ Version: %s, Name: %q, Choice: %s }",
		dec.Version, dec.Name, dec.Authentication.Choice())
	// Output: { Version: 1, Name: "uid=someone,ou=people,o=acme", Choice: sasl }
}
