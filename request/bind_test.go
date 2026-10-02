package request

import (
	"fmt"
)

func ExampleSimpleBind() {
	req := SimpleBind(
		[]byte("uid=someone,ou=people,o=acme"), // BindDN
		[]byte("coolP@$$werd"))                 // BindPW

	fmt.Printf("{ Version: %s, Name: %q, Choice: %s }",
		req.Version, req.Name, req.Authentication.Choice())
	// Output: { Version: 3, Name: "uid=someone,ou=people,o=acme", Choice: simple }
}

func ExampleBind_roundTripBER() {
	name, _ := NewLDAPDN([]byte("uid=someone,ou=people,o=acme"))
	req := Bind{
		Name: name,
		Authentication: SaslCredentials{
			Mechanism: LDAPString("EXTERNAL"),
		},
	}
	req.SetVersion(3)

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
	// Output: { Version: 3, Name: "uid=someone,ou=people,o=acme", Choice: sasl }
}
