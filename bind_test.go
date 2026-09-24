package protocol

import (
	"fmt"
	"testing"
)

func ExampleBindRequest_roundTripBER() {
	vers, _ := NewInteger(1)
	name, _ := NewLDAPDN([]byte("uid=someone,ou=people,o=acme"))
	req := BindRequest{
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

	var dec BindRequest
	if err = dec.Decode(enc); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("{ Version: %s, Name: %q, Choice: %s }",
		dec.Version, dec.Name, dec.Authentication.Choice())
	// Output: { Version: 1, Name: "uid=someone,ou=people,o=acme", Choice: sasl }
}

func ExampleBindResponse_roundTripBER() {
	creds := OctetString(`someSecretString`)
	res := BindResponse{
		LDAPResult: LDAPResult{
			ResultCode:        Enumerated(66),                               //
			MatchedDN:         LDAPDN("cn=Some Guy,ou=people,o=acme"),       //
			DiagnosticMessage: LDAPString("A diagnostic message goes here"), // COMPONENTS OF LDAPResult
			Referral: &Referral{ //
				URI(`ldap:///something`),     //
				URI(`ldap:///somethingElse`), //
			},
		},
		ServerSaslCreds: &creds,
	}

	enc, err := res.Encode()
	if err != nil {
		fmt.Println(err)
		return
	}

	var dec BindResponse
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
	fmt.Printf("SaslCreds:  %s\n", dec.ServerSaslCreds)
	// Output:
	// ResultCode: 66
	// MatchedDN:  cn=Some Guy,ou=people,o=acme
	// Message:    "A diagnostic message goes here"
	// Referral:   ldap:///something
	// Referral:   ldap:///somethingElse
	// SaslCreds:  someSecretString
}

func BenchmarkBindResponse(b *testing.B) {
	creds := OctetString(`someSecretString`)
	res := BindResponse{
		LDAPResult: LDAPResult{
			ResultCode:        Enumerated(66),
			MatchedDN:         LDAPDN("cn=Some Guy,ou=people,o=acme"),
			DiagnosticMessage: LDAPString("A diagnostic message goes here"),
			Referral: &Referral{
				URI(`ldap:///something`),
				URI(`ldap:///somethingElse`),
			},
		},
		ServerSaslCreds: &creds,
	}

	b.StopTimer()
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		out, _ := res.Encode()
		var dec BindResponse
		_ = dec.Decode(out)
	}
}
