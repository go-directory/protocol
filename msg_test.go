package protocol

import (
	"fmt"
)

func ExampleLDAPMessage_addRequestRoundTripBER() {
	req := AddRequest{
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

	msg := NewLDAPMessage()
	msg.MessageID = 1763
	msg.ProtocolOp = req
	msg.Controls = &Controls{
		ControlStandard{
			ControlType:  []byte(`1.2.3.4.5.6`),
			Criticality:  true,
			ControlValue: []byte(`1234567890`),
		},
	}

	enc, err := msg.Encode()
	if err != nil {
		fmt.Println(err)
		return
	}

	var dec LDAPMessage
	if err = dec.Decode(enc); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("MessageID:    %d\n", dec.MessageID)
	fmt.Printf("Target DN:    %q\n", dec.ProtocolOp.(AddRequest).Entry)
	fmt.Printf("ControlType:  %s\n", (*dec.Controls)[0].Type())
	fmt.Printf("Criticality:  %t\n", (*dec.Controls)[0].Critical())
	fmt.Printf("ControlValue: %s\n", (*dec.Controls)[0].Value().Bytes)
	// Output:
	// MessageID:    1763
	// Target DN:    "uid=username,ou=accounts,o=acme"
	// ControlType:  1.2.3.4.5.6
	// Criticality:  true
	// ControlValue: 1234567890
}

func ExampleLDAPMessage_delRequestRoundTripBER() {
	req := DelRequest("uid=username,ou=accounts,o=acme")

	msg := NewLDAPMessage()
	msg.MessageID = 1763
	msg.ProtocolOp = req
	msg.Controls = &Controls{
		ControlStandard{
			ControlType:  []byte(`1.2.3.4.5.6`),
			Criticality:  true,
			ControlValue: []byte(`1234567890`),
		},
	}

	enc, err := msg.Encode()
	if err != nil {
		fmt.Println(err)
		return
	}

	var dec LDAPMessage
	if err = dec.Decode(enc); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("MessageID:    %d\n", dec.MessageID)
	fmt.Printf("Target DN:    %q\n", dec.ProtocolOp.(DelRequest))
	fmt.Printf("ControlType:  %s\n", (*dec.Controls)[0].Type())
	fmt.Printf("Criticality:  %t\n", (*dec.Controls)[0].Critical())
	fmt.Printf("ControlValue: %s\n", (*dec.Controls)[0].Value().Bytes)
	// Output:
	// MessageID:    1763
	// Target DN:    "uid=username,ou=accounts,o=acme"
	// ControlType:  1.2.3.4.5.6
	// Criticality:  true
	// ControlValue: 1234567890
}

func ExampleLDAPMessage_modifyRequestRoundTripBER() {
	req := ModifyRequest{
		Object: LDAPDN(`uid=username,ou=accounts,o=acme`),
		Changes: []ModifyRequestChange{
			{
				Operation: 0,
				Modification: PartialAttribute{
					Type: AttributeDescription("cn"),
					Vals: []AttributeValue{
						AttributeValue("Some T. Guy, III"),
						AttributeValue("Some Guy"),
					},
				},
			},
			{
				Operation: 2,
				Modification: PartialAttribute{
					Type: AttributeDescription("sn"),
					Vals: []AttributeValue{
						AttributeValue("New Surname"),
					},
				},
			},
		},
	}

	msg := NewLDAPMessage()
	msg.MessageID = 1763
	msg.ProtocolOp = req
	msg.Controls = &Controls{
		ControlStandard{
			ControlType:  []byte(`1.2.3.4.5.6`),
			Criticality:  true,
			ControlValue: []byte(`1234567890`),
		},
	}

	enc, err := msg.Encode()
	if err != nil {
		fmt.Println(err)
		return
	}

	var dec LDAPMessage
	if err = dec.Decode(enc); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("MessageID:\t\t%d\n", dec.MessageID)
	fmt.Printf("Target DN:\t\t%q\n", dec.ProtocolOp.(ModifyRequest).Object)

	attrs := dec.ProtocolOp.(ModifyRequest).Changes
	for i := 0; i < len(attrs); i++ {
		fmt.Printf("Change[%d]:\t\tType: %q, Vals: %s\n",
			i, attrs[i].Modification.Type,
			attrs[i].Modification.Vals)
	}
	fmt.Printf("Control:\n")
	fmt.Printf("  - Type:\t\t%s\n", (*dec.Controls)[0].Type())
	fmt.Printf("  - Critical:\t%t\n", (*dec.Controls)[0].Critical())
	fmt.Printf("  - Value:\t\t%s\n", (*dec.Controls)[0].Value().Bytes)
	// Output:
	// MessageID:		1763
	// Target DN:		"uid=username,ou=accounts,o=acme"
	// Change[0]:		Type: "cn", Vals: [Some T. Guy, III Some Guy]
	// Change[1]:		Type: "sn", Vals: [New Surname]
	// Control:
	//   - Type:		1.2.3.4.5.6
	//   - Critical:	true
	//   - Value:		1234567890

}
