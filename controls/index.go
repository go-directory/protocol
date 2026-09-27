package controls

/*
Control OIDs associated with [Control] definitions registered in this package.
*/
var (
	OIDPagedResults            = LDAPOID("1.2.840.113556.1.4.319")  // RFC2696
	OIDManageDsaIT             = LDAPOID("2.16.840.1.113730.3.4.2") // RFC3296
	OIDWhoAmI                  = LDAPOID("1.3.6.1.4.1.4203.1.11.3") // RFC4532
	OIDSubtreeDelete           = LDAPOID("1.2.840.113556.1.4.805")  // draft-armijo-ldap-treedelete
	OIDServerSideSorting       = LDAPOID("1.2.840.113556.1.4.473")  // RFC2891
	OIDServerSideSortingResult = LDAPOID("1.2.840.113556.1.4.474")  // RFC2891
)

/*
Names contains a numeric OID to friendly Control name table.
*/
var Names = map[string]string{
	OIDPagedResults.String():            "Paged Results Control",
	OIDManageDsaIT.String():             "Manage DSA IT Control",
	OIDWhoAmI.String():                  "Who Am I? Control",
	OIDSubtreeDelete.String():           "Subtree Delete Control",
	OIDServerSideSorting.String():       "Server Side Sorting Control",
	OIDServerSideSortingResult.String(): "Server Side Sorting Result Control",
}

// these decoders are called when decoding controls in iterations,
// particularly when we don't know what controls to expect.
var decoders = map[string]func([]byte) (Control, error){
	string(OIDPagedResults): func(x []byte) (c Control, err error) {
		var dec PagedResults
		err = dec.Decode(x)
		c = dec
		return
	},
	string(OIDManageDsaIT): func(x []byte) (c Control, err error) {
		var dec ManageDsaIT
		err = dec.Decode(x)
		c = dec
		return
	},
	string(OIDSubtreeDelete): func(_ []byte) (c Control, _ error) {
		c = SubtreeDelete{}
		return
	},
	string(OIDServerSideSorting): func(x []byte) (c Control, err error) {
		var dec ServerSideSorting
		err = dec.Decode(x)
		c = dec
		return
	},
}

/*
var (
        OIDBeheraPasswordPolicy = "1.3.6.1.4.1.42.2.27.8.5.1" // draft-behera-password-policy
        OIDVChuPasswordMustChange = "2.16.840.1.113730.3.4.4" // draft-vchu-ldap-pwd-policy
        OIDVChuPasswordWarning = "2.16.840.1.113730.3.4.5"    // draft-vchu-ldap-pwd-policy
)
*/

