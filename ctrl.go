package protocol

/*
ctrl.go serves as a bridge between the protocol package and the controls
package subdirectory.
*/

import (
	"github.com/go-directory/protocol/controls"
)

/*
Control implements [§ 4.1.11 of RFC4511] and serves as the slice type
in an instance of [Controls].

[§ 4.1.11 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.1.11
*/
type Control = controls.Control

/*
	SEQUENCE OF control Control

Controls implements [§ 4.1.11 of RFC4511], containing slices of individual [Control]
implementation type instances.

[§ 4.1.11 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.1.11
*/
type Controls = controls.Controls

/*
	Control ::= SEQUENCE {
		controlType  LDAPOID,
		criticality  BOOLEAN DEFAULT FALSE,
		controlValue OCTET STRING OPTIONAL }

ControlStandard implements the Control SEQUENCE, per [§ 4.1.11 of RFC4511]. Instances of
this type serve as a fallback measure for handling controls for which there is not a
dedicated type.

[§ 4.1.11 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.1.11
*/
type ControlStandard = controls.Standard

/*
ControlManageDsaIT implements [§ 3 of RFC3296] and is identified by the
controlType [OIDControlTypeManageDsaIT].

[§ 3 of RFC3296]: https://datatracker.ietf.org/doc/html/rfc3296#section-3
*/
type ControlManageDsaIT = controls.ManageDsaIT

/*
	pagedResultsControl ::= SEQUENCE {
	        controlType     1.2.840.113556.1.4.319,
	        criticality     BOOLEAN DEFAULT FALSE,
	        controlValue    searchControlValue }

ControlPagedResults implements [§ 2 of RFC2696] and is identified by the
controlType [OIDControlTypePagedResults]. Note that because the controlType is
fixed per the specification, the "ControlType" field is omitted from this
implementation. The encoding, however, must remain faithful to the above
ASN.1 definition.

[§ 2 of RFC2696]: https://datatracker.ietf.org/doc/html/rfc2696#section-2
*/
type ControlPagedResults = controls.PagedResults

/*
	ServerSideSorting ::= SEQUENCE {
	        controlType     LDAPOID,
	        criticality     BOOLEAN DEFAULT FALSE,
	        controlValue    SortKeyList }

	SortKeyList ::= SEQUENCE OF sortKey SortKey

	SortKey ::= SEQUENCE {
	        attributeType   AttributeDescription,
	        orderingRule    [0] MatchingRuleId OPTIONAL,
	        reverseOrder    [1] BOOLEAN DEFAULT FALSE }

ControlServerSideSorting implements [§ 1.1 of RFC2891], and is identified by the controlType
[OIDControlTypeServerSideSorting].

[§ 1.1 of RFC2891]: https://datatracker.ietf.org/doc/html/rfc2891#section-1.1
*/
type ControlServerSideSorting = controls.ServerSideSorting

/*
ControlSubtreeDelete implements the Subtree Delete Control, as defined in
[draft-armijo-ldap-treedelete] and is identified by the controlType
[OIDControlTypeSubtreeDelete].

[draft-armijo-ldap-treedelete]: https://datatracker.ietf.org/doc/html/draft-armijo-ldap-treedelete-02
*/
type ControlSubtreeDelete = controls.SubtreeDelete

/*
Control OIDs associated with [Control] definitions supported by this package.
*/
var (
	OIDControlTypePagedResults            = controls.OIDPagedResults            // RFC 2696
	OIDControlTypeManageDsaIT             = controls.OIDManageDsaIT             // RFC3296
	OIDControlTypeWhoAmI                  = controls.OIDWhoAmI                  // RFC4532
	OIDControlTypeSubtreeDelete           = controls.OIDSubtreeDelete           // draft-armijo-ldap-treedelete
	OIDControlTypeServerSideSorting       = controls.OIDServerSideSorting       // RFC2891
	OIDControlTypeServerSideSortingResult = controls.OIDServerSideSortingResult // RFC2891
)

/*
ControlNames contains a numeric OID to friendly Control name table.
*/
var ControlNames = controls.Names
