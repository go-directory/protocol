package request

/*
Request tabgs.  Note that all of these are bound to the APPLICATION
ASN.1 class, and not CONTEXT-SPECIFIC.

For example, for [TagModify] (6), it appears in definitions as:

	ModifyRequest ::= [APPLICATION 6] SEQUENCE ....
*/
const (
	TagBind     = 0
	TagUnbind   = 2
	TagSearch   = 3
	TagModify   = 6
	TagAdd      = 8
	TagDel      = 10
	TagModifyDN = 12
	TagCompare  = 14
	TagAbandon  = 16
	TagExtended = 23
)

/*
Request CHOICE names, as defined in [§ 4.1.1 of RFC4511].

[§ 4.1.1 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.1.1
*/
const (
	nameAbandonChoice  = `abandonRequest`
	nameAddChoice      = `addRequest`
	nameBindChoice     = `bindRequest`
	nameCompareChoice  = `compareRequest`
	nameDelChoice      = `delRequest`
	nameExtendedChoice = `extendedReq`
	nameModifyChoice   = `modifyRequest`
	nameModifyDNChoice = `modDNRequest`
	nameSearchChoice   = `searchRequest`
	nameUnbindChoice   = `unbindRequest`
)
