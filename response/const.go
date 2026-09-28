package response

const (
	TagBind                  = 1
	TagSearchResultEntry     = 4
	TagSearchResultDone      = 5
	TagModify                = 7
	TagAdd                   = 9
	TagDel                   = 11
	TagModifyDN              = 13
	TagCompare               = 15
	TagSearchResultReference = 19
	TagExtended              = 24
	TagIntermediate          = 25
)

/*
Response CHOICE names, as defined in [§ 4.1.1 of RFC4511].

[§ 4.1.1 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.1.1
*/
const (
	nameAddChoice                   = `addResponse`
	nameBindChoice                  = `bindResponse`
	nameCompareChoice               = `compareResponse`
	nameDelChoice                   = `delResponse`
	nameIntermediateChoice          = `intermediateResponse`
	nameExtendedChoice              = `extendedResp`
	nameModifyChoice                = `modifyResponse`
	nameModifyDNChoice              = `modDNResponse`
	nameSearchChoice                = `searchResponse`
	nameSearchResultEntryChoice     = `searchResEntry`
	nameSearchResultDoneChoice      = `searchResDone`
	nameSearchResultReferenceChoice = `searchResRef`
)
