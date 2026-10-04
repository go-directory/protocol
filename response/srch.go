package response

import (
	"github.com/go-directory/protocol/controls"
)

/*
SearchResponse defines a convenient [Response] subset, and is meant to
operate based on delivered [SearchResultEntry], [SearchResultReference]
and [SearchResultDone] [LDAPResult] payloads. This type does not extend
from any formal standard and is implemented here merely as a supplement
of the DUA.

Concrete implementations of this interface are [SearchSyncResult] and
[SearchAsyncResult] for synchronous or asynchronous requests respectively.
*/
type SearchResponse interface {
	// Encode serves no useful purpose, and exists only to satisfy
	// Go's interface signature requirements with respect to the
	// Response interface type.
	Encode() ([]byte, error)

	// Decode serves no useful purpose, and exists only to satisfy
	// Go's interface signature requirements with respect to the
	// ProtocolOp and Response interface types.
	Decode([]byte) error

	// Choice returns a useless string literal. This method exists
	// solely to satisfy Go's interface signature requirements with
	// respect to the ProtocolOp and Response interface types.
	Choice() string

	// Kind returns a string literal of "sync" (for synchronous
	// searches) and "async" (for asynchronous searches).
	Kind() string

	// Tag serves no useful purpose, and exists only to satisfy
	// Go's interface signature requirements with respect to the
	// ProtocolOp and Response interface types.
	Tag() int

	// Entry is called by the client when the polling
	// retrieved entries asynchronously. Any Subsequent call of this
	// method are contingent upon the SearchAsyncResult.Next method
	// returning a value of true.
	Entry() *SearchResultEntry

	// SearchResultReference contains slices of URI values, each
	// representing a referral returned by the DSA.
	Reference() *SearchResultReference

	// SearchResultDone circumscribes an instance of LDAPResult,
	// and serves as an indicator as to whether the search was
	// completed successfully and, if not, what result codes were
	// returned by the DSA.
	Done() *SearchResultDone

	// Controls returns an instance of Controls, containing zero (0)
	// or more Control SEQUENCE instances the DSA has returned while
	// search operations are underway.
	Controls() Controls

	// Error returns an error, or nil if no error has been raised.
	// This method only applies to SearchAsyncResult instances,
	// and will always return nil when called via SearchSyncResult
	// instances.
	Error() error

	// Next returns a Boolean value indicative of a successful
	// advancement of the underlying "entry cursor". When a value
	// of true is returned, this indicates there is at least one
	// more SearchResultEntry ready for receipt. When false, this
	// means SearchResultDone was received, or that there was an
	// unrecoverable error of some kind during receipt of entries.
	//
	// Note this method is only meaningful for SearchAsyncResult
	// instances. It will always return false via SearchSyncResult
	// instance calls.
	Next() bool

	IsProtocolOp() // marker method
	IsResponseOp() // marker method
}

// go-directory/protocol/controls alias type.
type (
	Control  = controls.Control
	Controls = controls.Controls
)

/*
SearchAsyncResult is a [Response] implementation type intended for
use as a return value following an asynchronous search request.
*/
type SearchAsyncResult struct {
	ctrls    Controls
	referral *SearchResultReference

	asyncE chan *SearchResultEntry
	entry  *SearchResultEntry
	done   *SearchResultDone
	err    error
}

/*
Encode returns a nil []byte instance alongside an error. This method serves no
useful purpose and only exists to satify Go's interface signature requirements
with respect to the [Response] and [SearchResponse] interface types.
*/
func (_ SearchAsyncResult) Encode() ([]byte, error) { return nil, nil }

/*
Decode returns a nil error. This method serves no useful purpose and only exists
to satify Go's interface signature requirements with respect to the [Response]
and [SearchResponse] interface types.
*/
func (_ SearchAsyncResult) Decode(enc []byte) error            { return nil }
func (_ SearchAsyncResult) Tag() int                           { return -1 }
func (_ SearchAsyncResult) classTag() Tag                      { return Tag{} }
func (_ SearchAsyncResult) Kind() string                       { return `async` } // asynchronous
func (_ SearchAsyncResult) Choice() string                     { return `searchResults` }
func (_ SearchAsyncResult) IsProtocolOp()                      {}
func (_ SearchAsyncResult) IsResponseOp()                      {}
func (_ SearchAsyncResult) Result() Enumerated                 { return -1 }
func (r SearchAsyncResult) Error() error                       { return r.err }
func (r SearchAsyncResult) Chan() chan *SearchResultEntry      { return r.asyncE }
func (r SearchAsyncResult) Controls() Controls                 { return r.ctrls }
func (r SearchAsyncResult) Entry() *SearchResultEntry          { return r.entry }
func (r SearchAsyncResult) Reference() *SearchResultReference  { return r.referral }
func (r SearchAsyncResult) Done() *SearchResultDone            { return r.done }
func (r *SearchAsyncResult) SetError(err error)                { r.err = err }
func (r *SearchAsyncResult) AddControl(ctrl Control)           { r.ctrls.Append(ctrl) }
func (r *SearchAsyncResult) SetDone(done *SearchResultDone)    { r.done = done }

func (r *SearchAsyncResult) Next() bool {
	var is bool
	if r == nil {
		return is
	}
	res, ok := <-r.asyncE
	if !ok || res == nil {
		return is
	}

	//if r.err = res.Error; r.err == nil {
	is = true
	r.entry = res
	//}

	return is
}

func NewSearchAsyncResult(size ...int) SearchAsyncResult {
	bsize := 0
	if len(size) > 0 && size[0] > 0 {
		bsize = size[0]
	}
	return SearchAsyncResult{
		asyncE:   make(chan *SearchResultEntry, bsize),
		referral: new(SearchResultReference),
		ctrls:    make(Controls, 0),
	}
}

/*
SearchSyncResult is a [Response] implementation type intended for
use as a return value following an synchronous search request.
*/
type SearchSyncResult struct {
	Entries  []*SearchResultEntry
	ctrls    Controls
	referral *SearchResultReference
}

/*
Encode returns a nil []byte instance alongside an error. This method serves no
useful purpose and only exists to satify Go's interface signature requirements
with respect to the [Response] and [SearchResponse] interface types.
*/
func (_ SearchSyncResult) Encode() ([]byte, error) { return nil, nil }

/*
Decode returns a nil error. This method serves no useful purpose and only exists
to satify Go's interface signature requirements with respect to the [Response]
and [SearchResponse] interface types.
*/
func (_ SearchSyncResult) Decode(enc []byte) error                        { return nil }
func (_ SearchSyncResult) Tag() int                                       { return -1 }
func (_ SearchSyncResult) classTag() Tag                                  { return Tag{} }
func (_ SearchSyncResult) Kind() string                                   { return `sync` } // synchronous
func (_ SearchSyncResult) Choice() string                                 { return `searchResults` }
func (_ SearchSyncResult) IsProtocolOp()                                  {}
func (_ SearchSyncResult) IsResponseOp()                                  {}
func (_ SearchSyncResult) Result() Enumerated                             { return -1 }
func (_ SearchSyncResult) Error() error                                   { return nil }
func (_ *SearchSyncResult) Next() bool                                    { return false }
func (_ *SearchSyncResult) SetDone(_ *SearchResultDone)    		  {}
func (_ *SearchSyncResult) SetError(_ error)                		  {}
func (r *SearchSyncResult) AddControl(ctrl Control)                       { r.ctrls.Append(ctrl) }
func (r SearchSyncResult) Entry() *SearchResultEntry         		  { return nil }
func (r SearchSyncResult) Reference() *SearchResultReference 		  { return nil }
func (r SearchSyncResult) Controls() Controls                             { return r.ctrls }
func (r SearchSyncResult) Chan() chan *SearchResultEntry      		  { return nil }
func (r SearchSyncResult) Done() *SearchResultDone           		  { return nil }

func NewSearchSyncResult() SearchSyncResult {
	return SearchSyncResult{
		Entries:  make([]*SearchResultEntry, 0),
		referral: new(SearchResultReference),
		ctrls:    make(Controls, 0),
	}
}

/*
	SearchResultEntry ::= [APPLICATION 4] SEQUENCE {
	    objectName LDAPDN,
	    attributes PartialAttributeList }

SearchResultEntry implements [§ 4.5.2 of RFC4511].

[§ 4.5.2 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.5.2
*/
type SearchResultEntry struct {
	ObjectName LDAPDN
	Attributes PartialAttributeList
}

func (_ SearchResultEntry) Kind() string   { return `response` }
func (_ SearchResultEntry) Choice() string { return nameSearchResultEntryChoice }
func (_ SearchResultEntry) IsProtocolOp()  {}
func (_ SearchResultEntry) IsResponseOp()  {}
func (_ SearchResultEntry) Tag() int       { return TagSearchResultEntry }
func (_ SearchResultEntry) classTag() Tag {
	return aTag(classA, true, uint32(TagSearchResultEntry))
}
func (r SearchResultEntry) Result() Enumerated { return 0 }

/*
Encode returns an instance of []byte alongside an error following
an attempt to encode the contents of the receiver instance as an
[APPLICATION 4] SEQUENCE.
*/
func (r SearchResultEntry) Encode() ([]byte, error) {
	var enc []byte
	name, err := r.ObjectName.Encode()
	if err == nil {
		enc = append(enc, name...)
		var attrs []byte
		attrs, err = r.Attributes.Encode()
		if err == nil {
			enc = append(enc, attrs...)
			enc, err = wrapTLV(enc,
				uSeqTag(),    // SEQUENCE
				r.classTag()) // [APPLICATION 4]
		}
	}

	return enc, err
}

/*
Decode returns an error following an attempt to decode and write
the input encoding to the receiver instance. The encoding must
not be truncated, and must bear the [APPLICATION 4] SEQUENCE tag.
*/
func (r *SearchResultEntry) Decode(enc []byte) error {
	payload, err := unwrapTLV(enc,
		r.classTag(), // [APPLICATION 4]
		uSeqTag())    // SEQUENCE

	if err == nil {
		p := 0
		var name []byte
		name, err = readEPTLV(payload, &p,
			classU, uint32(tOct))

		if err == nil {
			r.ObjectName = LDAPDN(name)
			err = r.Attributes.Decode(payload[p:])
		}
	}

	return err
}

/*
	SearchResultReference ::= [APPLICATION 19] SEQUENCE SIZE (1..MAX) OF uri URI

SearchResultReference implements [§ 4.5.2 of RFC4511].

[§ 4.5.2 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.5.2
*/
type SearchResultReference []URI

func (_ SearchResultReference) Kind() string   { return `response` }
func (_ SearchResultReference) Choice() string { return nameSearchResultReferenceChoice }
func (_ SearchResultReference) IsProtocolOp()  {}
func (_ SearchResultReference) IsResponseOp()  {}
func (_ SearchResultReference) Tag() int       { return TagSearchResultReference }
func (_ SearchResultReference) classTag() Tag {
	return aTag(classA, true, uint32(TagSearchResultReference))
}
func (r *SearchResultReference) Append(u URI)      { *r = append(*r, u) }
func (r SearchResultReference) Result() Enumerated { return 0 }

/*
Encode returns an instance of []byte alongside an error following
an attempt to encode the contents of the receiver instance as an
[APPLICATION 19], circumscribing a SEQUENCE OF [LDAPString] ([URI]).

Note that this method uses the same underlying code as [LDAPResult],
given that [Referral] is a [][URI] like [SearchResultReference].
*/
func (r SearchResultReference) Encode() ([]byte, error) {
	enc, err := Referral(r).Encode() // SEQUENCE OF URI
	if err == nil {
		enc, err = wrapTLV(enc, r.classTag()) // [APPLICATION 19]
	}

	return enc, err
}

/*
Decode returns an error following an attempt to decode and write the
input encoding to the receiver instance. The encoding must not be
truncated, and must bear the [APPLICATION 19] SEQUENCE OF tag.
*/
func (r *SearchResultReference) Decode(enc []byte) error {
	payload, err := unwrapTLV(enc, r.classTag()) // [APPLICATION 19]
	if err == nil {
		// Unwrap SEQUENCE OF for payload, then decode
		// the individual LDAPString (URI) slices.
		var ref Referral
		if err = ref.Decode(payload); err == nil {
			// Cast Referral as plain []URI. We do it
			// this way merely to reduce code bloat.
			*r = []URI(ref)
		}
	}

	return err
}

/*
	SearchResultDone ::= [APPLICATION 5] LDAPResult

SearchResultDone implements [§ 4.5.2 of RFC4511], circumscribing
an [LDAPResult] SEQUENCE.

[§ 4.5.2 of RFC4511]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.5.2
*/
type SearchResultDone LDAPResult

func (_ SearchResultDone) Kind() string       { return `response` }
func (_ SearchResultDone) Choice() string     { return nameSearchResultDoneChoice }
func (_ SearchResultDone) IsProtocolOp()      {}
func (_ SearchResultDone) IsResponseOp()      {}
func (_ SearchResultDone) Tag() int           { return TagSearchResultDone }
func (_ SearchResultDone) classTag() Tag      { return aTag(classA, true, uint32(TagSearchResultDone)) }
func (r SearchResultDone) Result() Enumerated { return LDAPResult(r).ResultCode }

/*
Encode returns an instance of []byte alongside an error following
an attempt to encode the contents of the receiver instance as an
[APPLICATION 5], circumscribing an [LDAPResult] SEQUENCE.
*/
func (r SearchResultDone) Encode() ([]byte, error) {
	enc, err := LDAPResult(r).Encode() // SEQUENCE
	if err == nil {
		enc, err = wrapTLV(enc, r.classTag()) // [APPLICATION 5]
	}

	return enc, err
}

/*
Decode returns an error following an attempt to decode and write
the input encoding to the receiver instance. The encoding must
not be truncated, and must bear the [APPLICATION 5] SEQUENCE tag.
*/
func (r *SearchResultDone) Decode(enc []byte) error {
	payload, err := unwrapTLV(enc, r.classTag()) // [APPLICATION 5]
	if err == nil {
		var dec LDAPResult
		if err = dec.Decode(payload); err == nil { // SEQUENCE
			*r = SearchResultDone(dec)
		}
	}

	return err
}
