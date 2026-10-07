package protocol

import (
	"sort"
)

/*
Entry implements a loose interpretation of [§ 2.2 of RFC4512].

Officially, there is no true definition of this type in any standard, and is
implemented here merely to aid in certain parallel processes -- such as LDIF
processing -- in which the assembly of an abstract DIT entry is necessary or
advantageous.

Instances of this type are NOT used in any official LDAP operation, such as
Search, Delete and others.

Though this type bears a strong resemblance to the [response.SearchResultEntry]
type, the two are not related.

See the [NewEntry] constructor for a means of assembling new instances of this
type.

[§ 2.2 of RFC4512]: https://datatracker.ietf.org/doc/html/rfc4512#section-2.2
*/
type Entry struct {
	Name       LDAPDN
	Attributes []EntryAttribute
}

/*
NewEntry returns an instance of [Entry] following an attempt to marshal the
dn and attrs input values.
*/
func NewEntry(dn LDAPDN, attrs map[string][]string) Entry {
	var attributeNames []string
	for attributeName := range attrs {
		attributeNames = append(attributeNames, attributeName)
	}
	sort.Strings(attributeNames)

	var encodedAttributes []EntryAttribute
	for _, attributeName := range attributeNames {
		var values []AttributeValue
		for i := 0; i < len(attrs[attributeName]); i++ {
			values = append(values, AttributeValue(attrs[attributeName][i]))
		}
		encodedAttributes = append(encodedAttributes, EntryAttribute{
			Type: AttributeDescription(attributeName),
			Vals: values,
		})
	}
	return Entry{
		Name:       dn,
		Attributes: encodedAttributes,
	}
}

func (r Entry) DN() LDAPDN { return r.Name }

/*
Choice returns the string literal 'entry'. This method exists only to allow easier type
management within the [util/ldif] package and does not relate to, nor extend from, any
ASN.1 CHOICE definition, official or otherwise.

[util/ldif]: https://github.com/go-directory/util/tree/main/ldif
*/
func (_ Entry) Choice() string { return `entry` }

/*
GetAttributeValues returns an instance of [][AttributeValue], which will contain all
[AttributeValue] instances associated with the input [AttributeDescription].
*/
func (r Entry) GetAttributeValues(at AttributeDescription) []AttributeValue {
	var vals []AttributeValue
	for i := 0; i < len(r.Attributes); i++ {
		attr := r.Attributes[i]
		if attr.Type.EqualFold(at) {
			vals = attr.Vals
			break
		}
	}

	return vals
}

/*
GetAttributeValue returns the first instance of [AttributeValue] associated with
the input [AttributeDescription].
*/
func (r Entry) GetAttributeValue(at AttributeDescription) AttributeValue {
	vals := r.GetAttributeValues(at)
	var av AttributeValue
	if len(vals) > 0 {
		av = vals[0]
	}
	return av
}

/*
GetAttributeDescriptions returns slices of [AttributeDescription].
Note that these slices may or may not contain [AttributeOption]
statements, such as tags, in addition to the [AttributeType]
component.

See [Entry.GetAttributeTypes] for means to obtain slices of only
[AttributeType].
*/
func (r Entry) GetAttributeDescriptions() []AttributeDescription {
	var desc []AttributeDescription
	for i := 0; i < len(r.Attributes); i++ {
		attr := r.Attributes[i]
		desc = append(desc, attr.Type)
	}

	return desc
}

/*
GetAttributeDescriptions returns slices of [AttributeDescription].

Note that these slices will not contain any [AttributeOption]
statements, such as tags.

See [Entry.GetAttributeDescriptions] for means to obtain complete
[AttributeDescription] slices.
*/
func (r Entry) GetAttributeTypes() []AttributeType {
	var types []AttributeType
	for i := 0; i < len(r.Attributes); i++ {
		attr := r.Attributes[i]
		types = append(types, attr.Type.Type()) // type ONLY
	}

	return types
}
