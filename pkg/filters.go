package sync

import (
	"regexp"
	"strings"
)

// Used for determining group membership of users
type GroupMembershipAssociator struct {
	UserAttribute   string             //user attribute to match against the group attribute, e.g. memberOf
	GroupAttribute  string             // Group attribute to match against a user attribute e.g. DN
	Operator        LDAPFilterOperator // logical operator to chain this and AdditionalRules for more complex membership conditions
	AdditionalRules []GroupMembershipAssociator
}

// determines whether a user based on a user LDAP attribute belongs to a group e.g. {Name: memberOf, Value: superusers}
func (gmf GroupMembershipAssociator) IsMember(user, group *LDAPEntry) bool {

	m := false
	switch gmf.Operator {
	case And:
		if strings.ToLower(gmf.UserAttribute) == "dn" {
			if strings.ToLower(gmf.GroupAttribute) == "dn" {
				if user.DN != group.DN {
					return false // short circuit
				}
				for _, f2 := range gmf.AdditionalRules {
					if !f2.IsMember(user, group) {
						return false // short circuit
					}
				}
				return true // everything checks out
			} else {
				if !group.ContainsAttributeValue(gmf.GroupAttribute, user.DN) {
					return false // short circuit
				}
				for _, f2 := range gmf.AdditionalRules {
					if !f2.IsMember(user, group) {
						return false // short circuit
					}
				}
				return true // everything checks out
			}
		} else {
			//some arbitrary user attribute
			present, values := user.GetAttribute(gmf.UserAttribute)
			if !present { // user does not even have attribute of interest, bail out
				return false
			}
			if strings.ToLower(gmf.GroupAttribute) == "dn" {
				for _, v := range values {
					if v == group.DN {
						//we found the match, check the rest of the conditions
						for _, f2 := range gmf.AdditionalRules {
							if !f2.IsMember(user, group) {
								return false // short circuit
							}
						}
						return true // everything checks out
					}
				}
				//no match
				return false
			} else {
				//some arbitrary group attribute
				present, gValues := group.GetAttribute(gmf.GroupAttribute)
				if !present { // group does not have attribute, bail out
					return false
				}
				//check whether the user values intersect the group values
				for _, uv := range values {
					for _, gv := range gValues {
						if uv == gv {
							//we found a match, check the other conditions
							for _, f2 := range gmf.AdditionalRules {
								if !f2.IsMember(user, group) {
									return false // short circuit
								}
							}
							return true // everything checks out
						}
					}
				}
				//no match
				return false
			}
		}
	case Or:
		if strings.ToLower(gmf.UserAttribute) == "dn" {
			if strings.ToLower(gmf.GroupAttribute) == "dn" {
				if user.DN == group.DN {
					return true // short circuit
				}
				for _, f2 := range gmf.AdditionalRules {
					if f2.IsMember(user, group) {
						return true // short circuit
					}
				}
				return false // nothing checks out
			} else {
				if group.ContainsAttributeValue(gmf.GroupAttribute, user.DN) {
					return true // short circuit
				}
				for _, f2 := range gmf.AdditionalRules {
					if f2.IsMember(user, group) {
						return true // short circuit
					}
				}
				return false // nothing checks out
			}
		} else {
			//some arbitrary user attribute
			present, values := user.GetAttribute(gmf.UserAttribute)
			if !present { // user does not even have attribute of interest, bail out
				return false
			}
			if strings.ToLower(gmf.GroupAttribute) == "dn" {
				for _, v := range values {
					if v == group.DN {
						//we found the match, short circuit
						return true
					}
				}
				for _, f2 := range gmf.AdditionalRules {
					if f2.IsMember(user, group) {
						return true // short circuit
					}
				}
				//nothing checks out
				return false
			} else {
				//some arbitrary group attribute
				present, gValues := group.GetAttribute(gmf.GroupAttribute)
				if !present { // group does not have attribute, bail out
					return false
				}
				//check whether the user values intersect the group values
				for _, uv := range values {
					for _, gv := range gValues {
						if uv == gv {
							//we found a match, short circuit
							return true
						}
					}
				}
				//check other conditions
				for _, f2 := range gmf.AdditionalRules {
					if f2.IsMember(user, group) {
						return true // short circuit
					}
				}
				return false // nothing checks out
			}
		}
	}

	return m
}

type LDAPFilterOperator int

const (
	And LDAPFilterOperator = iota
	Or
)

// Filter LDAP entities with the struct
// e.g. (&(memberof=cn=access-checkmate,cn=groups,cn=accounts,dc=example,dc=org)(cn=*Developers*))
// {Operator: And, Filters: []FilterExpression{{Name: "memberof", Value: "cn=access-checkmate,cn=groups,cn=accounts,dc=example,dc=org"},
// {Name: "cn", Value: "*Developers*"}}}
type LDAPFilter struct {
	Operator     LDAPFilterOperator
	Filters      []FilterExpression
	FilterGroups []LDAPFilter
	compiled     bool
}

func (lf *LDAPFilter) compile() {
	for i := range lf.Filters {
		lf.Filters[i].compile()
	}

	for i := range lf.FilterGroups {
		lf.FilterGroups[i].compile()
	}

	lf.compiled = true
}

func (f *LDAPFilter) Matches(ent *LDAPEntry) bool {

	if ent == nil {
		return false //bail out on nonsensical entry
	}

	if !f.compiled {
		f.compile()
	}

	m := false
	switch f.Operator {
	case And:
		for _, ff := range f.Filters {
			if strings.ToLower(ff.Name) == "dn" {
				if ent.DN == ff.Value {
					m = true
				} else {
					return false // short-circuit on wrong DN
				}
			} else {
				if !ent.ContainsAttribute(&ff) {
					return false // short-circuit entity with non-matching attribute
				} else {
					m = true
				}
			}
		}
		for _, fg := range f.FilterGroups {
			if fg.Matches(ent) {
				m = true
			} else {
				return false // short-circuit any group that does not match
			}
		}
	case Or:
		for _, ff := range f.Filters {
			if strings.ToLower(ff.Name) == "dn" {
				if ent.DN == ff.Value {
					return true // short-circuit on correct DN
				}
			} else {
				if ent.ContainsAttribute(&ff) {
					return true // short-circuit entity with matching attribute
				}
			}
		}
		for _, fg := range f.FilterGroups {
			if fg.Matches(ent) {
				return true // short-circuit on any group match
			}
		}
	}

	return m
}

func (ent *LDAPEntry) ContainsAttributeValue(attr, value string) bool {
	for _, att := range ent.Attributes {
		if att.Name == attr {
			for _, v := range att.Values {
				if v == value {
					return true
				}
			}
		}
	}
	return false

}

func (ent *LDAPEntry) ContainsAttribute(ff *FilterExpression) bool {
	ff.compile()
	for _, att := range ent.Attributes {
		if att.Name == ff.Name {
			for _, v := range att.Values {
				if ff.compiledValue.MatchString(v) {
					return true
				}
			}
		}
	}
	return false
}

type NameValue struct {
	Name, Value string
}

type FilterExpression struct {
	Name, Value          string
	compiledValue        *regexp.Regexp
	compiledSuccessfully bool
}

func (fe *FilterExpression) compile() {
	if fe.compiledSuccessfully {
		return //compile once
	}
	re, err := regexp.Compile(fe.Value)
	if err == nil {
		fe.compiledValue = re
		fe.compiledSuccessfully = true
	}
}
