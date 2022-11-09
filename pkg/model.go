package sync

import (
	"fmt"
	"net"
)

type LDAPRecords struct {
	Entries []*LDAPEntry
	config  *LDAPSyncConfig
}

func (sr LDAPRecords) GetUsers() (ents []*LDAPEntry) {
	for _, e := range sr.Entries {
		if sr.config.UserFilter.Matches(e) {
			ents = append(ents, e)
		}
	}
	return
}

func (sr LDAPRecords) GetGroups() (ents []*LDAPEntry) {
	for _, e := range sr.Entries {
		if sr.config.GroupFilter.Matches(e) {
			ents = append(ents, e)
		}
	}
	return
}

// checks whether a user distinguished name (DN) belongs to the group specified as a DN
func (sr LDAPRecords) IsMember(user, group string) bool {
	var uu, gg *LDAPEntry
	for _, g := range sr.GetGroups() {
		if g.DN == group {
			gg = g
		}
	}

	if gg == nil { // group not found
		return false
	}

	for _, u := range sr.GetUsers() {
		if u.DN == user {
			uu = u
		}
	}

	if uu == nil { // user not found
		return false
	}

	//found a user and group. Determine if user belongs to group
	return sr.config.GroupMembership.IsMember(uu, gg)
}

type LDAPConfig struct {
	Server                 string
	RequiresAuthentication bool   //if sync requires authentication, in which case sync username and passwords below must be set
	SyncUserName           string //distinguished name of an administrative user that the application will use when connecting to the directory server. For Active Directory, the user should be a member of the built-in administrator group
	SyncUserPassword       string
	RootPath               string
	TLS, StartTLS          bool
	Port                   *string //389 if not set
}

type LDAPSyncConfig struct {
	ServerConfig    LDAPConfig
	BaseDNs         []string //Base DNs to search from
	GroupFilter     LDAPFilter
	UserFilter      LDAPFilter
	GroupMembership GroupMembershipAssociator // how we determine which groups the user belongs to
}

func (conf LDAPSyncConfig) GetDialAddr() string {
	port := "389"
	if conf.ServerConfig.Port != nil {
		port = *conf.ServerConfig.Port
	}
	return net.JoinHostPort(conf.ServerConfig.Server, port)
}

func (conf LDAPSyncConfig) GetDialURL() string {
	port := "389"
	if conf.ServerConfig.Port != nil {
		port = *conf.ServerConfig.Port
	}
	return "ldap://" + net.JoinHostPort(conf.ServerConfig.Server, port)
}

// Prevent LDAP Injection
// See https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html
// TODO: Implement the sanitization
func (conf LDAPSyncConfig) Sanitize() LDAPSyncConfig {
	for i := range conf.BaseDNs {
		conf.BaseDNs[i] = sanitiseDN(conf.BaseDNs[i])
	}
	return conf
}

// TODO
func sanitiseDN(d string) string {
	return d
}

type LDAPEntry struct {
	DN         string
	Attributes []LDAPAttribute
}

func (ent LDAPEntry) GetAttribute(attribute string) (bool, []string) {
	for _, att := range ent.Attributes {
		if att.Name == attribute {
			return true, att.Values
		}
	}
	return false, []string{}
}

// LDAPAttribute is an LDAP attribute that has a name and a list of values
type LDAPAttribute struct {
	Name   string
	Values []string
}

func (att LDAPAttribute) String() string {
	return fmt.Sprintf("%s -> %s", att.Name, att.Values)
}
