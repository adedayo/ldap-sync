package sync

import (
	"crypto/tls"

	"github.com/go-ldap/ldap/v3"
)

func LDAP(config LDAPSyncConfig) (result LDAPRecords, err error) {
	config = config.Sanitize()
	result.config = &config
	var l *ldap.Conn
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, //TODO: support self-signed CAs
	}

	if config.ServerConfig.TLS {
		l, err = ldap.DialTLS("tcp", config.GetDialAddr(), tlsConfig)
		if err != nil {
			return
		}
	} else {
		l, err = ldap.DialURL(config.GetDialURL())
		if err != nil {
			return
		}
		if config.ServerConfig.StartTLS {
			err = l.StartTLS(tlsConfig)
			if err != nil {
				return
			}
		}
	}

	if err != nil {
		return
	}
	defer l.Close()

	if config.ServerConfig.RequiresAuthentication {
		err = l.Bind(config.ServerConfig.SyncUserName, config.ServerConfig.SyncUserPassword)
		if err != nil {
			return
		}
	}

	for _, baseDN := range config.BaseDNs {
		searchRequest := ldap.NewSearchRequest(
			baseDN, // The base dn to search
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			"(&(objectClass=*))", // The filter to apply - get everything
			[]string{},           // A list attributes to retrieve - get all attributes
			[]ldap.Control{},
		)

		sr, e := l.SearchWithPaging(searchRequest, 5 /*limit pagination size to 5*/)
		if e != nil {
			err = e
			return
		}

		for _, entry := range sr.Entries {
			ent := LDAPEntry{
				DN:         entry.DN,
				Attributes: make([]LDAPAttribute, len(entry.Attributes)),
			}
			for i, att := range entry.Attributes {
				ent.Attributes[i] = LDAPAttribute{
					Name:   att.Name,
					Values: att.Values,
				}
			}
			result.Entries = append(result.Entries, &ent)
		}
	}
	return

}
