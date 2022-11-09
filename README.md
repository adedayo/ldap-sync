# Simple Go library for syncing against an LDAP server

A simple library for syncing/downloading the content of an LDAP server.

Possible use case may be to review privileges or determine which principal should have access to resources based on existing group membership

## Basic usage
The primary entry point is 

```go
conf :=  := sync.LDAPSyncConfig {  
    ...
}
result, err := sync.LDAP(conf)
```

## A more complete example

Sync against an LDAP server running on the localhost and identify users, groups and group membership of users.

```go
port := "389"
	conf := sync.LDAPSyncConfig{
		BaseDNs: []string{"dc=example,dc=org"},
		ServerConfig: sync.LDAPConfig{
			Server:                 "localhost", //LDAP server
			RequiresAuthentication: true, // set to false if server supports anonymous query, in which case the SyncUserName and the SyncUserPassword are not necessary
			SyncUserName:           "cn=admin,dc=example,dc=org",
			SyncUserPassword:       "secret_admin_password",
			Port:                   &port, //LDAP port, default 389, if not set
		},
		GroupFilter: sync.LDAPFilter{ //This is how we identify groups in the LDAP tree. In this case it says if the LDAP entity's "objectClass" attribute contains value "posixGroup" then the entry is a "group"
			Filters: []sync.FilterExpression{
				{
					Name:  "objectClass",
					Value: "posixGroup",
				},
			},
		},
		UserFilter: sync.LDAPFilter{ //This is how we identify users in the LDAP tree. In this case, it says if the LDAP entity's "objectClass" attribute has a value "inetOrgPerson" then the entry is a "user" 
			Filters: []sync.FilterExpression{
				{
					Name:  "objectClass",
					Value: "inetOrgPerson",
				},
			},
		},

		GroupMembership: sync.GroupMembershipAssociator{ //This is how we map users to groups. In this example, it is when a user's "uid" is contained in a group's "memberUid" attribute
			UserAttribute:  "uid",
			GroupAttribute: "memberUid",
		},
	}

//sync against the LDAP server
 result, err := sync.LDAP(conf)

 if err != nil {
    log.Fatal(err)
 }

 fmt.Printf("\nGroups:\n %v\n", result.GetGroups())
 fmt.Printf("\nUsers:\n %v", result.GetUsers())

//check membership
user := "cn=admin,dc=example,dc=org"
group := "cn=ServerAdmins,dc=example,dc=org"
 fmt.Printf("\n It is %v that user %s is a memeber of group %s",  result.IsMember(user, group), user, group)

```

Enjoy!