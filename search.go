package auth

import (
	"fmt"

	ldap "gopkg.in/ldap.v2"
)

//Search returns the entries for the given search criteria or an error if one occurred.
func (c *Conn) Search(filter string, attrs []string, sizeLimit int) ([]*ldap.Entry, error) {
	answer := []*ldap.Entry{}
	searches := []string{c.Config.BaseDN}
	if c.Config.SearchDN != nil {
		searches = c.Config.SearchDN
	}

	var terr error
	for _, s := range searches {
		search := ldap.NewSearchRequest(
			s,
			ldap.ScopeWholeSubtree,
			ldap.DerefAlways,
			sizeLimit,
			0,
			false,
			filter,
			attrs,
			nil,
		)
		result, err := c.Conn.Search(search)
		if err != nil {
			terr = fmt.Errorf(`Search error "%s": %v`, filter, err)
		}
		answer = append(answer, result.Entries...)
	}

	// If found no answers and have an error, return it
	if len(answer) == 0 && terr != nil {
		return nil, terr
	}

	return answer, nil
}

//SearchOne returns the single entry for the given search criteria or an error if one occurred.
//An error is returned if exactly one entry is not returned.
func (c *Conn) SearchOne(filter string, attrs []string) (*ldap.Entry, error) {
	searches := []string{c.Config.BaseDN}
	if c.Config.SearchDN != nil {
		searches = c.Config.SearchDN
	}
	var terr error
	for _, s := range searches {
		search := ldap.NewSearchRequest(
			s,
			ldap.ScopeWholeSubtree,
			ldap.DerefAlways,
			1,
			0,
			false,
			filter,
			attrs,
			nil,
		)

		result, err := c.Conn.Search(search)
		if err != nil {
			if e, ok := err.(*ldap.Error); ok {
				if e.ResultCode == ldap.LDAPResultSizeLimitExceeded {
					terr = fmt.Errorf(`Search error "%s": more than one entries returned`, filter)
					continue
				}
			}

			terr = fmt.Errorf(`Search error "%s": %v`, filter, err)
			continue
		}

		if len(result.Entries) == 0 {
			terr = fmt.Errorf(`Search error "%s": no entries returned`, filter)
			continue
		}

		return result.Entries[0], nil
	}
	return nil, terr
}

//GetDN returns the DN for the object with the given attribute value or an error if one occurred.
func (c *Conn) GetDN(attr, value string) (string, error) {
	entry, err := c.SearchOne(fmt.Sprintf("(%s=%s)", attr, value), nil)
	if err != nil {
		return "", err
	}

	return entry.DN, nil
}

//GetAttributes returns the *ldap.Entry with the given attributes for the object with the given attribute value or an error if one occurred.
func (c *Conn) GetAttributes(attr, value string, attrs []string) (*ldap.Entry, error) {
	return c.SearchOne(fmt.Sprintf("(%s=%s)", attr, value), attrs)
}
