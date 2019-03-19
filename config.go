package auth

import (
	"errors"
	"fmt"
	"net/mail"
	"strings"
)

//SecurityType specifies the type of security to use when connecting to an Active Directory Server.
type SecurityType int

//Security will default to SecurityNone if not given.
const (
	SecurityNone SecurityType = iota
	SecurityTLS
	SecurityStartTLS
)

//Config contains settings for connecting to an Active Directory server.
type Config struct {
	Server   string
	Port     int
	BaseDN   string
	SearchDN []string
	Security SecurityType
}

func getDomainFromDCString(dcString string) (string, error) {
	domain := ""
	for _, v := range strings.Split(strings.ToLower(dcString), ",") {
		if trimmed := strings.TrimSpace(v); strings.HasPrefix(trimmed, "dc=") {
			domain = domain + "." + trimmed[3:]
		}
	}
	if len(domain) <= 1 {
		return "", errors.New("Configuration error: invalid BaseDN")
	}
	return domain[1:], nil
}

//Domain returns the domain derived from BaseDN or an error if misconfigured.
func (c *Config) Domain() (string, error) {
	return getDomainFromDCString(c.BaseDN)
}

//UPN returns the userPrincipalName for the given username or an error if misconfigured.
func (c *Config) UPN(username string) (string, error) {
	if _, err := mail.ParseAddress(username); err == nil {
		return username, nil
	}

	domain, err := c.Domain()
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s@%s", username, domain), nil
}

//Domains returns the domain derived from BaseDN or an error if misconfigured.
func (c *Config) Domains() ([]string, error) {
	terr := &AggregatingError{}
	answer := []string{}
	searches := []string{c.BaseDN}
	if c.SearchDN != nil {
		searches = c.SearchDN
	}
	for _, ds := range searches {
		d, err := getDomainFromDCString(ds)
		if err != nil {
			terr.AddError(err)
			continue
		}
		answer = append(answer, d)
	}
	if len(answer) == 0 {
		return nil, terr
	}
	return answer, nil
}

//UPNs returns the userPrincipalName for the given username or an error if misconfigured.
func (c *Config) UPNs(username string) ([]string, error) {
	if _, err := mail.ParseAddress(username); err == nil {
		return []string{username}, nil
	}
	domains, err := c.Domains()
	if err != nil {
		return nil, err
	}
	answer := []string{}
	for _, d := range domains {
		answer = append(answer, fmt.Sprintf("%s@%s", username, d))
	}
	return answer, nil
}
