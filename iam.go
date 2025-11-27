package Cx1ClientGo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

func (c *Cx1Client) GetAuthenticationProviders() ([]AuthenticationProvider, error) {
	var idps []AuthenticationProvider

	response, err := c.sendRequestIAM(http.MethodGet, "/auth/admin", "/identity-provider/instances", nil, nil)
	if err != nil {
		return idps, err
	}

	err = json.Unmarshal(response, &idps)
	return idps, err
}

func (c *Cx1Client) GetAuthenticationProviderByAlias(alias string) (AuthenticationProvider, error) {
	var idp AuthenticationProvider

	response, err := c.sendRequestIAM(http.MethodGet, "/auth/admin", fmt.Sprintf("/identity-provider/instances/%v", alias), nil, nil)
	if err != nil {
		return idp, err
	}

	err = json.Unmarshal(response, &idp)
	return idp, err
}

func (c *Cx1Client) CreateAuthenticationProvider(alias, providerId string) (AuthenticationProvider, error) {
	idp := AuthenticationProvider{
		Alias:      alias,
		ProviderID: providerId,
	}
	jsonBody, _ := json.Marshal(idp)

	_, err := c.sendRequestIAM(http.MethodPost, "/auth/admin", "/identity-provider/instances", bytes.NewReader(jsonBody), nil)
	if err != nil {
		return AuthenticationProvider{}, err
	}

	return c.GetAuthenticationProviderByAlias(alias)
}

func (c *Cx1Client) DeleteAuthenticationProvider(provider AuthenticationProvider) error {
	_, err := c.sendRequestIAM(http.MethodDelete, "/auth/admin", fmt.Sprintf("/identity-provider/instances/%v", provider.Alias), nil, nil)
	return err
}

func (p AuthenticationProvider) String() string {
	return fmt.Sprintf("[%v] %v (%v)", ShortenGUID(p.ID), p.Alias, strings.ToUpper(p.ProviderID))
}

func (c *Cx1Client) GetAuthenticationProviderMappers(provider AuthenticationProvider) ([]AuthenticationProviderMapper, error) {
	var mappers []AuthenticationProviderMapper

	response, err := c.sendRequestIAM(http.MethodGet, "/auth/admin", fmt.Sprintf("/identity-provider/instances/%v/mappers", provider.Alias), nil, nil)
	if err != nil {
		return mappers, err
	}

	err = json.Unmarshal(response, &mappers)
	return mappers, err
}

func (c *Cx1Client) AddAuthenticationProviderMapper(mapper AuthenticationProviderMapper) error {
	jsonBody, _ := json.Marshal(mapper)

	_, err := c.sendRequestIAM(http.MethodPost, "/auth/admin", fmt.Sprintf("/identity-provider/instances/%v/mappers", mapper.Alias), bytes.NewReader(jsonBody), nil)
	return err
}

func (c *Cx1Client) DeleteAuthenticationProviderMapper(mapper AuthenticationProviderMapper) error {
	_, err := c.sendRequestIAM(http.MethodDelete, "/auth/admin", fmt.Sprintf("/identity-provider/instances/%v/mappers/%v", mapper.Alias, mapper.ID), nil, nil)
	return err
}

func (m AuthenticationProviderMapper) String() string {
	name := fmt.Sprintf("[%v] %v.%v mapper (%v)", ShortenGUID(m.ID), m.Alias, m.Name, m.Config.SyncMode)

	switch m.Mapper {
	case "saml-user-attribute-idp-mapper":
		return fmt.Sprintf("%v: Set %v to IdP-provided %v by %v", name, m.Config.UserAttribute, m.Config.Name, m.Mapper)
	case "saml-username-idp-mapper":
		return fmt.Sprintf("%v: Set Username to IdP-provided %v by %v", name, m.Config.Template, m.Mapper)
	case "custom-roles-saml-idp-mapper":
		return fmt.Sprintf("%v: Add role %v when IdP-provided %v is %v by %v", name, m.Config.Role, m.Config.Name, m.Config.Value, m.Mapper)
	case "custom-group-saml-idp-mapper":
		return fmt.Sprintf("%v: Set group membership in IdP-provided %v by %v", name, m.Config.Name, m.Mapper)
	default:
		return fmt.Sprintf("%v: Type %v with config: %v", name, m.Mapper, m.Config)
	}
}

// Convenience functions
func (a AuthenticationProvider) MakeDefaultMapper(attribute string) (AuthenticationProviderMapper, error) {
	switch strings.ToUpper(attribute) {
	case "LASTNAME":
		return AuthenticationProviderMapper{
			Name:   "Last Name",
			Alias:  a.Alias,
			Mapper: "saml-user-attribute-idp-mapper",
			Config: AuthenticationProviderMapperConfig{
				SyncMode:      "FORCE",
				UserAttribute: "lastName",
				Format:        "ATTRIBUTE_FORMAT_BASIC",
				Name:          "Last name",
			},
		}, nil
	case "FIRSTNAME":
		return AuthenticationProviderMapper{
			Name:   "First Name",
			Alias:  a.Alias,
			Mapper: "saml-user-attribute-idp-mapper",
			Config: AuthenticationProviderMapperConfig{
				SyncMode:      "FORCE",
				UserAttribute: "firstName",
				Format:        "ATTRIBUTE_FORMAT_BASIC",
				Name:          "First name",
			},
		}, nil
	case "EMAIL":
		return AuthenticationProviderMapper{
			Name:   "Email",
			Alias:  a.Alias,
			Mapper: "saml-user-attribute-idp-mapper",
			Config: AuthenticationProviderMapperConfig{
				SyncMode:      "FORCE",
				UserAttribute: "email",
				Format:        "ATTRIBUTE_FORMAT_BASIC",
				Name:          "Email",
			},
		}, nil
	case "USERNAME":
		return AuthenticationProviderMapper{
			Name:   "Username",
			Alias:  a.Alias,
			Mapper: "saml-username-idp-mapper",
			Config: AuthenticationProviderMapperConfig{
				SyncMode: "FORCE",
				Template: "${ATTRIBUTE.Username}",
				Target:   "LOCAL"},
		}, nil
	case "ROLE":
		return AuthenticationProviderMapper{
			Name:   "Scanner Role",
			Alias:  a.Alias,
			Mapper: "custom-roles-saml-idp-mapper",
			Config: AuthenticationProviderMapperConfig{
				SyncMode: "FORCE",
				Value:    "Scanner",
				Name:     "Role",
				Role:     "ast-app.ast-scanner",
			},
		}, nil
	case "GROUP":
		return AuthenticationProviderMapper{
			Name:   "Groups",
			Alias:  a.Alias,
			Mapper: "custom-group-saml-idp-mapper",
			Config: AuthenticationProviderMapperConfig{
				SyncMode: "FORCE",
				Name:     "Groups",
			},
		}, nil
	}

	return AuthenticationProviderMapper{}, fmt.Errorf("unable to create mapper: unknown attribute. Options are: lastname, firstname, email, username, role, group")
}
