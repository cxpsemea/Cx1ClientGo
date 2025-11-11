package Cx1ClientGo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-querystring/query"
)

// Get all OIDC Clients in the system
func (c Cx1Client) GetClients() ([]OIDCClient, error) {
	c.logger.Debugf("Getting OIDC Clients")
	_, clients, err := c.GetAllClientsFiltered(OIDCClientFilter{
		BaseIAMFilter: BaseIAMFilter{
			First: 0,
			Max:   c.pagination.Clients,
		},
	})
	return clients, err
}

// Get details about a specific OIDC Client by GUID
func (c Cx1Client) GetClientByID(guid string) (OIDCClient, error) {
	c.logger.Debugf("Getting OIDC client with ID %v", guid)
	var client OIDCClient

	response, err := c.sendRequestIAM(http.MethodGet, "/auth/admin", fmt.Sprintf("/clients/%v", guid), nil, nil)
	if err != nil {
		return client, err
	}

	var json_client map[string]interface{}
	err = json.Unmarshal(response, &json_client)
	if err != nil {
		return client, err
	}

	return clientFromMap(json_client)
}

// Get all OIDC Clients matching a string
func (c Cx1Client) GetClientsByName(clientName string) ([]OIDCClient, error) {
	c.logger.Debugf("Getting OIDC clients matching name %v", clientName)
	_, clients, err := c.GetAllClientsFiltered(OIDCClientFilter{
		BaseIAMFilter: BaseIAMFilter{
			First: 0,
			Max:   c.pagination.Clients,
		},
		ClientID: clientName,
		Search:   boolPtr(true),
	})

	return clients, err
}

// Gets a specific OIDC client with the client id matching this name exactly
func (c Cx1Client) GetClientByName(clientName string) (OIDCClient, error) {
	c.logger.Debugf("Getting OIDC client with name %v", clientName)

	var client OIDCClient
	_, clients, err := c.GetAllClientsFiltered(OIDCClientFilter{
		BaseIAMFilter: BaseIAMFilter{
			First: 0,
			Max:   c.pagination.Clients,
		},
		ClientID: clientName,
		Search:   boolPtr(false),
	})
	if err != nil {
		return client, err
	}

	if len(clients) == 1 {
		return clients[0], nil
	}
	return client, fmt.Errorf("no such client %v found", clientName)
}

// Gets the secret for an OIDC Client
// Only available to the creator of the OIDC Client
func (c Cx1Client) GetClientSecret(client *OIDCClient) (string, error) {
	c.logger.Debugf("Getting OIDC client secret for %v", client.String())

	var responseBody struct {
		Type  string
		Value string
	}

	response, err := c.sendRequestIAM(http.MethodGet, "/auth/admin", fmt.Sprintf("/clients/%v/client-secret", client.ID), nil, nil)
	if err != nil {
		return "", err
	}

	err = json.Unmarshal(response, &responseBody)
	if err == nil {
		client.ClientSecret = responseBody.Value
	}
	return responseBody.Value, err
}

// Create a new OIDC client
func (c Cx1Client) CreateClient(name string, notificationEmails []string, secretExpiration int) (OIDCClient, error) {
	c.logger.Debugf("Creating OIDC client with name %v", name)

	notificationEmailsStr := "[\"" + strings.Join(notificationEmails, "\",\"") + "\"]"
	//c.logger.Infof("Setting emails: %v", notificationEmailsStr)

	body := map[string]interface{}{
		"enabled": true,
		"attributes": map[string]interface{}{
			"lastUpdate":                    time.Now().UnixMilli(),
			"client.secret.creation.time":   time.Now().Unix(),
			"client.secret.expiration.time": time.Now().AddDate(0, 0, secretExpiration).Unix(),
			"notificationEmail":             notificationEmailsStr,
			"secretExpiration":              fmt.Sprintf("%d", secretExpiration),
		},
		"redirectUris":           []string{},
		"clientId":               name,
		"protocol":               "openid-connect",
		"frontchannelLogout":     true,
		"publicClient":           false,
		"serviceAccountsEnabled": true,
		"standardFlowEnabled":    false,
	}

	jsonBody, _ := json.Marshal(body)

	_, err := c.sendRequestIAM(http.MethodPost, "/auth/admin", "/clients", bytes.NewReader(jsonBody), nil)
	if err != nil {
		return OIDCClient{}, err
	}

	newClient, err := c.GetClientByName(name)
	if err != nil {
		return newClient, err
	}

	groupScope, err := c.GetClientScopeByName("groups")
	if err != nil {
		return newClient, fmt.Errorf("failed to get 'groups' client scope to add to new client: %s", err)
	}

	err = c.AddClientScopeByID(newClient.ID, groupScope.ID)
	if err != nil {
		return newClient, fmt.Errorf("failed to add 'groups' client scope to new client: %s", err)
	}

	err = c.UpdateClient(newClient)
	return newClient, err
}

func clientFromMap(data map[string]interface{}) (OIDCClient, error) {
	var client OIDCClient
	err := client.ClientFromMap(data)
	return client, err
}

// Used internally to update an OIDC Client struct from JSON data
func (c *OIDCClient) ClientFromMap(data map[string]interface{}) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal unmarshaled json: %s", err)
	}

	err = json.Unmarshal(jsonData, c)
	if err != nil {
		return fmt.Errorf("failed to re-unmarshal json: %s", err)
	}

	c.OIDCClientRaw = data
	if c.OIDCClientRaw["attributes"] != nil {
		if c.OIDCClientRaw["attributes"].(map[string]interface{})["client.secret.expiration.time"] != nil {
			timestamp := c.OIDCClientRaw["attributes"].(map[string]interface{})["client.secret.expiration.time"].(string)
			c.ClientSecretExpiry, _ = strconv.ParseUint(timestamp, 10, 64)
		}
		if c.OIDCClientRaw["attributes"].(map[string]interface{})["secretExpiration"] != nil {
			expiryDaysStr := c.OIDCClientRaw["attributes"].(map[string]interface{})["secretExpiration"].(string)
			expiryDays, _ := strconv.ParseUint(expiryDaysStr, 10, 64)
			c.SecretExpirationDays = expiryDays
		}
		if c.OIDCClientRaw["attributes"].(map[string]interface{})["creator"] != nil {
			c.Creator = c.OIDCClientRaw["attributes"].(map[string]interface{})["creator"].(string)
		}
	}
	return nil
}

func (c *OIDCClient) clientToMap() {
	if c.OIDCClientRaw["attributes"] != nil {
		attributes := c.OIDCClientRaw["attributes"].(map[string]interface{})
		if attributes["client.secret.expiration.time"] != nil {
			timestamp := attributes["client.secret.expiration.time"].(string)
			expiry, _ := strconv.ParseUint(timestamp, 10, 64)
			if expiry != c.ClientSecretExpiry {
				attributes["client.secret.expiration.time"] = expiry
			}
		}

		if attributes["secretExpiration"] != nil {
			expiryDaysStr := attributes["secretExpiration"].(string)
			expiryDays, _ := strconv.ParseUint(expiryDaysStr, 10, 64)
			if expiryDays != c.SecretExpirationDays {
				attributes["secretExpiration"] = c.SecretExpirationDays
			}
		}
		/*
			// it may be a bug to allow changing the creator
			if attributes["creator"] != nil {
				creator := attributes["creator"].(string)
				if creator != c.Creator {
					attributes["creator"] = c.Creator
				}
			}
		*/
		c.OIDCClientRaw["attributes"] = attributes
	}
}

/*
The UpdateClient function should be used sparingly - it will use the contents of the OIDCClient.OIDCClientRaw variable of type map[string]interface{} in the PUT request.
As a result, changes to the member variables in the OIDCClient object itself (creator & clientsecretexpiry) will not be saved using this method unless they are also updated in OIDCClientRaw.
*/
func (c Cx1Client) UpdateClient(client OIDCClient) error {
	c.logger.Debugf("Updating OIDC client with name %v", client.ClientID)
	client.clientToMap()

	jsonBody, _ := json.Marshal(client.OIDCClientRaw)

	_, err := c.sendRequestIAM(http.MethodPut, "/auth/admin", fmt.Sprintf("/clients/%v", client.ID), bytes.NewReader(jsonBody), nil)
	if err != nil {
		return err
	}

	return nil
}

// review Keycloak documentation for correct usage
func (c Cx1Client) AddClientScopeByID(guid, clientScopeId string) error {
	c.logger.Debugf("Adding client scope %v to OIDC Client %v", clientScopeId, guid)

	_, err := c.sendRequestIAM(http.MethodPut, "/auth/admin", fmt.Sprintf("/clients/%v/default-client-scopes/%v", guid, clientScopeId), nil, nil)
	return err
}

// Delete an OIDC Client
func (c Cx1Client) DeleteClientByID(guid string) error {
	c.logger.Debugf("Deleting OIDC client with ID %v", guid)
	if strings.EqualFold(guid, c.GetASTAppID()) {
		return fmt.Errorf("attempt to delete the ast-app client (ID: %v) prevented - this will break your tenant", guid)
	}
	_, err := c.sendRequestIAM(http.MethodDelete, "/auth/admin", fmt.Sprintf("/clients/%v", guid), nil, nil)
	return err
}

// Retrieve the user account behind the OIDC Client
// The user account stores the roles, group access, and other mappings
func (c Cx1Client) GetServiceAccountByID(guid string) (User, error) {
	c.logger.Debugf("Getting service account user behind OIDC client with ID %v", guid)
	var user User
	response, err := c.sendRequestIAM(http.MethodGet, "/auth/admin", fmt.Sprintf("/clients/%v/service-account-user", guid), nil, nil)
	if err != nil {
		return user, err
	}

	err = json.Unmarshal(response, &user)
	return user, err
}

func (c Cx1Client) GetClientScopes() ([]OIDCClientScope, error) {
	c.logger.Debugf("Getting OIDC Client Scopes")
	var clientscopes []OIDCClientScope

	response, err := c.sendRequestIAM(http.MethodGet, "/auth/admin", "/client-scopes", nil, nil)
	if err != nil {
		return clientscopes, err
	}

	err = json.Unmarshal(response, &clientscopes)
	c.logger.Tracef("Got %d client scopes", len(clientscopes))
	return clientscopes, err
}

func (c Cx1Client) GetClientScopeByName(name string) (OIDCClientScope, error) {
	clientScopes, err := c.GetClientScopes()
	if err != nil {
		return OIDCClientScope{}, err
	}

	for _, cs := range clientScopes {
		if cs.Name == name {
			return cs, nil
		}
	}

	return OIDCClientScope{}, fmt.Errorf("client-scope %v not found", name)
}

func (c *Cx1Client) GetCurrentClient() (OIDCClient, error) {
	if c.client != nil {
		return *c.client, nil
	}
	if c.IsUser {
		return OIDCClient{}, fmt.Errorf("currently connected as user %v (%v) and not an OIDC client", c.claims.Username, c.claims.Email)
	}
	var client OIDCClient

	client, err := c.GetClientByName(c.claims.ClientID)
	c.client = &client

	return *c.client, err
}

// convenience function
func (c *Cx1Client) GetASTAppID() string {
	if c.astAppID == "" {
		client, err := c.GetClientByName("ast-app")
		if err != nil {
			c.logger.Warnf("Error finding AST App ID: %s", err)
			return ""
		}

		c.astAppID = client.ID
	}

	return c.astAppID
}

func (c Cx1Client) RegenerateClientSecret(client OIDCClient) (string, error) {
	clientId := client.ID
	body := map[string]interface{}{
		"realm":  c.tenant,
		"client": clientId,
	}

	type RespBody struct {
		Type  string
		Value string
	}
	var secretResponse RespBody

	jsonBody, _ := json.Marshal(body)

	response, err := c.sendRequestIAM(http.MethodPost, "/auth/admin", fmt.Sprintf("/clients/%s/client-secret", clientId), bytes.NewReader(jsonBody), nil)
	if err != nil {
		return "", err
	}
	err = json.Unmarshal(response, &secretResponse)
	if err != nil {
		return "", err
	}

	return secretResponse.Value, nil
}

func (client OIDCClient) String() string {
	return fmt.Sprintf("[%v] %v", ShortenGUID(client.ID), client.ClientID)
}

func (c Cx1Client) GetClientsFiltered(filter OIDCClientFilter) ([]OIDCClient, error) {
	var clients []OIDCClient
	if filter.Max < 10 {
		filter.Max = 10
	}
	params, _ := query.Values(filter)

	response, err := c.sendRequestIAM(http.MethodGet, "/auth/admin", fmt.Sprintf("/clients?%v", params.Encode()), nil, nil)
	if err != nil {
		return clients, err
	}

	var json_clients []map[string]interface{}
	err = json.Unmarshal(response, &json_clients)
	if err != nil {
		return clients, err
	}

	clients = make([]OIDCClient, len(json_clients))
	for id, client := range json_clients {
		clients[id], err = clientFromMap(client)
		if err != nil {
			return clients, err
		}
	}

	return clients, err
}

func (c Cx1Client) GetAllClientsFiltered(filter OIDCClientFilter) (uint64, []OIDCClient, error) {
	var clients []OIDCClient
	// paginate until we get all results.
	count := uint64(0)

	cs, err := c.GetClientsFiltered(filter)
	clients = cs
	count = uint64(len(clients))

	for err == nil && ((filter.Search != nil && *filter.Search) || filter.ClientID == "") && filter.Max > 0 && uint64(len(cs)) > 0 {
		filter.Bump()
		cs, err = c.GetClientsFiltered(filter)
		clients = append(clients, cs...)
		count = uint64(len(clients))
	}

	return count, clients, err
}

func (c Cx1Client) GetXClientsFiltered(filter OIDCClientFilter, count uint64) (uint64, []OIDCClient, error) {
	var clients []OIDCClient

	cs, err := c.GetClientsFiltered(filter)
	clients = cs

	for err == nil && count > filter.Max+filter.First && ((filter.Search != nil && *filter.Search) || filter.ClientID == "") && filter.Max > 0 && uint64(len(clients)) < count {
		filter.Bump()
		cs, err = c.GetClientsFiltered(filter)
		clients = append(clients, cs...)
	}

	if uint64(len(clients)) > count {
		return count, clients[:count], err
	}

	return uint64(len(clients)), clients, err
}
