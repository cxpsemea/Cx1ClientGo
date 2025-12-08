package Cx1ClientGo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/go-querystring/query"
)

func (c *Cx1Client) GetCxLinks(count uint64) ([]CxLink, error) {
	_, links, err := c.GetXCxLinksFiltered(
		CxLinkFilter{
			BaseFilter: BaseFilter{
				Offset: 0,
				Limit:  c.pagination.CxLinks,
			},
		},
		count,
	)

	return links, err
}

func (c *Cx1Client) GetAllCxLinks() ([]CxLink, error) {
	_, links, err := c.GetAllCxLinksFiltered(
		CxLinkFilter{
			BaseFilter: BaseFilter{
				Offset: 0,
				Limit:  c.pagination.CxLinks,
			},
		},
	)

	return links, err
}

func (c *Cx1Client) CreateCxLink(name, description, privateUrl string) (newLink CxLinkResponse, err error) {
	params, _ := json.Marshal(map[string]string{
		"name":        name,
		"privateUrl":  privateUrl,
		"description": description,
	})

	response, err := c.sendRequest(http.MethodPost, "/v1/link/links", bytes.NewReader(params), nil)
	if err != nil {
		return
	}

	err = json.Unmarshal(response, &newLink)
	return
}

func (c *Cx1Client) DeleteCxLink(link CxLink) error {
	return c.DeleteCxLinkByID(link.LinkID)
}
func (c *Cx1Client) DeleteCxLinkByID(linkId string) error {
	_, err := c.sendRequest(http.MethodDelete, fmt.Sprintf("/v1/link/links/%v", linkId), nil, nil)
	return err
}

func (c *Cx1Client) UpdateCxLink(link CxLink) error {
	params, _ := json.Marshal(map[string]string{
		"name":        link.Name,
		"description": link.Description,
	})

	_, err := c.sendRequest(http.MethodPut, fmt.Sprintf("/v1/link/links/%v", link.LinkID), bytes.NewReader(params), nil)
	return err
}

func (newlink CxLinkResponse) DockerCommand() string {
	return fmt.Sprintf("docker run --pull=always --rm -it checkmarx/link-client:1 --tunnel-name %v --tunnel-server-url %v --link-token %v --private-url %v", newlink.Link.TunnelName, newlink.ServerURL, newlink.Token, newlink.Link.PrivateURL)
}

// Underlying function used by many GetCxLink* calls
// Returns the total number of matching results plus an array of cxlinks with
// one page of results (from filter.Offset to filter.Offset+filter.Limit)
func (c *Cx1Client) GetCxLinksFiltered(filter CxLinkFilter) (uint64, []CxLink, error) {
	params, _ := query.Values(filter)

	var CxLinkResponse struct {
		TotalCount uint64   `json:"totalCount"`
		CxLinks    []CxLink `json:"items"`
	}

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/v1/link/links?%v", params.Encode()), nil, nil)

	if err != nil {
		return CxLinkResponse.TotalCount, CxLinkResponse.CxLinks, err
	}

	err = json.Unmarshal(response, &CxLinkResponse)
	return CxLinkResponse.TotalCount, CxLinkResponse.CxLinks, err
}

// Retrieves all cxlinks matching the filter
func (c *Cx1Client) GetAllCxLinksFiltered(filter CxLinkFilter) (uint64, []CxLink, error) {
	var cxlinks []CxLink

	count, err := c.GetCxLinkCountFiltered(filter)
	if err != nil {
		return count, cxlinks, err
	}
	_, cxlinks, err = c.GetXCxLinksFiltered(filter, count)
	return count, cxlinks, err
}

// Retrieves the top 'count' cxlinks matching the filter
func (c *Cx1Client) GetXCxLinksFiltered(filter CxLinkFilter, count uint64) (uint64, []CxLink, error) {
	var cxlinks []CxLink

	_, projs, err := c.GetCxLinksFiltered(filter)
	cxlinks = projs

	for err == nil && count > filter.Offset+filter.Limit && filter.Limit > 0 && uint64(len(cxlinks)) < count {
		filter.Bump()
		_, projs, err = c.GetCxLinksFiltered(filter)
		cxlinks = append(cxlinks, projs...)
	}

	if uint64(len(cxlinks)) > count {
		return count, cxlinks[:count], err
	}

	return count, cxlinks, err
}

func (c *Cx1Client) GetCxLinkCountFiltered(filter CxLinkFilter) (uint64, error) {
	filter.Limit = 1
	params, _ := query.Values(filter)
	c.logger.Debugf("Get Cx1 CxLink count matching filter: %v", params.Encode())
	count, _, err := c.GetCxLinksFiltered(filter)
	return count, err
}

func (c CxLink) String() string {
	return fmt.Sprintf("[%v] %v", ShortenGUID(c.LinkID), c.Name)
}

func (c CxLink) StringDetailed() string {
	return fmt.Sprintf("[%v] %v (%v -> %v): %v", ShortenGUID(c.LinkID), c.Name, c.LinkURL, c.PrivateURL, c.Description)
}
