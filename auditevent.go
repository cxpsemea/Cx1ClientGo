package Cx1ClientGo

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/go-querystring/query"
)

func (c *Cx1Client) GetAllAuditEvents() ([]AuditEvent, error) {
	_, events, err := c.GetAllAuditEventsFiltered(AuditEventFilter{
		BaseFilter: BaseFilter{Limit: c.config.Pagination.AuditEvents},
	})

	return events, err
}

// Underlying function used by many GetAuditEvent* calls
// Returns the total number of matching results plus an array of auditevents with
// one page of results (from filter.Offset to filter.Offset+filter.Limit)
func (c *Cx1Client) GetAuditEventsFiltered(filter AuditEventFilter) (uint64, []AuditEvent, error) {
	params, _ := query.Values(filter)

	var AuditEventResponse struct {
		Links struct {
			TotalFilteredCount uint64 `json:"totalFilteredCount"`
		} `json:"Links"`
		AuditEvents []AuditEvent `json:"events"`
	}

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/audit-events?%v", params.Encode()), nil, nil)

	if err != nil {
		return AuditEventResponse.Links.TotalFilteredCount, AuditEventResponse.AuditEvents, err
	}

	err = json.Unmarshal(response, &AuditEventResponse)
	return AuditEventResponse.Links.TotalFilteredCount, AuditEventResponse.AuditEvents, err
}

// Retrieves all auditevents matching the filter
func (c *Cx1Client) GetAllAuditEventsFiltered(filter AuditEventFilter) (uint64, []AuditEvent, error) {
	if filter.Limit == 0 {
		filter.Limit = c.config.Pagination.AuditEvents
	}
	var auditevents []AuditEvent
	count, err := c.GetAuditEventsCountFiltered(filter)
	if err != nil {
		return count, auditevents, err
	}
	_, auditevents, err = c.GetXAuditEventsFiltered(filter, count)
	return count, auditevents, err
}

// Retrieves the top 'count' auditevents matching the filter
func (c *Cx1Client) GetXAuditEventsFiltered(filter AuditEventFilter, count uint64) (uint64, []AuditEvent, error) {
	var auditevents []AuditEvent

	c.config.Logger.Tracef("Get X=%d Cx1 Audit Events matching filter: %v", count, filter)
	_, projs, err := c.GetAuditEventsFiltered(filter)
	auditevents = projs

	for err == nil && count > filter.Offset+filter.Limit && filter.Limit > 0 && uint64(len(auditevents)) < count {
		filter.Bump()
		_, projs, err = c.GetAuditEventsFiltered(filter)
		auditevents = append(auditevents, projs...)
	}

	if uint64(len(auditevents)) > count {
		return count, auditevents[:count], err
	}

	return count, auditevents, err
}

// Get the count of all projects matching the filter
func (c *Cx1Client) GetAuditEventsCountFiltered(filter AuditEventFilter) (uint64, error) {
	filter.Limit = 1
	count, _, err := c.GetAuditEventsFiltered(filter)
	return count, err
}
