package identity

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/euyuil/memberid/internal/authevent"
	"github.com/jackc/pgx/v5"
)

// Filters only narrow an already-authorized collection. They confer no ownership.
type AuthenticationEventFilter struct {
	Type, Outcome, Method, MemberID, ClientID, GrantID, RequestID, InteractionID string
	From, To, After                                                              string
	Limit                                                                        int
}

type AuthenticationEventPage struct {
	Page[authevent.Event]
	OrganizationNames map[string]string `json:"organizationNames"`
}

var eventReference = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)

func validEventReference(value string) bool { return eventReference.MatchString(value) }

type eventCursor struct {
	At time.Time `json:"at"`
	ID string    `json:"id"`
}

func encodeEventCursor(event authevent.Event) string {
	data, _ := json.Marshal(eventCursor{event.OccurredAt, event.EventID})
	return base64.RawURLEncoding.EncodeToString(data)
}

func (filter AuthenticationEventFilter) validate() (from, to time.Time, cursor eventCursor, err error) {
	invalid := func() (time.Time, time.Time, eventCursor, error) {
		return time.Time{}, time.Time{}, eventCursor{}, ErrInvalid
	}
	if filter.Limit < 1 || filter.Limit > 100 ||
		!slices.Contains([]string{"", "sms.send", "authentication.verify", "oidc.grant.issue", "oidc.authorizationCode.reuse", "oidc.refreshToken.reuse", "session.revoke", "grant.revoke"}, filter.Type) ||
		!slices.Contains([]string{"", "succeeded", "rejected", "failed", "detected"}, filter.Outcome) ||
		!slices.Contains([]string{"", "sms", "dingtalk", "feishu"}, filter.Method) ||
		filter.MemberID != "" && !ValidID(filter.MemberID, MemberKind) {
		return invalid()
	}
	for _, value := range []string{filter.ClientID, filter.GrantID, filter.RequestID, filter.InteractionID} {
		if value != "" && !validEventReference(value) {
			return invalid()
		}
	}
	if filter.From != "" {
		from, err = time.Parse(time.RFC3339Nano, filter.From)
		if err != nil {
			return invalid()
		}
	}
	if filter.To != "" {
		to, err = time.Parse(time.RFC3339Nano, filter.To)
		if err != nil || !from.IsZero() && !to.After(from) {
			return invalid()
		}
	}
	if filter.After != "" {
		if len(filter.After) > 512 {
			return invalid()
		}
		data, decodeErr := base64.RawURLEncoding.DecodeString(filter.After)
		if decodeErr != nil || json.Unmarshal(data, &cursor) != nil || cursor.At.IsZero() || !validEventReference(cursor.ID) {
			return invalid()
		}
	}
	return from, to, cursor, nil
}

const authenticationEventColumns = `e.event_id,e.event_type,e.outcome,e.organization_id,e.member_id,e.client_id,e.interaction_id,e.request_id,e.occurred_at,e.recorded_at,e.data,
 ($1='' OR EXISTS(SELECT 1 FROM authentication_events cause WHERE cause.event_id=e.data->>'causationId' AND cause.organization_id=$1 AND cause.occurred_at>$2))`
const authenticationEventWhere = ` FROM authentication_events e WHERE ($1='' OR e.organization_id=$1) AND e.occurred_at>$2`

func readAuthenticationEvent(row pgx.Row, organizationView bool) (authevent.Event, error) {
	var columns, event authevent.Event
	var data []byte
	var visibleCause bool
	err := row.Scan(&columns.EventID, &columns.Type, &columns.Outcome, &columns.OrganizationID, &columns.MemberID, &columns.ClientID, &columns.InteractionID, &columns.RequestID, &columns.OccurredAt, &columns.RecordedAt, &data, &visibleCause)
	if err != nil {
		return event, storageError(err)
	}
	if err := json.Unmarshal(data, &event); err != nil {
		return authevent.Event{}, err
	}
	// Ownership and pagination use indexed database values, including PostgreSQL
	// timestamp precision, rather than potentially different JSON timestamps.
	event.EventID, event.Type, event.Outcome = columns.EventID, columns.Type, columns.Outcome
	event.OrganizationID, event.MemberID, event.ClientID = columns.OrganizationID, columns.MemberID, columns.ClientID
	event.InteractionID, event.RequestID = columns.InteractionID, columns.RequestID
	event.OccurredAt, event.RecordedAt = columns.OccurredAt.UTC(), columns.RecordedAt.UTC()
	if organizationView {
		event.FactorID, event.SessionID = "", ""
		if event.Actor.Kind == "factor" || event.Actor.Kind == "member" && event.Actor.ID != event.MemberID {
			event.Actor = authevent.Actor{}
		}
		if !visibleCause {
			event.CausationID = ""
		}
	}
	return event, nil
}

func (service *ManagementService) AuthenticationEvents(ctx context.Context, principal Principal, organizationID string, filter AuthenticationEventFilter) (AuthenticationEventPage, error) {
	page := AuthenticationEventPage{Page: Page[authevent.Event]{Items: []authevent.Event{}}, OrganizationNames: map[string]string{}}
	requirement := authenticationEventsResource.require(actionList)
	if organizationID != "" {
		requirement = organizationAuthenticationEventsResource.require(actionList, organizationID)
	}
	if err := service.store.authorizeManagementRead(ctx, principal, requirement); err != nil {
		return page, err
	}
	from, to, cursor, err := filter.validate()
	if err != nil {
		return page, err
	}
	if service.authenticationEventRetention <= 0 {
		return page, ErrInvalid
	}
	args := []any{organizationID, time.Now().UTC().Add(-service.authenticationEventRetention)}
	query := "SELECT " + authenticationEventColumns + authenticationEventWhere
	add := func(expression string, value any) {
		args = append(args, value)
		query += fmt.Sprintf(expression, len(args))
	}
	for _, condition := range []struct{ column, value string }{
		{"e.event_type", filter.Type}, {"e.outcome", filter.Outcome}, {"e.data->>'method'", filter.Method},
		{"e.member_id", filter.MemberID}, {"e.client_id", filter.ClientID}, {"e.data->>'grantId'", filter.GrantID},
		{"e.request_id", filter.RequestID}, {"e.interaction_id", filter.InteractionID},
	} {
		if condition.value != "" {
			add(" AND "+condition.column+"=$%d", condition.value)
		}
	}
	if !from.IsZero() {
		add(" AND e.occurred_at >= $%d", from)
	}
	if !to.IsZero() {
		add(" AND e.occurred_at < $%d", to)
	}
	if !cursor.At.IsZero() {
		args = append(args, cursor.At, cursor.ID)
		query += fmt.Sprintf(" AND (e.occurred_at,e.event_id)<($%d,$%d)", len(args)-1, len(args))
	}
	add(" ORDER BY e.occurred_at DESC,e.event_id DESC LIMIT $%d", filter.Limit+1)
	rows, err := service.store.pool.Query(ctx, query, args...)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		event, err := readAuthenticationEvent(rows, organizationID != "")
		if err != nil {
			return page, err
		}
		if len(page.Items) == filter.Limit {
			page.NextAfter = encodeEventCursor(page.Items[filter.Limit-1])
			break
		}
		page.Items = append(page.Items, event)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return page, err
	}
	organizationIDs := []string{}
	for _, event := range page.Items {
		if event.OrganizationID != "" && !slices.Contains(organizationIDs, event.OrganizationID) {
			organizationIDs = append(organizationIDs, event.OrganizationID)
		}
	}
	if len(organizationIDs) == 0 {
		return page, nil
	}
	// Resolve current display names only for organizations in the authorized page.
	// These names are presentation metadata, not historical event snapshots.
	names, err := service.store.pool.Query(ctx, "SELECT id,name FROM organizations WHERE id=ANY($1)", organizationIDs)
	if err != nil {
		return page, err
	}
	defer names.Close()
	for names.Next() {
		var id, name string
		if err := names.Scan(&id, &name); err != nil {
			return page, err
		}
		page.OrganizationNames[id] = name
	}
	return page, names.Err()
}

func (service *ManagementService) AuthenticationEvent(ctx context.Context, principal Principal, organizationID, eventID string) (authevent.Event, error) {
	requirement := authenticationEventResource.require(actionGet, eventID)
	if organizationID != "" {
		requirement = organizationAuthenticationEventResource.require(actionGet, organizationID, eventID)
	}
	if err := service.store.authorizeManagementRead(ctx, principal, requirement); err != nil {
		return authevent.Event{}, err
	}
	if service.authenticationEventRetention <= 0 {
		return authevent.Event{}, ErrInvalid
	}
	return readAuthenticationEvent(service.store.pool.QueryRow(ctx, "SELECT "+authenticationEventColumns+authenticationEventWhere+" AND e.event_id=$3", organizationID, time.Now().UTC().Add(-service.authenticationEventRetention), eventID), organizationID != "")
}
