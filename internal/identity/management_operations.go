package identity

import (
	"slices"
	"strings"

	"github.com/euyuil/memberid/internal/authorization"
)

const (
	actionCreate       = "create"
	actionList         = "list"
	actionGet          = "get"
	actionUpdate       = "update"
	actionDelete       = "delete"
	actionStatusUpdate = "status.update"
)

// These templates are internal resource definitions, not runtime scope syntax.
// Callers supply IDs in placeholder order; policy selectors use pattern instead
// of require so a wildcard can never become a concrete operation target.
type managementResource string

const (
	organizationsResource                    managementResource = "organizations"
	organizationResource                     managementResource = organizationsResource + "/{organizationId}"
	membersResource                          managementResource = organizationResource + "/members"
	memberResource                           managementResource = membersResource + "/{memberId}"
	bindingsResource                         managementResource = memberResource + "/bindings"
	bindingResource                          managementResource = bindingsResource + "/{bindingId}"
	roleAssignmentsResource                  managementResource = organizationResource + "/roleAssignments"
	roleAssignmentResource                   managementResource = roleAssignmentsResource + "/{memberId}"
	providersResource                        managementResource = organizationResource + "/providers"
	providerTypeResource                     managementResource = providersResource + "/{providerType}"
	providerResource                         managementResource = providerTypeResource + "/{providerId}"
	organizationEventsResource               managementResource = organizationResource + "/managementEvents"
	memberDirectoryResource                  managementResource = "memberDirectory"
	managementEventsResource                 managementResource = "managementEvents"
	authenticationEventsResource             managementResource = "authenticationEvents"
	authenticationEventResource              managementResource = authenticationEventsResource + "/{eventId}"
	organizationAuthenticationEventsResource managementResource = organizationResource + "/authenticationEvents"
	organizationAuthenticationEventResource  managementResource = organizationAuthenticationEventsResource + "/{eventId}"
)

// Registered operations constrain even a platform-wide wildcard. Adding a
// permission does not introduce an endpoint or bypass its entry contract.
// Existing assignments use the Member ID as their logical deletion key.
var managementOperations = map[managementResource][]string{
	organizationsResource:                    {actionCreate, actionList},
	organizationResource:                     {actionGet, actionUpdate, actionStatusUpdate},
	membersResource:                          {actionCreate, actionList},
	memberResource:                           {actionGet, actionUpdate, actionStatusUpdate},
	bindingsResource:                         {actionList, actionCreate},
	bindingResource:                          {actionDelete},
	roleAssignmentsResource:                  {actionCreate, actionList},
	roleAssignmentResource:                   {actionDelete},
	providersResource:                        {actionList},
	providerTypeResource:                     {actionCreate},
	providerResource:                         {actionUpdate, actionStatusUpdate},
	organizationEventsResource:               {actionList},
	memberDirectoryResource:                  {actionList},
	managementEventsResource:                 {actionList},
	authenticationEventsResource:             {actionList},
	authenticationEventResource:              {actionGet},
	organizationAuthenticationEventsResource: {actionList},
	organizationAuthenticationEventResource:  {actionGet},
}

func (resource managementResource) require(action string, ids ...string) authorization.Requirement {
	if !slices.Contains(managementOperations[resource], action) {
		return authorization.Requirement{}
	}
	return authorization.Requirement{Target: resource.path(false, ids), Action: action}
}

func (resource managementResource) pattern(ids ...string) string {
	return resource.path(true, ids)
}

// Invalid arguments produce an invalid empty path, never a broader target.
func (resource managementResource) path(pattern bool, ids []string) string {
	if _, ok := managementOperations[resource]; !ok {
		return ""
	}
	parts := strings.Split(string(resource), "/")
	next := 0
	for index, part := range parts {
		if !strings.HasPrefix(part, "{") {
			continue
		}
		if next == len(ids) {
			return ""
		}
		value := ids[next]
		if !(pattern && (value == "?" || value == "*")) && !validManagementPart(part, value) {
			return ""
		}
		parts[index] = value
		next++
	}
	if next != len(ids) {
		return ""
	}
	return strings.Join(parts, "/")
}

func registeredManagementOperation(requirement authorization.Requirement) bool {
	parts := strings.Split(requirement.Target, "/")
	for resource, actions := range managementOperations {
		if !slices.Contains(actions, requirement.Action) {
			continue
		}
		template := strings.Split(string(resource), "/")
		if len(parts) != len(template) {
			continue
		}
		matched := true
		for index, part := range template {
			if !validManagementPart(part, parts[index]) {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

func validManagementPart(template, value string) bool {
	if strings.ContainsAny(value, "/?*") {
		return false
	}
	switch template {
	case "{organizationId}":
		return ValidID(value, OrganizationKind)
	case "{memberId}":
		return ValidID(value, MemberKind)
	case "{bindingId}":
		return ValidUUID(value)
	case "{eventId}":
		return validEventReference(value)
	case "{providerType}":
		return value == "dingtalk" || value == "feishu"
	case "{providerId}":
		return validText(value, 128)
	default:
		return template == value
	}
}
