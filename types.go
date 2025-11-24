package Cx1ClientGo

import (
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type Logger interface {
	Tracef(format string, args ...interface{})
	Debugf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
	Fatalf(format string, args ...interface{})
}

type Cx1Client struct {
	httpClient *http.Client
	//authToken  string
	baseUrl    string
	iamUrl     string
	tenant     string
	logger     Logger
	flags      map[string]bool // initial implementation ignoring "payload" part of the flag
	consts     ClientVars
	pagination PaginationSettings

	auth     Cx1ClientAuth
	claims   Cx1Claims
	user     *User
	client   *OIDCClient
	IsUser   bool
	userinfo Cx1TokenUserInfo

	version         *VersionInfo
	astAppID        string
	tenantID        string
	cx1UserAgent    string
	tenantOwner     *TenantOwner
	maxRetries      int
	retryDelay      int
	suppressdepwarn bool
}

type Cx1TokenUserInfo struct {
	UserID     string // token.sub
	UserName   string // token.preferred_username
	ClientName string // token.azp
}

type Cx1ClientAuth struct {
	APIKey       string
	ClientID     string
	ClientSecret string
	AccessToken  string
	Expiry       time.Time
}

type Cx1Claims struct {
	jwt.RegisteredClaims
	Cx1License    ASTLicense `json:"ast-license"`
	IsServiceUser string     `json:"is-service-user"`
	ISS           string     `json:"iss"`
	UserID        string     `json:"sub"`
	Username      string     `json:"name"`
	ClientID      string     `json:"clientId"`
	ASTBaseURL    string     `json:"ast-base-url"`
	TenantID      string     `json:"tenant_id"`
	TenantName    string     `json:"tenant_name"`
	Email         string     `json:"email"`
	Expiry        int64      `json:"exp"`
	AZP           string     `json:"azp"`

	// the following are generated during parsing
	IAMURL     string    `json:"-"`
	ExpiryTime time.Time `json:"-"`
}
type ASTLicense struct {
	ID          int
	TenantID    string
	PackageName string
	LicenseData struct {
		AllowedEngines     []string
		APISecurityEnabled bool
		CodebashingEnabled bool
		DASTEnabled        bool
		MaxConcurrentScans int
		SCSEnabled         bool
		ServiceType        string
		Services           []string
		UsersCount         int
	}
}

type TenantOwner struct {
	Username  string
	Firstname string
	Lastname  string
	Email     string
	UserID    string `json:"id"`
}

type ClientVars struct {
	MigrationPollingMaxSeconds                int
	MigrationPollingDelaySeconds              int
	AuditEnginePollingMaxSeconds              int
	AuditEnginePollingDelaySeconds            int
	AuditScanPollingMaxSeconds                int
	AuditScanPollingDelaySeconds              int
	AuditCompilePollingMaxSeconds             int
	AuditCompilePollingDelaySeconds           int
	AuditLanguagePollingMaxSeconds            int
	AuditLanguagePollingDelaySeconds          int
	ReportPollingMaxSeconds                   int
	ReportPollingDelaySeconds                 int
	ExportPollingMaxSeconds                   int
	ExportPollingDelaySeconds                 int
	ScanPollingMaxSeconds                     int
	ScanPollingDelaySeconds                   int
	ProjectApplicationLinkPollingMaxSeconds   int
	ProjectApplicationLinkPollingDelaySeconds int
}

// Related to pagination and filtering
type PaginationSettings struct {
	Applications     uint64
	Branches         uint64
	Clients          uint64
	CxLinks          uint64
	Groups           uint64
	GroupMembers     uint64
	Policies         uint64
	PolicyViolations uint64
	Projects         uint64
	ProjectOverviews uint64
	Results          uint64
	Scans            uint64
	ScanSchedules    uint64
	SASTAggregate    uint64
	Users            uint64
}

type BaseFilter struct {
	Offset uint64 `url:"offset"` // offset is set automatically for pagination
	Limit  uint64 `url:"limit"`  // limit is set automatically for pagination, should generally not be 0
}

type BaseIAMFilter struct {
	First uint64 `url:"first"` // offset is set automatically for pagination
	Max   uint64 `url:"max"`   // limit is set automatically for pagination, should generally not be 0
}

type BasePolicyFilter struct {
	Page  uint64 `url:"page"`  // eg offset = (page-1)*limit
	Limit uint64 `url:"limit"` // limit is set automatically for pagination, should generally not be 0
}

type BaseFilteredResponse struct {
	TotalCount         uint64 `json:"totalCount"`
	FilteredTotalCount uint64 `json:"filteredTotalCount"`
}

type AccessAssignment struct {
	TenantID     string               `json:"tenantID"`
	EntityID     string               `json:"entityID"`
	EntityType   string               `json:"entityType"`
	EntityName   string               `json:"entityName"`
	EntityRoles  []AccessAssignedRole `json:"entityRoles"`
	ResourceID   string               `json:"resourceID"`
	ResourceType string               `json:"resourceType"`
	ResourceName string               `json:"resourceName"`
	CreatedAt    string               `json:"createdAt"`
}

type AccessAssignedRole struct {
	Id   string `json:"id"`
	Name string `json:"name"`
}

type AccessibleResource struct {
	ResourceID   string   `json:"resourceId"`
	ResourceType string   `json:"resourceType"`
	ResourceName string   `json:"resourceName"`
	Roles        []string `json:"roles"`
}

type AnalyticsTime struct {
	time.Time
}

type AnalyticsFilter struct {
	Projects        []string       `json:"projects,omitempty"`
	Applications    []string       `json:"applications,omitempty"`
	Scanners        []string       `json:"scanners,omitempty"`
	ApplicationTags []string       `json:"applicationTags,omitempty"`
	ProjectTags     []string       `json:"projectTags,omitempty"`
	ScanTags        []string       `json:"scanTags,omitempty"`
	States          []string       `json:"states,omitempty"` // toVerify,notExploitable,proposedNotExploitable,confirmed,urgent
	Status          []string       `json:"status,omitempty"`
	Severities      []string       `json:"severities,omitempty"`
	BranchNames     []string       `json:"branchNames,omitempty"`
	Timezone        string         `json:"timezone,omitempty"`
	Groups          []string       `json:"groupIds,omitempty"`
	StartDate       *AnalyticsTime `json:"startDate,omitempty"`
	EndDate         *AnalyticsTime `json:"endDate,omitempty"`
}

type AnalyticsDistributionEntry struct {
	Label      string  `json:"label"`
	Density    float32 `json:"density"`
	Percentage float32 `json:"percentage"`
	Results    uint64  `json:"results"`
}
type AnalyticsDistributionBlock struct {
	Label  string                       `json:"label"`
	Values []AnalyticsDistributionEntry `json:"values"`
}
type AnalyticsDistributionStats struct {
	Distribution []AnalyticsDistributionBlock `json:"distribution"`
	LOC          uint64                       `json:"loc"`
	Total        uint64                       `json:"total"`
}

type AnalyticsIDEStatEntry struct {
	Label      string  `json:"label"`
	Scans      float32 `json:"scans"`
	Developers float32 `json:"developers"`
}

type AnalyticsIDEOverTimeEntry struct {
	Label      string        `json:"label"`
	Scans      float32       `json:"scans"`
	Developers float32       `json:"developers"`
	Date       AnalyticsTime `json:"date"`
}

type AnalyticsIDEOverTimeDistribution struct {
	Label  string                      `json:"label"`
	Values []AnalyticsIDEOverTimeEntry `json:"values"`
}

type AnalyticsOverTimeEntry struct {
	Time  uint64        `json:"time"`
	Value float32       `json:"value"`
	Date  AnalyticsTime `json:"date"`
}
type AnalyticsOverTimeStats struct {
	Label  string                   `json:"label"`
	Values []AnalyticsOverTimeEntry `json:"values"`
}

type AnalyticsLabeledResultsCountEntry struct {
	Label   string `json:"label"`
	Results int64  `json:"results"`
}
type AnalyticsSeverityAndStateStats struct {
	Label      string                              `json:"label"`
	Results    int64                               `json:"results"`
	Severities []AnalyticsLabeledResultsCountEntry `json:"severities"`
}
type AnalyticsAgingStats struct { // identical structure to AnalyticsSeverityAndStateStats
	Label      string                              `json:"label"`
	Results    int64                               `json:"results"`
	Severities []AnalyticsLabeledResultsCountEntry `json:"severities"`
}

type AnalyticsMeanTimeEntry struct {
	Label    string `json:"label"`
	Results  int64  `json:"results"`
	MeanTime int64  `json:"meanTime"`
}
type AnalyticsMeanTimeStats struct {
	MeanTimeData      []AnalyticsMeanTimeEntry `json:"meanTimeData"`
	MeanTimeStateData []AnalyticsMeanTimeEntry `json:"meanTimeStateData"`
	TotalResults      int64                    `json:"totalResults"`
}

type AnalyticsVulnerabilitiesStats struct {
	VulnerabilityName string                              `json:"vulnerabilityName"`
	Total             int64                               `json:"total"`
	Severities        []AnalyticsLabeledResultsCountEntry `json:"severities"`
}

type Application struct {
	ApplicationID      string            `json:"id"`
	Name               string            `json:"name"`
	Description        string            `json:"description"`
	Criticality        uint              `json:"criticality"`
	Rules              []ApplicationRule `json:"rules"`
	Tags               map[string]string `json:"tags"`
	ProjectIds         *[]string         `json:"projectIds,omitempty"`
	originalProjectIds []string          `json:"-"` // Cx1clientgo internal/restricted, do not change
	CreatedAt          string            `json:"createdAt"`
	UpdatedAt          string            `json:"updatedAt"`
}

type ApplicationPatch struct {
	Name        *string            `json:"name,omitempty"`
	Description *string            `json:"description,omitempty"`
	Criticality *uint              `json:"criticality,omitempty"`
	Tags        *map[string]string `json:"tags,omitempty"`
}

type ApplicationFilter struct {
	BaseFilter
	Name       string   `url:"name,omitempty"`
	TagsKeys   []string `url:"tags-keys,omitempty"`
	TagsValues []string `url:"tags-values,omitempty"`
}

type ApplicationRule struct {
	ID    string `json:"id"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

type ApplicationOverview struct {
	ApplicationID string            `json:"applicationId"`
	Name          string            `json:"applicationName"`
	Criticality   uint64            `json:"criticality"`
	ProjectNumber uint64            `json:"projectNumber"`
	RiskLevel     string            `json:"riskLevel"`
	Tags          map[string]string `json:"tags"`
	TotalCounters struct {
		SeverityCounters []ScanSummarySeverityCounter `json:"severityCounters"`
	} `json:"totalCounters"`
}

type ApplicationOverviewFilter struct { // max limit = 100
	BaseFilter
	Name        []string `url:"name,omitempty"`
	RiskLevel   []string `url:"risk-level,omitempty"`
	EmptyTags   bool     `url:"empty-tags,omitempty"`
	Criticality []uint64 `url:"criticality"`
	Sort        []string `url:"sort,omitempty"` //  nname, criticality, num-of-projects, risk-level
}

type AuditIACQuery struct {
	QueryID  string `json:"id"`
	Key      string `json:"-"`
	Name     string
	Level    string
	LevelID  string
	Path     string
	Source   string
	Metadata AuditIACQueryMetadata
}
type AuditIACQueryMetadata struct {
	Aggregation    string `json:"aggregation,omitempty"`
	Category       string `json:"category,omitempty"`
	CloudProvider  string `json:"cloudprovider,omitempty"`
	Cwe            string `json:"cwe,omitempty"`
	Description    string `json:"description,omitempty"`
	DescriptionID  string `json:"descriptionId,omitempty"`
	DescriptionURL string `json:"descriptionurl,omitempty"`
	OldSeverity    string `json:"oldseverity,omitempty"`
	Platform       string `json:"platform"`
	QueryID        string `json:"queryId"`
	Name           string `json:"queryname"`
	Severity       string `json:"severity"`
}

type AuditSASTQuery struct {
	Key      string `json:"id"`
	Name     string
	Level    string
	LevelID  string
	Path     string
	Source   string
	Metadata AuditSASTQueryMetadata
}
type AuditSASTQueryMetadata struct {
	Cwe             int64  `json:"cwe,omitempty"`
	IsExecutable    bool   `json:"executable"`
	CxDescriptionID int64  `json:"description,omitempty"`
	Language        string `json:"language"`
	Group           string `json:"group"`
	Severity        string `json:"severity"`
	SastID          uint64 `json:"sastId,omitempty"`
	Name            string `json:"name"`
}

type AuditQueryTree struct {
	IsLeaf bool
	Title  string
	Key    string
	Data   struct {
		Level    string
		Severity string
		CWE      int64
		Custom   bool
	}
	Children []AuditQueryTree
}

type AuditPermissions struct {
	View   bool `json:"view"`
	Update bool `json:"update"`
	Create bool `json:"create"`
	Delete bool `json:"delete"`
}

type AuditSession struct {
	ID   string `json:"id"`
	Data struct {
		Status       string   `json:"status"`
		RequestID    string   `json:"requestId"`
		QueryFilters []string `json:"queryFilters"`
		Permissions  struct {
			Tenant      AuditPermissions `json:"tenant"`
			Project     AuditPermissions `json:"project"`
			Application AuditPermissions `json:"application"`
		} `json:"permissions"`
	} `json:"data"`
	ProjectName            string    `json:"projectName"`
	QueryBuilder           bool      `json:"queryBuilder"`
	ApplicationAssociation bool      `json:"applicationAssociation"`
	Status                 string    `json:"status"`
	Value                  []string  `json:"value"`
	Engine                 string    `json:"-"`
	ProjectID              string    `json:"-"`
	ApplicationID          string    `json:"-"`
	ScanID                 string    `json:"-"`
	Languages              []string  `json:"-"`
	Platforms              []string  `json:"-"`
	CreatedAt              time.Time `json:"-"`
	LastHeartbeat          time.Time `json:"-"`
}

type AuditSessionFilters map[string]AuditSessionLanguageFilters

type AuditSessionLanguageFilters struct {
	Description string
	Filters     []AuditSessionLanguage
}

type AuditSessionLanguage struct {
	Key   string
	Title string
	Icon  string
}

type AuditScanSourceFile struct {
	IsLeaf   bool                  `json:"isLeaf"`
	Title    string                `json:"title"`
	Key      string                `json:"key"`
	Children []AuditScanSourceFile `json:"children"`
}

type AuthenticationProvider struct {
	Alias      string `json:"alias"`
	ID         string `json:"internalId,omitempty"`
	ProviderID string `json:"providerId"`
}

type AuthenticationProviderMapper struct {
	ID     string                             `json:"id,omitempty"`
	Name   string                             `json:"name"`
	Alias  string                             `json:"identityProviderAlias"`
	Mapper string                             `json:"identityProviderMapper"`
	Config AuthenticationProviderMapperConfig `json:"config"`
}

type AuthenticationProviderMapperConfig struct {
	SyncMode      string `json:"syncMode"`
	UserAttribute string `json:"user.attribute,omitempty"`
	FriendlyName  string `json:"attribute.friendly.name,omitempty"`
	Format        string `json:"attribute.name.format,omitempty"`
	Name          string `json:"attribute.name,omitempty"`
	Role          string `json:"attribute.role,omitempty"`
	Value         string `json:"attribute.value,omitempty"`
	Target        string `json:"target,omitempty"`
	Template      string `json:"template,omitempty"`
}

type ConfigurationSetting struct {
	Key             string `json:"key,omitempty"`
	Name            string `json:"name,omitempty"`
	Category        string `json:"category,omitempty"`
	OriginLevel     string `json:"originLevel,omitempty"`
	Value           string `json:"value,omitempty"`
	ValueType       string `json:"valuetype,omitempty"`
	ValueTypeParams string `json:"valuetypeparams,omitempty"`
	AllowOverride   bool   `json:"allowOverride,omitempty"`
}

type CxLink struct {
	LinkID      string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	PrivateURL  string    `json:"privateUrl"`
	LinkURL     string    `json:"linkUrl"`
	TunnelName  string    `json:"tunnelName"` // unique tunnel name
	State       string    `json:"state"`
	CreatedAt   time.Time `json:"createdAt"`
}

type CxLinkResponse struct {
	Link      CxLink `json:"link"`
	Token     string `json:"token"`
	ServerURL string `json:"tunnelServerUrl"`
}

type CxLinkFilter struct {
	BaseFilter
}

type DataImport struct {
	MigrationId string             `json:"migrationId"`
	Status      string             `json:"status"`
	CreatedAt   string             `json:"createdAt"`
	Logs        []DataImportStatus `json:"logs"`
}

type DataImportStatus struct {
	Level   string `json:"level"`
	Message string `json:"msg"`
	Error   string `json:"error"`
	Worker  string `json:"worker"`
	RawLog  string `json:"raw_log"`
}

type ExportStatus struct {
	ExportID  string `json:"exportId"`
	Status    string `json:"exportStatus"`
	ExportURL string `json:"fileUrl"`
}

type Group struct {
	GroupID         string              `json:"id"`
	ParentID        string              `json:"parentId"`
	Name            string              `json:"name"`
	Path            string              `json:"path"`
	SubGroups       []Group             `json:"subGroups"`
	SubGroupCount   uint64              `json:"subGroupCount"`
	DescendentCount uint64              `json:"-"`
	ClientRoles     map[string][]string `json:"clientRoles"`
	RealmRoles      []string            `json:"realmRoles"`
	Filled          bool                `json:"-"`
}

type GroupFilter struct {
	BaseIAMFilter
	BriefRepresentation *bool  `url:"briefRepresentation,omitempty"`
	Exact               *bool  `url:"exact,omitempty"`
	PopulateHierarchy   *bool  `url:"populateHierarchy,omitempty"`
	Q                   *bool  `url:"q,omitempty"`
	Search              string `url:"search,omitempty"` // used in both GetGroup and GetGroupCount
	Top                 bool   `url:"-"`                // used only in GetGroupCount
}

type GroupMembersFilter struct {
	BaseIAMFilter
	BriefRepresentation bool `url:"briefRepresentation,omitempty"`
}

/*
type IACPreset struct {
	PresetBase
	IACQueryIDs []string
	//Queries  []SASTQuery `json:"-"`
}
*/

type IACQuery struct {
	QueryID        string `json:"queryId"` // this is a unique ID per query per level (eg: query1 tenant-level override will have a different ID from the query1 project-level override)
	Name           string `json:"name"`
	Description    string `json:"description"`
	DescriptionID  string `json:"descriptionId"`
	DescriptionURL string `json:"descriptionUrl"`
	Platform       string `json:"platform"`
	Group          string `json:"group"` // aka cloudprovider?
	Category       string `json:"category"`
	Severity       string `json:"severity"`
	CWE            string `json:"cwe"`
	Level          string `json:"level"`
	LevelID        string `json:"-"`
	Custom         bool   `json:"-"`
	Key            string `json:"-"` // this is the ID of the query consistent across overrides (eg: query1 tenant-level override will have the same ID as the query1 project-level override)
	Path           string `json:"path"`
	Source         string `json:"-"`
}
type IACQueryGroup struct {
	Name     string
	Platform string
	Queries  []IACQuery
}
type IACQueryPlatform struct {
	Name        string
	QueryGroups []IACQueryGroup
}

type IACQueryCollection struct {
	Platforms []IACQueryPlatform
}

type QueryCollection interface {
	GetQueryFamilies(executableOnly bool) []QueryFamily
}

type OIDCClient struct {
	ID                   string                 `json:"id"`
	ClientID             string                 `json:"clientId"`
	Enabled              bool                   `json:"enabled"`
	ClientSecret         string                 `json:"secret"`
	ClientSecretExpiry   uint64                 `json:"-"` // this is the actual time/date it will expire
	SecretExpirationDays uint64                 `json:"-"` // this is the number of days after which a secret will expire
	Creator              string                 `json:"-"`
	OIDCClientRaw        map[string]interface{} `json:"-"`
}

type OIDCClientScope struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Protocol    string `json:"protocol"`
}

type OIDCClientFilter struct {
	BaseIAMFilter
	ClientID     string `url:"clientId,omitempty"`
	Q            string `url:"q,omitempty"`
	Search       *bool  `url:"search,omitempty"`
	ViewableOnly *bool  `url:"viewableOnly,omitempty"`
}

type Policy struct {
	PolicyID     uint64    `json:"id"`
	Name         string    `json:"name"`
	Description  string    `json:"description"`
	IsActivated  bool      `json:"isActivated"`
	Tags         []string  `json:"tags"`
	BreakBuild   bool      `json:"breakBuild"`
	PinPolicy    bool      `json:"pinPolicy"`
	LastViolated time.Time `json:"lastViolated"`
	UpdatedAt    time.Time `json:"updatedAt"`
	Projects     []struct {
		AstProjectID string `json:"astProjectId"`
	} `json:"projects"`
	NetNewBreakBuild       bool   `json:"netNewBreakBuild"`
	Type                   string `json:"type"`
	AllScannersSeverities  []any  `json:"allScannersSeverities"`
	ViolatingAssocProjects struct {
		AssocProjects uint64 `json:"assocProjects"`
		Violating     uint64 `json:"violating"`
	} `json:"violatingAssocProjects"`
	DefaultPolicy bool `json:"defaultPolicy"`
}

type PolicyFilter struct {
	BasePolicyFilter
}

type PolicyViolation struct {
	ViolationID             uint64    `json:"id"`
	PolicyName              string    `json:"policyName"`
	ProjectName             string    `json:"projectName"`
	Branch                  string    `json:"branch"`
	RuleName                string    `json:"ruleName"`
	ScanID                  string    `json:"scanId"`
	ScanDate                time.Time `json:"scanDate"`
	PolicyTags              []string  `json:"policyTags"`
	DefaultPolicy           bool      `json:"defaultPolicy"`
	DefaultPolicyEvaluation bool      `json:"defaultPolicyEvaluation"`
}

type PolicyViolationFilter struct {
	BasePolicyFilter
}

type PolicyViolationDetails struct {
	Status     string                      `json:"status"`
	BreakBuild bool                        `json:"breakBuild"`
	Policies   []PolicyViolationInfoPolicy `json:"policies"`
}
type PolicyViolationInfoPolicy struct {
	PolicyName    string   `json:"policyName"`
	Description   string   `json:"description"`
	RulesViolated []string `json:"rulesViolated"`
	Tags          []string `json:"tags"`
	BreakBuild    bool     `json:"breakBuild"`
	Status        string   `json:"status"`
}

type Preset struct {
	PresetID           string        `json:"id"`
	Name               string        `json:"name"`
	Description        string        `json:"description"`
	AssociatedProjects uint64        `json:"associatedProjects"`
	Custom             bool          `json:"custom"`
	IsTenantDefault    bool          `json:"isTenantDefault"`
	IsMigrated         bool          `json:"isMigrated"`
	Filled             bool          `json:"-"`
	Engine             string        `json:"-"`
	QueryFamilies      []QueryFamily `json:"queries"` // this member variable should not be modified, any content changes come from the QueryCollection objects
}

type Preset_v330 struct {
	PresetID    uint64 `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Custom      bool   `json:"custom"`
	QueryIDs    []uint64
	Filled      bool
	Queries     []SASTQuery `json:"-"`
}

type Project struct {
	ProjectID            string                 `json:"id"`
	Name                 string                 `json:"name"`
	CreatedAt            string                 `json:"createdAt"`
	UpdatedAt            string                 `json:"updatedAt"`
	Groups               []string               `json:"groups,omitempty"`
	Applications         *[]string              `json:"applicationIds,omitempty"`
	originalApplications []string               `json:"-"` // Cx1clientgo internal/restricted, do not change
	Tags                 map[string]string      `json:"tags"`
	RepoUrl              string                 `json:"repoUrl"`
	MainBranch           string                 `json:"mainBranch"`
	Origin               string                 `json:"origin"`
	Criticality          uint                   `json:"criticality"`
	Configuration        []ConfigurationSetting `json:"-"`
}

type ProjectPatch struct {
	Name        *string            `json:"name,omitempty"`
	RepoUrl     *string            `json:"repoUrl,omitempty"`
	MainBranch  *string            `json:"mainBranch,omitempty"`
	Criticality *uint              `json:"criticality,omitempty"`
	Tags        *map[string]string `json:"tags,omitempty"`
	Groups      *[]string          `json:"groups,omitempty"`
}

type ProjectFilter struct {
	BaseFilter
	ProjectIDs []string `url:"ids,omitempty"`
	Names      []string `url:"names,omitempty"`
	Name       string   `url:"name,omitempty"`
	NameRegex  string   `url:"name-regex,omitempty"`
	Groups     []string `url:"groups,omitempty"`
	Origins    []string `url:"origins,omitempty"`
	TagsKeys   []string `url:"tags-keys,omitempty"`
	TagsValues []string `url:"tags-values,omitempty"`
	EmptyTags  *bool    `url:"empty-tags,omitempty"`
	RepoURL    string   `url:"repo-url,omitempty"`
}

type ProjectBranchFilter struct {
	BaseFilter
	ProjectID string `url:"project-id,omitempty"`
	Name      string `url:"branch-name,omitempty"`
}

type ProjectOverview struct {
	ProjectID    string            `json:"projectId"`
	Name         string            `json:"projectName"`
	Origin       string            `json:"sourceOrigin"`
	LastScanDate string            `json:"lastScanDate"` // can be an empty string
	SourceType   string            `json:"sourceType"`
	Tags         map[string]string `json:"tags"`
	GroupIDs     []string          `json:"groupIds"`
	RiskLevel    string            `json:"riskLevel"`
	RepoID       uint64            `json:"repoId"`
	SCMRepoID    string            `json:"scmRepoId"`
	//TotalCounters  TODO
	//EnginesData TODO
	IsDeployed          bool   `json:"isDeployed"`
	IsPublic            bool   `json:"isPublic"`
	ImportedProjectName string `json:"importedProjName"`
	ProjectOrigin       string `json:"projectOrigin"`

	ApplicationIDs []struct {
		Id   string `json:"id"`
		Name string `json:"name"`
	} `json:"applications"`
}

type ProjectOverviewFilter struct { // max limit = 100
	BaseFilter
	Name           string   `url:"name,omitempty"`
	Origin         []string `url:"scan-origin,omitempty"`
	SourceType     []string `url:"source-type,omitempty"`
	GroupIDs       []string `url:"group-ids,omitempty"`
	ApplicationIDs []string `url:"applications,omitempty"`
	TagKeys        []string `url:"tag-keys,omitempty"`
	TagValues      []string `url:"tag-values,omitempty"`
	EmptyTags      *bool    `url:"empty-tags,omitempty"`
	RiskLevel      []string `url:"risk-level,omitempty"`
	FromDate       string   `url:"from-date,omitempty"`
	ToDate         string   `url:"to-date,omitempty"`
	IsDeployed     *bool    `url:"is-deployed,omitempty"`
	IsPublic       *bool    `url:"is-public,omitempty"`
	Search         string   `url:"search,omitempty"`
	Sort           []string `url:"sort,omitempty"` //  name, scan-origin, last-scan-date, source-type, risk-level, is-public, applications
}

type ProjectScanSchedule struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	ProjectID     string            `json:"projectID"`
	NextStartTime time.Time         `json:"start_time"`
	StartTime     string            `json:"-"`
	CreatedAt     time.Time         `json:"create_at"`
	UpdatedAt     time.Time         `json:"update_at"`
	Frequency     string            `json:"frequency"`      // weekly or daily
	Days          []string          `json:"days,omitempty"` // monday, tuesday ... iff weekly
	Active        bool              `json:"active"`
	Engines       []string          `json:"engines"`
	Branch        string            `json:"branch"`
	Tags          map[string]string `json:"tags"`
}

type ProjectScanScheduleFilter struct {
	BaseFilter
	Search           string     `url:"string,omitempty"`
	Name             string     `url:"name,omitempty"`
	Active           *bool      `url:"active,omitempty"`
	Frequency        []string   `url:"frequency,omitempty"`
	FromCreationDate *time.Time `url:"from-creation-date,omitempty"`
	ToCreationDate   *time.Time `url:"to-creation-date,omitempty"`
	FromTriggerDate  *time.Time `url:"from-trigger-date,omitempty"`
	ToTriggerDate    *time.Time `url:"to-trigger-date,omitempty"`
	Sort             []string   `url:"sort,omitempty"` //  -created_at, +created_at, -status, +status, +name, -name, +trigger_time, -trigger_time
}

type QueryError struct {
	Line        uint64
	StartColumn uint64
	EndColumn   uint64
	Code        string
	Message     string
}

type QueryFailure struct {
	QueryID string       `json:"query_id"`
	Errors  []QueryError `json:"error"`
}

type QueryFamily struct {
	Name       string   `json:"familyName"`
	TotalCount uint64   `json:"totalCount"`
	QueryIDs   []string `json:"queryIds"`
}

type QueryUpdate_v310 struct {
	// used when saving queries in Cx1
	Name     string `json:"name"`
	Path     string `json:"path"`
	Source   string `json:"source"`
	Language string `json:"-"`
	Group    string `json:"-"`

	Metadata QueryUpdateMetadata_v310 `json:"metadata"`
}
type QueryUpdateMetadata_v310 struct {
	Severity uint `json:"severity"`
}

type ReportStatus struct {
	ReportID  string `json:"reportId"`
	Status    string `json:"status"`
	ReportURL string `json:"url"`
}

type ResultsChangeFilter struct {
	BaseFilter
	History    bool   `url:"history,omitempty"` // default false
	EntityID   string `url:"entityId"`
	EntityType string `url:"entityType"` // Possible values: similarityID, scanID, projectID
}

type ResultsChangeHistory struct {
	SimilarityID string             `json:"similarityId"`
	Predicates   []ResultsChangelog `json:"predicates"`
}
type ResultsChangelog struct {
	Change string    `json:"change"`
	Date   time.Time `json:"date"`
	User   string    `json:"user"`
}

type ResultsPredicatesBase struct {
	PredicateID  string `json:"ID,omitempty"`
	SimilarityID string `json:"similarityId"`
	ProjectID    string `json:"projectId"`
	ScanID       string `json:"scanId"`
	State        string `json:"state,omitempty"`
	Comment      string `json:"comment"`
	Severity     string `json:"severity,omitempty"`
	CreatedBy    string `json:"createdBy,omitempty"`
	CreatedAt    string `json:"createdAt,omitempty"`
}

type ResultState struct {
	ID        uint64 `json:"id"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	IsAllowed bool   `json:"isAllowed"`
}

type Role struct {
	ClientID    string `json:"containerId"` // the 'client' in Keycloak - AST roles with have the "ast-app" client ID
	RoleID      string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Attributes  struct {
		Creator    []string
		Type       []string
		Category   []string
		LastUpdate []string // it is returned as [ "uint",... ]
	} `json:"attributes"`
	Composite  bool   `json:"composite"`
	ClientRole bool   `json:"clientRole"`
	SubRoles   []Role `json:"-"`
}

type RunningScan struct {
	ScanID    string
	Status    string
	ProjectID string
	CreatedAt time.Time
	UpdatedAt time.Time
}

type SASTQuery struct {
	QueryID            uint64 `json:"queryID,string"`
	Level              string `json:"level"`
	LevelID            string `json:"levelId"`
	Path               string `json:"path"`
	Modified           string `json:"-"`
	Source             string `json:"-"`
	Name               string `json:"queryName"`
	Group              string `json:"group"`
	Language           string `json:"language"`
	Severity           string `json:"severity"`
	CweID              int64  `json:"cweID"`
	IsExecutable       bool   `json:"isExecutable"`
	QueryDescriptionId int64  `json:"queryDescriptionId"`
	Custom             bool   `json:"custom"`
	EditorKey          string `json:"key"`
	SastID             uint64 `json:"sastId"`
}

type SASTQueryGroup struct {
	Name     string
	Language string
	Queries  []SASTQuery
}

type SASTQueryLanguage struct {
	Name        string
	QueryGroups []SASTQueryGroup
}

type SASTQueryCollection struct {
	QueryLanguages []SASTQueryLanguage
}

type SASTResultsPredicates struct {
	ResultsPredicatesBase // actually the same structure but different endpoint
}
type IACResultsPredicates struct {
	ResultsPredicatesBase // actually the same structure but different endpoint
}

/*
type KeyCloakClient struct {
	ClientID string `json:"id"`
	Name     string `json:"clientId"`
	Enabled  bool
}*/

type SASTAggregateSummary struct {
	Status    string
	QueryID   uint64 `json:"queryID,string"`
	QueryName string
	Severity  string
	Language  string
	Count     uint64
}

type SASTAggregateSummaryFilter struct {
	BaseFilter
	ScanID                 string   `url:"scan-id"`
	GroupBy                []string `url:"group-by-field,omitempty" del:","` //Options: QUERY,SEVERITY,STATE,STATUS,SOURCE_NODE,SINK_NODE,SOURCE_FILE,SINK_FILE,LANGUAGE
	Language               []string `url:"language,omitempty"`
	Status                 []string `url:"status,omitempty"`   //NEW, RECURRENT
	Severity               []string `url:"severity,omitempty"` //CRITICAL, HIGH, MEDIUM, LOW, INFO
	SourceFile             string   `url:"source-file,omitempty"`
	SourceFileOperation    string   `url:"source-file-operation,omitempty"` // LESS_THAN, GREATER_THAN, EQUAL, NOT_EQUAL, CONTAINS, NOT_CONTAINS, START_WITH
	SourceNode             string   `url:"source-node,omitempty"`
	SourceNodeOperation    string   `url:"source-node-operation,omitempty"` // LESS_THAN, GREATER_THAN, EQUAL, NOT_EQUAL, CONTAINS, NOT_CONTAINS, START_WITH
	SourceLine             uint64   `url:"source-line,omitempty"`
	SourceLineOperation    string   `url:"source-line-operation,omitempty"` // LESS_THAN, GREATER_THAN, EQUAL, NOT_EQUAL
	SinkFile               string   `url:"sink-file,omitempty"`
	SinkFileOperation      string   `url:"sink-file-operation,omitempty"` // LESS_THAN, GREATER_THAN, EQUAL, NOT_EQUAL, CONTAINS, NOT_CONTAINS, START_WITH
	SinkNode               string   `url:"sink-node,omitempty"`
	SinkNodeOperation      string   `url:"sink-node-operation,omitempty"` // LESS_THAN, GREATER_THAN, EQUAL, NOT_EQUAL, CONTAINS, NOT_CONTAINS, START_WITH
	NumberOfNodes          uint64   `url:"number-of-nodes,omitempty"`
	NumberOfNodesOperation string   `url:"number-of-nodes-operation,omitempty"` // LESS_THAN, GREATER_THAN, EQUAL, NOT_EQUAL
	Notes                  string   `url:"notes,omitempty"`
	NotesOperation         string   `url:"notes-operation,omitempty"` // CONTAINS, STARTS_WITH
	FirstFoundAt           string   `url:"first-found-at,omitempty"`
	FirstFoundAtOperation  string   `url:"first-found-at-operation,omitempty"` // LESS_THAN, GREATER_THAN
	QueryIDs               []uint64 `url:"query-ids,omitempty"`
	PresetID               uint64   `url:"preset-id,omitempty"`
	ResultIDs              []string `url:"result-ids,omitempty"`
	Categories             string   `url:"categories,omitempty"` // comma-separated list
	Search                 string   `url:"search,omitempty"`
	ApplyPredicates        *bool    `url:"apply-predicates,omitempty"`
}

type Scan struct {
	ScanID        string              `json:"id"`
	Status        string              `json:"status"`
	StatusDetails []ScanStatusDetails `json:"statusDetails"`
	Branch        string              `json:"branch"`
	CreatedAt     string              `json:"createdAt"`
	UpdatedAt     string              `json:"updatedAt"`
	ProjectID     string              `json:"projectId"`
	ProjectName   string              `json:"projectName"`
	UserAgent     string              `json:"userAgent"`
	Initiator     string              `json:"initiator"`
	Tags          map[string]string   `json:"tags"`
	Metadata      struct {
		Type    string              `json:"type"`
		Configs []ScanConfiguration `json:"configs"`
	} `json:"metadata"`
	Engines      []string `json:"engines"`
	SourceType   string   `json:"sourceType"`
	SourceOrigin string   `json:"sourceOrigin"`
}

type ScanFilter struct {
	BaseFilter
	ProjectID string    `url:"project-id"`
	Sort      []string  `url:"sort,omitempty"` // Available values : -created_at, +created_at, -status, +status, +branch, -branch, +initiator, -initiator, +user_agent, -user_agent, +name, -name
	TagKeys   []string  `url:"tags-keys,omitempty"`
	TagValues []string  `url:"tags-values,omitempty"`
	Statuses  []string  `url:"statuses,omitempty"`
	Branches  []string  `url:"branches,omitempty"`
	FromDate  time.Time `url:"from-date,omitempty"`
	ToDate    time.Time `url:"to-date,omitempty"`
}

type ScanConfiguration struct {
	ScanType string            `json:"type"`
	Values   map[string]string `json:"value"`
}

type ScanConfigurationSet struct {
	Configurations []ScanConfiguration
}

type ScanHandler struct {
	RepoURL     string                 `json:"repoUrl"`
	Branch      string                 `json:"branch"`
	Commit      string                 `json:"commit"`
	Credentials map[string]interface{} `json:"credentials"`
}

type ScanMetadata struct {
	ScanID                  string
	ProjectID               string
	LOC                     uint64
	FileCount               uint64
	IsIncremental           bool
	IsIncrementalCanceled   bool
	IncrementalCancelReason string
	BaseID                  string
	AddedFilesCount         uint64
	ChangedFilesCount       uint64
	DeletedFilesCount       uint64
	ChangePercentage        float64
	PresetName              string `json:"queryPreset"`
}

type ScanMetrics struct {
	ScanID                                    string
	MemoryPeak                                uint64
	VirtualMemoryPeak                         uint64
	TotalScannedFilesCount                    uint64
	TotalScannedLOC                           uint64
	DOMObjectsPerLanguage                     map[string]uint64
	SuccessfullLocPerLanguage                 map[string]uint64
	FailedLocPerLanguage                      map[string]uint64
	FileCountOfDetectedButNotScannedLanguages map[string]uint64
	ScannedFilesPerLanguage                   map[string]struct {
		GoodFiles          uint64
		PartiallyGoodFiles uint64
		BadFiles           uint64
	}
}

type ScanResultSet struct {
	SAST         []ScanSASTResult
	SCA          []ScanSCAResult
	SCAContainer []ScanSCAContainerResult
	IAC          []ScanIACResult
	Containers   []ScanContainersResult
}

type ScanResultsFilter struct {
	BaseFilter
	ScanID             string   `url:"scan-id"`
	Severity           []string `url:"severity"`
	State              []string `url:"state"`
	Status             []string `url:"status"`
	ExcludeResultTypes []string `url:"exclude-result-types"` // Available values : DEV_AND_TEST, NONE
	Sort               []string `url:"sort"`                 //Available values : -severity, +severity, -status, +status, -state, +state, -type, +type, -firstfoundat, +firstfoundat, -foundat, +foundat, -firstscanid, +firstscanid
}

// generic data common to all
type ScanResultBase struct {
	Type            string
	ResultID        string `json:"id"`
	SimilarityID    string `json:"similarityId"`
	AlternateID     string `json:"alternateId"`
	Status          string
	State           string
	Severity        string
	ConfidenceLevel int    `json:"confidenceLevel"`
	CreatedAt       string `json:"created"`
	FirstFoundAt    string
	FoundAt         string
	FirstScanId     string
	Description     string
	// Comments			// currently doesn't do anything?
	CVSSScore      float64
	ProjectID      string
	ScanID         string
	SourceFileName string
}

type ScanContainersResult struct {
	ScanResultBase
	Data                 ScanContainersResultData
	VulnerabilityDetails ScanContainersResultDetails
}

type ScanContainersResultData struct {
	PackageName    string
	PackageVersion string
	ImageName      string
	ImageTag       string
	ImageFilePath  string
	ImageOrigin    string
}

type ScanContainersResultDetails struct {
	CVSSScore float64
	CveName   string
	CweID     string
	Cvss      struct {
		Scope                 string
		Score                 string
		Severity              string
		AttackVector          string `json:"attack_vector"`
		IntegrityImpact       string `json:"integrity_impact"`
		UserInteraction       string `json:"user_interaction"`
		AttackComplexity      string `json:"attack_complexity"`
		AvailabilityImpact    string `json:"availability_impact"`
		PrivilegesRequired    string `json:"privileges_required"`
		ConfidentialityImpact string `json:"confidentiality_impact"`
	}
}

type ScanIACResult struct {
	ScanResultBase
	Data ScanIACResultData
}
type ScanIACResultData struct {
	QueryID       string
	QueryName     string
	Group         string
	QueryURL      string
	FileName      string
	Line          int
	Platform      string
	IssueType     string
	ExpectedValue string
	Value         string
}

type ScanSASTResult struct {
	ScanResultBase
	Data                 ScanSASTResultData
	VulnerabilityDetails ScanSASTResultDetails
}
type ScanSASTResultData struct {
	QueryID      uint64
	QueryName    string
	Group        string
	ResultHash   string
	LanguageName string
	Nodes        []ScanSASTResultNodes
}
type ScanSASTResultNodes struct {
	ID          string
	Line        uint64
	Name        string
	Column      uint64
	Length      uint64
	Method      string
	NodeID      uint64
	DOMType     string
	FileName    string
	FullName    string
	TypeName    string
	MethodLine  uint64
	Definitions string
}
type ScanSASTResultDetails struct {
	CweId       int
	Compliances []string
}

type ScanSASTResultsFilter struct {
	BaseFilter
	ScanID                 string   `url:"scan-id"`
	Language               []string `url:"language,omitempty"`
	Status                 []string `url:"status,omitempty"`   //NEW, RECURRENT
	Severity               []string `url:"severity,omitempty"` //CRITICAL, HIGH, MEDIUM, LOW, INFO
	SourceFile             string   `url:"source-file,omitempty"`
	SourceFileOperation    string   `url:"source-file-operation,omitempty"` // LESS_THAN, GREATER_THAN, EQUAL, NOT_EQUAL, CONTAINS, NOT_CONTAINS, START_WITH
	SourceNode             string   `url:"source-node,omitempty"`
	SourceNodeOperation    string   `url:"source-node-operation,omitempty"` // LESS_THAN, GREATER_THAN, EQUAL, NOT_EQUAL, CONTAINS, NOT_CONTAINS, START_WITH
	SourceLine             uint64   `url:"source-line,omitempty"`
	SourceLineOperation    string   `url:"source-line-operation,omitempty"` // LESS_THAN, GREATER_THAN, EQUAL, NOT_EQUAL
	SinkFile               string   `url:"sink-file,omitempty"`
	SinkFileOperation      string   `url:"sink-file-operation,omitempty"` // LESS_THAN, GREATER_THAN, EQUAL, NOT_EQUAL, CONTAINS, NOT_CONTAINS, START_WITH
	SinkNode               string   `url:"sink-node,omitempty"`
	SinkNodeOperation      string   `url:"sink-node-operation,omitempty"` // LESS_THAN, GREATER_THAN, EQUAL, NOT_EQUAL, CONTAINS, NOT_CONTAINS, START_WITH
	SinkLine               uint64   `url:"sink-line,omitempty"`
	SinkLineOperation      string   `url:"sink-line-operation,omitempty"` // LESS_THAN, GREATER_THAN, EQUAL, NOT_EQUAL
	NumberOfNodes          uint64   `url:"number-of-nodes,omitempty"`
	NumberOfNodesOperation string   `url:"number-of-nodes-operation,omitempty"` // LESS_THAN, GREATER_THAN, EQUAL, NOT_EQUAL
	Notes                  string   `url:"notes,omitempty"`
	NotesOperation         string   `url:"notes-operation,omitempty"` // CONTAINS, STARTS_WITH
	FirstFoundAt           string   `url:"first-found-at,omitempty"`
	FirstFoundAtOperation  string   `url:"first-found-at-operation,omitempty"` // LESS_THAN, GREATER_THAN
	QueryIDs               []uint64 `url:"query-ids,omitempty"`
	PresetID               uint64   `url:"preset-id,omitempty"`
	ResultIDs              []string `url:"result-ids,omitempty"`
	Categories             string   `url:"category,omitempty"` // comma-separated list
	Search                 string   `url:"search,omitempty"`
	IncludeNodes           *bool    `url:"include-nodes,omitempty"`
	ApplyPredicates        *bool    `url:"apply-predicates,omitempty"`
	Sort                   []string `url:"sort,omitempty"` // Default value : +status,+severity,-queryname
	VisibleColumns         []string `url:"visible-columns,omitempty"`
	State                  []string `url:"state,omitempty"`
}

type ScanSCAResult struct {
	ScanResultBase
	Data                 ScanSCAResultData `json:"data"`
	VulnerabilityDetails ScanSCAResultDetails
}
type ScanSCAResultData struct {
	PackageIdentifier  string
	PublishedAt        string
	Recommendation     string
	RecommendedVersion string
	//ExploitableMethods // TODO
	PackageData []ScanSCAResultPackageData
}
type ScanSCAResultDetails struct {
	CweId     string
	CVSSScore float64
	CveName   string
	Cvss      ScanSCAResultCVSS
}
type ScanSCAResultCVSS struct {
	Version          int
	AttackVector     string
	Availability     string
	Confidentiality  string
	AttackComplexity string
}
type ScanSCAResultPackageData struct {
	URL     string
	Type    string
	Comment string
}

type ScanSCAContainerResult struct {
	ScanResultBase
	Data                 ScanSCAContainerResultData `json:"data"`
	VulnerabilityDetails ScanSCAResultDetails
}

type ScanSCAContainerResultData struct {
	Metadata struct {
		Enrichers []string `json:"enrichers"`
	} `json:"metadata"`
	PackageName    string `json:"packageName"`
	PackageVersion string `json:"packageVersion"`
	PublishedAt    string `json:"publishedAt"`
}

type ScanStatusDetails struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Details string `json:"details"`
}

type ScanResultStatusSummary struct {
	ToVerify               uint64
	NotExploitable         uint64
	Confirmed              uint64
	ProposedNotExploitable uint64
	Urgent                 uint64
}

type ScanResultSummary struct {
	High        ScanResultStatusSummary
	Medium      ScanResultStatusSummary
	Low         ScanResultStatusSummary
	Information ScanResultStatusSummary
}

type ScanStatusSummary struct {
	Canceled  uint64
	Completed uint64
	Partial   uint64
	Queued    uint64
	Failed    uint64
	Running   uint64
}

// Very simplified for now
type ScanSummary struct {
	TenantID     string
	ScanID       string
	SASTCounters struct {
		QueriesCounters        []ScanSummaryQueriesCounter
		SinkFileCounters       []ScanSummaryFileCounter
		LanguageCounters       []ScanSummaryLanguageCounter
		ComplianceCounters     []ScanSummaryComplianceCounter
		SeverityCounters       []ScanSummarySeverityCounter
		StatusCounters         []ScanSummaryStatusCounter
		StateCounters          []ScanSummaryStateCounter
		SeverityStatusCounters []ScanSummarySeverityStatusCounter
		SourceFileCounters     []ScanSummaryFileCounter
		AgeCounters            []ScanSummaryAgeCounter

		TotalCounter        uint64
		FilesScannedCounter uint64
	}

	IACCounters struct {
		SeverityCounters       []ScanSummarySeverityCounter
		StatusCounters         []ScanSummaryStatusCounter
		StateCounters          []ScanSummaryStateCounter
		SeverityStatusCounters []ScanSummarySeverityStatusCounter
		SourceFileCounters     []ScanSummaryFileCounter
		AgeCounters            []ScanSummaryAgeCounter

		TotalCounter        uint64
		FilesScannedCounter uint64

		PlatformSummary []ScanSummaryPlatformCounter
		CategorySummary []ScanSummaryCategoryCounter
	} `json:"kicsCounters"`

	SCACounters struct {
		SeverityCounters       []ScanSummarySeverityCounter
		StatusCounters         []ScanSummaryStatusCounter
		StateCounters          []ScanSummaryStateCounter
		SeverityStatusCounters []ScanSummarySeverityStatusCounter
		SourceFileCounters     []ScanSummaryFileCounter
		AgeCounters            []ScanSummaryAgeCounter

		TotalCounter        uint64
		FilesScannedCounter uint64
	}

	SCAPackagesCounters struct {
		SeverityCounters       []ScanSummarySeverityCounter
		StatusCounters         []ScanSummaryStatusCounter
		StateCounters          []ScanSummaryStateCounter
		SeverityStatusCounters []ScanSummarySeverityStatusCounter
		SourceFileCounters     []ScanSummaryFileCounter
		AgeCounters            []ScanSummaryAgeCounter

		TotalCounter        uint64
		FilesScannedCounter uint64
		OutdatedCounter     uint64
		RiskLevelCounters   []ScanSummaryRiskLevelCounter
		LicenseCounters     []ScanSummaryLicenseCounter
		PackageCounters     []ScanSummaryPackageCounter
	}

	SCAContainersCounters struct {
		TotalPackagesCounters           uint64
		TotalVulnerabilitiesCounter     uint64
		SeverityVulnerabilitiesCounters []ScanSummarySeverityCounter
		StateVulnerabilityCounters      []ScanSummaryStateCounter
		StatusVulnerabilityCounters     []ScanSummaryStatusCounter
		AgeVulnerabilityCounters        []ScanSummaryAgeCounter
		PackageVulnerabilitiesCounters  []ScanSummaryPackageCounter
	}

	APISecCounters struct {
		SeverityCounters       []ScanSummarySeverityCounter
		StatusCounters         []ScanSummaryStatusCounter
		StateCounters          []ScanSummaryStateCounter
		SeverityStatusCounters []ScanSummarySeverityStatusCounter
		SourceFileCounters     []ScanSummaryFileCounter
		AgeCounters            []ScanSummaryAgeCounter

		TotalCounter        uint64
		FilesScannedCounter uint64
		RiskLevel           string
		APISecTotal         uint64
	}

	MicroEnginesCounters struct {
		SeverityCounters       []ScanSummarySeverityCounter
		StatusCounters         []ScanSummaryStatusCounter
		StateCounters          []ScanSummaryStateCounter
		SeverityStatusCounters []ScanSummarySeverityStatusCounter
		SourceFileCounters     []ScanSummaryFileCounter
		AgeCounters            []ScanSummaryAgeCounter

		TotalCounter        uint64
		FilesScannedCounter uint64
	}

	ContainersCounters struct {
		TotalPackagesCounter   uint64
		TotalCounter           uint64
		SeverityCounters       []ScanSummarySeverityCounter
		StatusCounters         []ScanSummaryStatusCounter
		StateCounters          []ScanSummaryStateCounter
		AgeCounters            []ScanSummaryAgeCounter
		PackageCounters        []ScanSummaryContainerPackageCounter
		SeverityStatusCounters []ScanSummarySeverityStatusCounter
	}
}

type ScanSummaryAgeCounter struct {
	Age              string
	SeverityCounters []ScanSummarySeverityCounter
	Counter          int64
}
type ScanSummaryComplianceCounter struct {
	Compliance string
	Counter    int64
}
type ScanSummaryFileCounter struct {
	File    string
	Counter int64
}
type ScanSummaryLanguageCounter struct {
	Language string
	Counter  int64
}
type ScanSummaryLicenseCounter struct {
	License string
	Counter int64
}
type ScanSummaryPackageCounter struct {
	Package string
	Counter int64
}
type ScanSummaryContainerPackageCounter struct {
	Package     string
	Counter     int64
	IsMalicious bool
}
type ScanSummaryQueriesCounter struct {
	QueryID        uint64                     `json:"queryID"`
	Name           uint64                     `json:"queryName"`
	Severity       string                     `json:"severity"`
	StatusCounters []ScanSummaryStatusCounter `json:"statusCounters"`
	Counter        int64                      `json:"counter"`
}
type ScanSummaryRiskLevelCounter struct {
	RiskLevel string
	Counter   int64
}
type ScanSummarySeverityCounter struct {
	Severity string
	Counter  int64
}
type ScanSummarySeverityStatusCounter struct {
	Severity string
	Status   string
	Counter  int64
}
type ScanSummaryStateCounter struct {
	State   string
	Counter int64
}
type ScanSummaryStatusCounter struct {
	Status  string
	Counter int64
}

type ScanSummaryPlatformCounter struct {
	Platform string
	Counter  int64
}
type ScanSummaryCategoryCounter struct {
	Category string
	Counter  int64
}

type ScanSummaryFilter struct {
	BaseFilter
	ScanIDs        string   `url:"scan-ids"` // comma-separated list of scan ids
	SeverityStatus *bool    `url:"include-severity-status"`
	Status         *bool    `url:"include-status-counters"`
	Queries        *bool    `url:"include-queries"`
	Files          *bool    `url:"include-files"`
	Predicates     *bool    `url:"apply-predicates"`
	Language       string   `url:"language"`
	ExcludeTypes   []string `url:"exclude-result-types"` // DEV_AND_TEST, NONE
}

type Status struct {
	ID      int               `json:"id"`
	Name    string            `json:"name"`
	Details ScanStatusDetails `json:"details"`
}

type Cx1LongTime struct {
	time.Time
}

type User struct {
	Enabled      bool        `json:"enabled"`
	UserID       string      `json:"id,omitempty"`
	FirstName    string      `json:"firstName"`
	LastName     string      `json:"lastName"`
	UserName     string      `json:"username"`
	Email        string      `json:"email"`
	LastLogin    Cx1LongTime `json:"-"`
	Groups       []Group     `json:"-"` // only returned from /users/{id}/groups. Use GetUserGroups to fill.
	FilledGroups bool        `json:"-"` // indicates if the user object has had the Groups array filled.
	Roles        []Role      `json:"-"` // only returned from /users/{id}/role-mappings. Use GetUserRoles to fill.
	FilledRoles  bool        `json:"-"` // indicates if the user object has had the Roles array filled.
}

type UserFilter struct {
	BaseIAMFilter
	BriefRepresentation *bool  `url:"briefRepresentation,omitempty"` // only used by GetUser* (not GetUserCount)
	Email               string `url:"email,omitempty"`
	EmailVerified       *bool  `url:"emailVerified,omitempty"`
	Enabled             *bool  `url:"enabled,omitempty"`
	Exact               *bool  `url:"exact,omitempty"` // only used by GetUser* (not GetUserCount)
	FirstName           string `url:"firstName,omitempty"`
	IDPAlias            string `url:"idpAlias,omitempty"`  // only used by GetUser* (not GetUserCount)
	IDPUserId           string `url:"idpUserId,omitempty"` // only used by GetUser* (not GetUserCount)
	Q                   string `url:"q,omitempty"`
	Search              string `url:"search,omitempty"`
	Username            string `url:"username,omitempty"`
	Realm               string `url:"realm"`
}

type UserWithAttributes struct {
	User
	Attributes struct {
		LastLogin []Cx1LongTime `json:"lastLogin"`
	} `json:"attributes"`
}

type VersionInfo struct {
	CxOne  string
	IAC    string `json:"kics"`
	SAST   string
	vCxOne VersionTriad `json:"-"`
	vIAC   VersionTriad `json:"-"`
	vSAST  VersionTriad `json:"-"`
}

type VersionTriad struct {
	Major uint
	Minor uint
	Patch uint
}

type WhoAmI struct {
	UserID string `json:"userId"`
	Name   string `json:"displayName"`
}

type WorkflowLog struct {
	Source    string `json:"Source"`
	Info      string `json:"Info"`
	Timestamp string `json:"Timestamp"`
}
