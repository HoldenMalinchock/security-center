/** Security Center often serializes IDs as strings. */
export type ScId = string | number;

/** Boolean-like values returned by Security Center. */
export type ScBoolean = boolean | "true" | "false" | "0" | "1" | 0 | 1;

/** ID reference used in create/update bodies. */
export type IdRef = {
  id?: ScId;
  uuid?: string;
};

/** Named object fragment commonly nested in SC responses. */
export type NamedRef = {
  id?: ScId;
  name?: string | null;
  description?: string | null;
  uuid?: string | null;
  type?: string | null;
  status?: string | number | null;
  dataFormat?: string | null;
  username?: string | null;
  firstname?: string | null;
  lastname?: string | null;
  [key: string]: unknown;
};

/** Sort direction for analysis and saved-query tools. */
export type SortDirection = "ASC" | "DESC";
/** Security Center string boolean used on many request fields. */
export type StringBoolean = "true" | "false";

/** Shared GET list/query options for `/resource` endpoints. */
export type ListQuery = {
  fields?: string[];
  expand?: string[];
  editable?: boolean;
  usable?: boolean;
  manageable?: boolean;
};

/** Standard Security Center JSON envelope (`response`, `error_code`, `error_msg`). */
export type SecurityCenterEnvelope = {
  type?: string;
  response?: unknown;
  error_code?: number | string;
  error_msg?: string | null;
  warnings?: unknown[];
  timestamp?: number | string;
  [key: string]: unknown;
};

/** Request body for `POST /token` session login. */
export type TokenLoginBody = {
  username: string;
  password: string;
  releaseSession?: boolean;
};

/** Response payload from `POST /token`. */
export type TokenResponse = {
  token?: string | number;
  releaseSession?: boolean | string;
  unassociatedCert?: boolean | string;
  failedLoginIP?: string | null;
  failedLogins?: string | number;
  lastFailedLogin?: string | number;
  lastLogin?: string | number;
  lastLoginIP?: string | null;
  [key: string]: unknown;
};

/** Saved-query type accepted by `/query` and `/analysis`. */
export type QueryType = "alert" | "all" | "lce" | "mobile" | "ticket" | "user" | "vuln";

/** Vulnerability analysis tool name (`vulndetails`, `sumip`, ...). */
export type VulnTool =
  | "iplist"
  | "listmailclients"
  | "listos"
  | "listservices"
  | "listsoftware"
  | "listsshservers"
  | "listvuln"
  | "listwebclients"
  | "listwebservers"
  | "remediationdetail"
  | "sumasset"
  | "sumcce"
  | "sumclassa"
  | "sumclassb"
  | "sumclassc"
  | "sumcve"
  | "sumdnsname"
  | "sumfamily"
  | "sumiavm"
  | "sumid"
  | "sumip"
  | "summsbulletin"
  | "sumport"
  | "sumprotocol"
  | "sumremediation"
  | "sumseverity"
  | "sumuserresponsibility"
  | "vulndetails"
  | "vulnipdetail"
  | "vulnipsummary";

/** Event / LCE analysis tool name. */
export type EventTool =
  | "listdata"
  | "sumasset"
  | "sumclassa"
  | "sumclassb"
  | "sumclassc"
  | "sumdate"
  | "sumevent"
  | "sumevent2"
  | "sumip"
  | "sumport"
  | "sumprotocol"
  | "sumsensor"
  | "sumtime"
  | "sumtype"
  | "sumuser"
  | "syslog"
  | "timedist";

/** Mobile analysis tool name. */
export type MobileTool =
  | "listvuln"
  | "sumdeviceid"
  | "summdmuser"
  | "summodel"
  | "sumoscpe"
  | "sumpluginid"
  | "vulndetails";

/** Value of a Security Center query filter. */
export type QueryFilterValue =
  | string
  | number
  | boolean
  | unknown[]
  | Record<string, unknown>;

/** Single analysis/query filter (`filterName`, `operator`, `value`). */
export type QueryFilter = {
  filterName: string;
  operator?: string;
  value: QueryFilterValue;
};

/** Reference to an existing saved query by ID. */
export type SavedQueryRef = { id: ScId };

/** Inline analysis query (tool + filters) instead of a saved query ID. */
export type InlineQuery = {
  tool: string;
  type?: Exclude<QueryType, "all">;
  name?: string;
  description?: string;
  filters?: QueryFilter[];
  startOffset?: number;
  endOffset?: number;
  sortField?: string;
  sortDir?: SortDirection;
  context?: string;
  tags?: string;
  browseColumns?: string;
  browseSortColumn?: string;
  browseSortDirection?: SortDirection;
  [key: string]: unknown;
};

/** Either a saved query `{ id }` or an inline query definition. */
export type QueryInput = SavedQueryRef | InlineQuery;

/** Query-string options for `GET /query`. */
export type ListQueriesQuery = ListQuery & {
  type?: QueryType;
};

/** Request body for `POST /query`. */
export type CreateQueryBody = {
  name: string;
  description?: string;
  ownerID?: string | number;
  tags?: string;
  type: Exclude<QueryType, "all">;
  context?: string;
  browseColumns?: string;
  browseSortColumn?: string;
  browseSortDirection?: SortDirection;
  tool: string;
  filters?: QueryFilter[];
  sortField?: string;
  sortDir?: SortDirection;
  startOffset?: number;
  endOffset?: number;
  [key: string]: unknown;
};

/** Partial body for `PATCH /query/{id}`. */
export type UpdateQueryBody = Partial<CreateQueryBody>;

/** Saved query record returned by `/query`. */
export type Query = {
  id?: ScId;
  name?: string | null;
  description?: string | null;
  type?: string;
  tool?: string;
  tags?: string | null;
  context?: string | null;
  status?: string | number;
  canManage?: boolean | StringBoolean;
  canUse?: boolean | StringBoolean;
  creator?: NamedRef;
  owner?: NamedRef;
  ownerGroup?: NamedRef;
  filters?: unknown[];
  createdTime?: string | number;
  modifiedTime?: string | number;
  [key: string]: unknown;
};

/** Top-level `/analysis` type discriminator. */
export type AnalysisType = "vuln" | "event" | "user" | "mobile";
/** Vulnerability analysis source (`cumulative`, `individual`, `patched`). */
export type VulnSourceType = "individual" | "cumulative" | "patched";
/** Event analysis source (`lce` or `archive`). */
export type EventSourceType = "lce" | "archive";
/** Whether WAS findings are included in vulnerability analysis. */
export type WasVuln = "onlyWas" | "excludeWas" | "includeWas";
/** View for an individual scan analysis (`all`, `new`, `patched`). */
export type IndividualView = "all" | "new" | "patched";

/** Canonical `POST /analysis` body for vulnerability analysis. */
export type VulnAnalysisRequest = {
  type?: "vuln";
  query: QueryInput;
  sourceType?: VulnSourceType;
  wasVuln?: WasVuln;
  scanID?: string | number;
  view?: IndividualView;
  sortDir?: SortDirection;
  sortField?: string;
  startOffset?: number;
  endOffset?: number;
};

/** Canonical `POST /analysis` body for event / LCE analysis. */
export type EventAnalysisRequest = {
  type?: "event";
  query: QueryInput;
  sourceType?: EventSourceType;
  lceID?: string | number;
  view?: string;
  sortDir?: SortDirection;
  sortField?: string;
  startOffset?: number;
  endOffset?: number;
};

/** Canonical `POST /analysis` body for user analysis. */
export type UserAnalysisRequest = {
  type?: "user";
  query: QueryInput;
};

/** Canonical `POST /analysis` body for mobile analysis. */
export type MobileAnalysisRequest = {
  type?: "mobile";
  query: QueryInput;
  sourceType?: "mobile";
  sortDir?: SortDirection;
  sortField?: string;
  startOffset?: number;
  endOffset?: number;
};

/** Any canonical `/analysis` request body. */
export type AnalysisRequest =
  | VulnAnalysisRequest
  | EventAnalysisRequest
  | UserAnalysisRequest
  | MobileAnalysisRequest;

/** Friendlier vulnerability analysis input. Accepts flattened `tool` + `filters`. */
export type VulnAnalysisInput = {
  type?: "vuln";
  query?: QueryInput;
  queryId?: ScId;
  tool?: VulnTool | string;
  filters?: QueryFilter[];
  sourceType?: VulnSourceType;
  wasVuln?: WasVuln;
  scanID?: string | number;
  view?: IndividualView;
  sortDir?: SortDirection;
  sortField?: string;
  startOffset?: number;
  endOffset?: number;
};

/** Friendlier event analysis input. Accepts flattened `tool` + `filters`. */
export type EventAnalysisInput = {
  type?: "event";
  query?: QueryInput;
  queryId?: ScId;
  tool?: EventTool | string;
  filters?: QueryFilter[];
  sourceType?: EventSourceType;
  lceID?: string | number;
  view?: string;
  sortDir?: SortDirection;
  sortField?: string;
  startOffset?: number;
  endOffset?: number;
};

/** Friendlier mobile analysis input. Accepts flattened `tool` + `filters`. */
export type MobileAnalysisInput = {
  type?: "mobile";
  query?: QueryInput;
  queryId?: ScId;
  tool?: MobileTool | string;
  filters?: QueryFilter[];
  sourceType?: "mobile";
  sortDir?: SortDirection;
  sortField?: string;
  startOffset?: number;
  endOffset?: number;
};

/** Request body for `POST /analysis/download`. User analysis cannot be downloaded. */
export type AnalysisDownloadRequest = {
  type: Exclude<AnalysisType, "user">;
  query: QueryInput;
  sourceType?: string;
  sortDir?: SortDirection;
  sortField?: string;
  startOffset?: number;
  endOffset?: number;
  columns?: Array<{ name: string }>;
  scanID?: string | number;
  view?: string;
  wasVuln?: WasVuln;
  lceID?: string | number;
};

/** One row in an `/analysis` `results` array. Extra plugin fields are preserved. */
export type AnalysisResultRow = {
  pluginID?: string | number;
  pluginName?: string;
  name?: string;
  severity?: { id?: ScId; name?: string; description?: string; [key: string]: unknown };
  ip?: string;
  dnsName?: string | null;
  macAddress?: string | null;
  netbiosName?: string | null;
  port?: string | number;
  protocol?: string;
  uuid?: string | null;
  hostUUID?: string | null;
  vulnUUID?: string | null;
  firstSeen?: string | number;
  lastSeen?: string | number;
  family?: NamedRef;
  repository?: NamedRef;
  vprScore?: string | number | null;
  epssScore?: string | number | null;
  cvssV3BaseScore?: string | number | null;
  cvssV4BaseScore?: string | number | null;
  [key: string]: unknown;
};

/** Unwrapped `/analysis` response (`results`, offsets, record counts). */
export type AnalysisResponse = {
  totalRecords?: string | number;
  returnedRecords?: string | number;
  startOffset?: string | number;
  endOffset?: string | number;
  matchingDataElementCount?: string | number;
  results?: AnalysisResultRow[];
  [key: string]: unknown;
};

/** Scan schedule type (`never`, `ical`, `template`, `dependent`, `rollover`). */
export type ScanScheduleType =
  | "dependent"
  | "ical"
  | "never"
  | "rollover"
  | "template";

/** Scan schedule object used when creating or updating a scan. */
export type ScanSchedule = {
  type?: ScanScheduleType;
  start?: string;
  repeatRule?: string;
  enabled?: StringBoolean;
  dependentID?: ScId;
  [key: string]: unknown;
};

/** Report to generate when a scan finishes. */
export type ScanReportRef = {
  id: ScId;
  reportSource: "cumulative" | "patched" | "individual" | "lce" | "archive" | "mobile";
};

/** Query-string options for `GET /scan`. */
export type ListScansQuery = ListQuery;

/** Request body for `POST /scan`. `name` and `repository` are required. */
export type CreateScanBody = {
  name: string;
  type?: string;
  description?: string;
  repository: IdRef;
  zone?: IdRef;
  dhcpTracking?: StringBoolean;
  classifyMitigatedAge?: number;
  schedule?: ScanSchedule;
  reports?: ScanReportRef[];
  assets?: IdRef[];
  credentials?: IdRef[];
  emailOnLaunch?: StringBoolean;
  emailOnFinish?: StringBoolean;
  timeoutAction?: "discard" | "import" | "rollover";
  scanningVirtualHosts?: StringBoolean;
  rolloverType?: "nextDay" | "template";
  ipList?: string;
  urlList?: string;
  maxScanTime?: string | number;
  inactivityTimeout?: number;
  policy?: IdRef;
  plugin?: IdRef;
  [key: string]: unknown;
};

/** Partial body for `PATCH /scan/{id}`. */
export type UpdateScanBody = Partial<CreateScanBody>;

/** Request body for `POST /scan/{id}/copy`. */
export type CopyScanBody = {
  name: string;
  targetUser: IdRef;
};

/** Optional diagnostic fields for `POST /scan/{id}/launch`. */
export type LaunchScanBody = {
  diagnosticTarget?: string;
  diagnosticPassword?: string;
};

/** Scan definition returned by `/scan`. */
export type Scan = {
  id?: ScId;
  uuid?: string;
  name?: string | null;
  description?: string | null;
  status?: string | number | null;
  ipList?: string | null;
  urlList?: string | null;
  type?: string | null;
  dhcpTracking?: string | boolean;
  classifyMitigatedAge?: string | number;
  emailOnLaunch?: string | boolean;
  emailOnFinish?: string | boolean;
  timeoutAction?: string;
  scanningVirtualHosts?: string | boolean;
  rolloverType?: string;
  createdTime?: string | number;
  modifiedTime?: string | number;
  maxScanTime?: string | number;
  inactivityTimeout?: string | number;
  numDependents?: string | number;
  canUse?: string | boolean;
  canManage?: string | boolean;
  schedule?: unknown;
  policy?: NamedRef;
  plugin?: NamedRef;
  repository?: NamedRef;
  zone?: NamedRef;
  owner?: NamedRef;
  ownerGroup?: NamedRef;
  creator?: NamedRef;
  reports?: unknown[];
  assets?: unknown[];
  credentials?: unknown[];
  [key: string]: unknown;
};

/** Query-string options for `GET /scanResult`. */
export type ListScanResultsQuery = ListQuery & {
  startTime?: number;
  endTime?: number;
  running?: boolean;
  completed?: boolean;
  optimizeCompletedScans?: boolean;
  timeCompareField?: "finishTime" | "createdTime";
};

/** Request body for `POST /scanResult/{id}/copy`. */
export type CopyScanResultBody = { users: IdRef[] };
/** Request body for `POST /scanResult/{id}/email`. */
export type EmailScanResultBody = { email: string };

/** Request body for `POST /scanResult/import`. */
export type ImportScanResultBody = {
  filename: string;
  repository: IdRef;
  classifyMitigatedAge?: number;
  dhcpTracking?: StringBoolean;
  scanningVirtualHosts?: StringBoolean;
};

/** Request body for `POST /scanResult/{id}/import`. */
export type ReimportScanResultBody = {
  classifyMitigatedAge?: number;
  dhcpTracking?: StringBoolean;
  scanningVirtualHosts?: StringBoolean;
};

/** Scan result record returned by `/scanResult`. */
export type ScanResult = {
  id?: ScId;
  name?: string | null;
  description?: string | null;
  status?: string;
  details?: string | null;
  importStatus?: string;
  importStart?: string | number;
  importFinish?: string | number;
  importDuration?: string | number;
  downloadAvailable?: string | boolean;
  downloadFormat?: string;
  dataFormat?: string;
  resultType?: string;
  resultSource?: string;
  running?: string | boolean;
  errorDetails?: string | null;
  importErrorDetails?: string | null;
  totalIPs?: string | number;
  scannedIPs?: string | number;
  startTime?: string | number;
  finishTime?: string | number;
  scanDuration?: string | number;
  completedIPs?: string | number;
  completedChecks?: string | number;
  totalChecks?: string | number;
  agentScanUUID?: string | null;
  agentScanContainerUUID?: string | null;
  progress?: Record<string, unknown>;
  initiator?: NamedRef;
  owner?: NamedRef;
  ownerGroup?: NamedRef;
  scan?: NamedRef;
  repository?: NamedRef;
  canUse?: string | boolean;
  canManage?: string | boolean;
  [key: string]: unknown;
};

/** Asset definition type (`static`, `dynamic`, `dnsname`, ...). */
export type AssetType =
  | "combination"
  | "dnsname"
  | "dnsnameupload"
  | "dynamic"
  | "ldapquery"
  | "static"
  | "staticeventfilter"
  | "staticvulnfilter"
  | "templates"
  | "upload"
  | "watchlist"
  | "watchlisteventfilter"
  | "watchlistupload";

/** Query-string options for `GET /asset`. */
export type ListAssetsQuery = ListQuery & {
  template?: ScId[];
  excludeAllDefined?: boolean;
  excludeWatchlists?: boolean;
};

/** Single dynamic-asset rule clause. */
export type AssetRuleClause = {
  type: "clause";
  operator: "contains" | "eq" | "lt" | "lte" | "ne" | "gt" | "gte" | "regex" | "pcre";
  filterName: string;
  pluginIDConstraint?: string;
  value: string | number | { id: ScId; [key: string]: unknown };
};

/** Nested group of dynamic-asset rules. */
export type AssetRuleGroup = {
  type: "group";
  operator: "all" | "any";
  children: Array<AssetRuleClause | AssetRuleGroup>;
};

/** Top-level dynamic asset rule tree. */
export type AssetRules = {
  operator: "all" | "any";
  children: Array<AssetRuleClause | AssetRuleGroup>;
};

/** Request body for `POST /asset`. Required fields depend on `type`. */
export type CreateAssetBody = {
  type: AssetType;
  prepare?: StringBoolean;
  name?: string;
  description?: string;
  context?: string;
  tags?: string;
  assetDataFields?: Array<{ fieldName?: string; fieldValue?: string }>;
  template?: IdRef;
  filename?: string;
  definedDNSNames?: string;
  definedIPs?: string;
  excludeManagedIPs?: StringBoolean;
  combinations?: unknown;
  rules?: AssetRules;
  definedLDAPQuery?: {
    searchString: string;
    searchBase: string;
    ldap: IdRef;
  };
  filters?: Array<{ filterName: string; value: string | number; operator?: string }>;
  tool?: string;
  sourceType?: string;
  startOffset?: number;
  endOffset?: number;
  sortField?: string;
  sortDir?: SortDirection;
  view?: string;
  scanID?: string | number;
  lce?: IdRef;
  [key: string]: unknown;
};

/** Partial body for `PATCH /asset/{id}`. */
export type UpdateAssetBody = Partial<CreateAssetBody>;

/** Asset record returned by `/asset`. */
export type Asset = {
  id?: ScId;
  uuid?: string;
  name?: string | null;
  description?: string | null;
  type?: string;
  status?: string | number;
  tags?: string | null;
  context?: string | null;
  createdTime?: string | number;
  modifiedTime?: string | number;
  ipCount?: string | number;
  owner?: NamedRef;
  ownerGroup?: NamedRef;
  creator?: NamedRef;
  organization?: NamedRef;
  groups?: NamedRef[];
  repositories?: unknown[];
  typeFields?: unknown;
  [key: string]: unknown;
};

/** Query-string options for `GET /repository`. */
export type ListRepositoriesQuery = ListQuery;
/** Query-string options for `GET /plugin`. */
export type ListPluginsQuery = ListQuery & {
  startOffset?: string | number;
  endOffset?: string | number;
  sortField?: string;
  sortDirection?: SortDirection;
  filterField?: string;
  op?: string;
  value?: string;
  type?: string;
};

/** Repository record returned by `/repository`. */
export type Repository = {
  id?: ScId;
  uuid?: string;
  name?: string | null;
  description?: string | null;
  type?: string;
  dataFormat?: string;
  vulnCount?: string | number;
  remoteID?: string | number | null;
  remoteIP?: string | null;
  running?: string | boolean;
  downloadFormat?: string;
  lastSyncTime?: string | number;
  lastVulnUpdate?: string | number;
  createdTime?: string | number;
  modifiedTime?: string | number;
  typeFields?: unknown;
  [key: string]: unknown;
};

/** Organization record returned by `/organization`. */
export type Organization = {
  id?: ScId;
  uuid?: string;
  name?: string | null;
  description?: string | null;
  createdTime?: string | number;
  modifiedTime?: string | number;
  userCount?: string | number;
  vulnScoringSystem?: string;
  repositories?: NamedRef[];
  zones?: NamedRef[];
  lces?: NamedRef[];
  [key: string]: unknown;
};

/** Nessus plugin record returned by `/plugin`. */
export type Plugin = {
  id?: ScId;
  name?: string | null;
  description?: string | null;
  family?: NamedRef;
  type?: string;
  [key: string]: unknown;
};

/** Scan policy record returned by `/policy`. */
export type Policy = {
  id?: ScId;
  uuid?: string;
  name?: string | null;
  description?: string | null;
  tags?: string | null;
  createdTime?: string | number;
  modifiedTime?: string | number;
  status?: string | number;
  owner?: NamedRef;
  ownerGroup?: NamedRef;
  creator?: NamedRef;
  [key: string]: unknown;
};

/** User group record returned by `/group`. */
export type Group = {
  id?: ScId;
  name?: string | null;
  description?: string | null;
  createdTime?: string | number;
  modifiedTime?: string | number;
  [key: string]: unknown;
};

/** Query-string options for `GET /user`. */
export type ListUsersQuery = ListQuery & {
  orgID?: ScId;
  paginated?: boolean;
  startOffset?: string | number;
  endOffset?: string | number;
  filters?: unknown;
};

/** One current-user preference entry. */
export type UserPreference = {
  name: string;
  value?: string | null;
  tag?: string | null;
  [key: string]: unknown;
};

/** User record returned by `/user` or `/currentUser`. */
export type User = {
  id?: ScId;
  uuid?: string;
  username?: string;
  firstname?: string | null;
  lastname?: string | null;
  status?: string | number;
  email?: string | null;
  title?: string | null;
  address?: string | null;
  city?: string | null;
  state?: string | null;
  country?: string | null;
  phone?: string | null;
  fax?: string | null;
  createdTime?: string | number;
  modifiedTime?: string | number;
  lastLogin?: string | number;
  lastLoginIP?: string | null;
  locked?: string | boolean;
  authType?: string;
  role?: NamedRef;
  group?: NamedRef;
  organization?: NamedRef;
  ldap?: NamedRef;
  apiKeys?: unknown[];
  preferences?: UserPreference[];
  canUse?: string | boolean;
  canManage?: string | boolean;
  [key: string]: unknown;
};

/** Request body for `PATCH /currentUser`. */
export type UpdateCurrentUserBody = {
  firstname?: string;
  lastname?: string;
  title?: string;
  email?: string;
  address?: string;
  city?: string;
  state?: string;
  country?: string;
  phone?: string;
  fax?: string;
  fingerprint?: string | null;
  emailNotice?: "both" | "id" | "none" | "password";
  password?: string;
  preferences?: UserPreference[];
};

/** Request body for `POST /currentUser/switch`. */
export type SwitchUserBody = { username: string };
/** Request body for `PATCH /currentUser/preferences`. */
export type UserPreferenceUpdate = {
  name: string;
  tag?: string;
  value: string;
};

/** Appliance status returned by `GET /status`. */
export type Status = {
  jobd?: string;
  licenseStatus?: string;
  migrationStatus?: unknown;
  PluginSubscriptionStatus?: string | null;
  LCEPluginSubscriptionStatus?: string | null;
  PassivePluginSubscriptionStatus?: string | null;
  pluginUpdates?: unknown;
  feedUpdates?: unknown;
  activeIPs?: string | number;
  licensedIPs?: string | number;
  noLCEs?: string | boolean;
  noReps?: string | boolean;
  lastDbBackupStatus?: string | number;
  lastDbBackupSuccess?: string | number;
  lastDbBackupFailure?: string | number;
  zones?: unknown;
  [key: string]: unknown;
};

/** System metadata returned by `GET /system`. */
export type System = {
  version?: string;
  buildID?: string;
  releaseID?: string;
  banner?: string | null;
  uuid?: string;
  licenseStatus?: string;
  licenseExpiration?: string | number;
  activeIPs?: string | number;
  licensedIPs?: string | number;
  sessionTimeout?: string | number;
  token?: string | number;
  reportTypes?: unknown[];
  [key: string]: unknown;
};

/** Host selector for an accept/recast risk rule (`all`, `ip`, `asset`). */
export type AcceptRiskHostType = "all" | "ip" | "asset";

/** Request body for `POST /acceptRiskRule`. */
export type CreateAcceptRiskRuleBody = {
  repositories: IdRef[];
  plugin: IdRef;
  comments?: string;
  expires?: string | number;
  hostType?: AcceptRiskHostType;
  hostValue?: string | IdRef;
  port?: string | number;
  protocol?: string | number;
  organization?: IdRef;
  [key: string]: unknown;
};

/** Request body for `POST /recastRiskRule`. Includes `newSeverity`. */
export type CreateRecastRiskRuleBody = CreateAcceptRiskRuleBody & {
  newSeverity: string | number | IdRef;
};

/** Accept-risk or recast-risk rule record. */
export type RiskRule = {
  id?: ScId;
  comments?: string | null;
  hostType?: string;
  hostValue?: unknown;
  port?: string | number;
  protocol?: string | number;
  expires?: string | number;
  plugin?: NamedRef;
  repository?: NamedRef;
  organization?: NamedRef;
  [key: string]: unknown;
};

/**
 * Opaque authenticated HTTP transport created by {@link SecurityCenter}.
 * Resource helpers accept this type; do not construct it yourself.
 */
export type SecurityCenterTransport = {
  /** Normalized appliance URL with no trailing `/rest`. */
  readonly baseUrl: string;
};

/** Fetch implementation used by the client. Must honor `init.client` for mTLS. */
export type SecurityCenterFetch = (
  input: string | URL | Request,
  init?: RequestInit,
) => Promise<Response>;

/**
 * mTLS material for self-hosted Security Center appliances.
 *
 * Pass a combined PEM (`pem`) or a separate `cert` + `key`. Each value may
 * be PEM text or a filesystem path. Optional `ca` is the server / private
 * PKI CA used to verify the appliance.
 */
export type MtlsOptions = {
  pem?: string;
  cert?: string;
  key?: string;
  ca?: string | string[];
};

/** Validated constructor fields (auth, mTLS paths, timeouts). */
export type SecurityCenterOptionsInput = {
  url: string;
  accessKey?: string;
  secretKey?: string;
  username?: string;
  password?: string;
  timeoutMs?: number;
  pem?: string;
  cert?: string;
  key?: string;
  ca?: string | string[];
};

/** Full {@link SecurityCenter} constructor options, including `fetch` and `httpClient`. */
export type SecurityCenterOptions = SecurityCenterOptionsInput & {
  fetch?: SecurityCenterFetch;
  httpClient?: Deno.HttpClient;
};

/** Common list payload that splits records into `usable` and `manageable`. */
export type UsableManageable<Item> = {
  usable?: Item[];
  manageable?: Item[];
};
