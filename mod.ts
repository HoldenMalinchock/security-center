/**
 * @module
 *
 * Typed Deno client for the Tenable Security Center (Tenable.sc) REST API.
 *
 * ```ts ignore
 * import { SecurityCenter } from "@hmalinchock/security-center";
 *
 * const securityCenter = new SecurityCenter({
 *   url: "https://sc.example.com",
 *   accessKey: "ACCESS",
 *   secretKey: "SECRET",
 * });
 *
 * const scans = await securityCenter.scans.list();
 * const vulns = await securityCenter.analysis.vulns({
 *   tool: "vulndetails",
 *   sourceType: "cumulative",
 *   filters: [{ filterName: "severity", operator: "=", value: "3,4" }],
 * });
 * ```
 */

export { SecurityCenter } from "./src/client.ts";
export {
  SecurityCenterError,
  SecurityCenterValidationError,
} from "./src/errors.ts";
export { buildUrl, normalizeBaseUrl } from "./src/http.ts";
export type { HttpMethod, RequestOptions, SessionState } from "./src/http.ts";
export { AnalysisResource } from "./src/resources/analysis.ts";
export { AssetResource } from "./src/resources/assets.ts";
export { QueryResource } from "./src/resources/queries.ts";
export { ScanResource } from "./src/resources/scans.ts";
export { ScanResultResource } from "./src/resources/scan-results.ts";
export { TokenResource } from "./src/resources/token.ts";
export {
  AcceptRiskRuleResource,
  CurrentUserResource,
  RecastRiskRuleResource,
  StatusResource,
  SystemResource,
  UserResource,
} from "./src/resources/admin.ts";
export {
  GroupResource,
  OrganizationResource,
  PluginResource,
  PolicyResource,
  RepositoryResource,
} from "./src/resources/catalog.ts";
export type * from "./src/types.ts";
