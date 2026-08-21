import { SecurityCenterValidationError } from "./errors.ts";
import {
  type HttpMethod,
  normalizeBaseUrl,
  type RequestOptions,
  SecurityCenterHttp,
} from "./http.ts";
import { parseConstructorOptions } from "./options.ts";
import {
  createMtlsHttpClient,
  hasMtlsOptions,
  resolveMtlsMaterial,
} from "./mtls.ts";
import type {
  SecurityCenterOptions,
  SecurityCenterOptionsInput,
  TokenLoginBody,
} from "./types.ts";
import { AnalysisResource } from "./resources/analysis.ts";
import { AssetResource } from "./resources/assets.ts";
import {
  AcceptRiskRuleResource,
  CurrentUserResource,
  RecastRiskRuleResource,
  StatusResource,
  SystemResource,
  UserResource,
} from "./resources/admin.ts";
import {
  GroupResource,
  OrganizationResource,
  PluginResource,
  PolicyResource,
  RepositoryResource,
} from "./resources/catalog.ts";
import { QueryResource } from "./resources/queries.ts";
import { ScanResultResource } from "./resources/scan-results.ts";
import { ScanResource } from "./resources/scans.ts";
import { TokenResource } from "./resources/token.ts";

/**
 * Typed Tenable Security Center (on-prem / data-center) API client.
 *
 * Authenticate with API keys (`x-apikey`) or a username/password session
 * (`X-SecurityCenter` + cookies). Self-hosted appliances can also present
 * a client certificate (`pem` or `cert`/`key`) for mTLS.
 *
 * Required Deno permissions: `--allow-net` for the Security Center host.
 * Add `--allow-read` when `pem`, `cert`, `key`, or `ca` are filesystem paths.
 *
 * @example Usage
 * ```ts ignore
 * import { SecurityCenter } from "@hmalinchock/security-center";
 *
 * const securityCenter = new SecurityCenter({
 *   url: "https://sc.example.com",
 *   accessKey: "ACCESS",
 *   secretKey: "SECRET",
 * });
 * const scans = await securityCenter.scans.list();
 * ```
 */
export class SecurityCenter {
  /** Vulnerability, event, mobile, and user analysis (`POST /analysis`). */
  readonly analysis: AnalysisResource;
  /** Asset lists and CRUD (`/asset`). */
  readonly assets: AssetResource;
  /** Scan definitions (`/scan`). */
  readonly scans: ScanResource;
  /** Scan results, import, and download (`/scanResult`). */
  readonly scanResults: ScanResultResource;
  /** Saved queries (`/query`). */
  readonly queries: QueryResource;
  /** Repositories (`/repository`). */
  readonly repositories: RepositoryResource;
  /** Organizations (`/organization`). */
  readonly organizations: OrganizationResource;
  /** Plugin catalog (`/plugin`). */
  readonly plugins: PluginResource;
  /** Scan policies (`/policy`). */
  readonly policies: PolicyResource;
  /** User groups (`/group`). */
  readonly groups: GroupResource;
  /** Users (`/user`). */
  readonly users: UserResource;
  /** Current user, preferences, and user-switch (`/currentUser`). */
  readonly currentUser: CurrentUserResource;
  /** Appliance job/license status (`GET /status`). */
  readonly status: StatusResource;
  /** Appliance version and license (`GET /system`). */
  readonly system: SystemResource;
  /** Accept-risk rules (`/acceptRiskRule`). */
  readonly acceptRiskRules: AcceptRiskRuleResource;
  /** Recast-risk rules (`/recastRiskRule`). */
  readonly recastRiskRules: RecastRiskRuleResource;
  /** Session token login/logout (`/token`). */
  readonly token: TokenResource;

  #http: SecurityCenterHttp;
  #username?: string;
  #password?: string;
  #ownsHttpClient = false;

  /**
   * Create a client for one Security Center appliance.
   *
   * Required Deno permissions: `--allow-read` immediately if `pem` / `cert` /
   * `key` / `ca` are file paths. `--allow-net` is needed on the first request.
   *
   * @param options Appliance URL plus API keys, password, and/or mTLS material.
   *
   * @example Usage
   * ```ts ignore
   * import { SecurityCenter } from "@hmalinchock/security-center";
   *
   * const securityCenter = new SecurityCenter({
   *   url: "https://sc.example.com",
   *   accessKey: "ACCESS",
   *   secretKey: "SECRET",
   * });
   * ```
   *
   * @tags allow-net
   */
  constructor(options: SecurityCenterOptions) {
    const parsed = parseConstructorOptions(options);
    const httpClient = resolveHttpClient(options, parsed);
    this.#ownsHttpClient = httpClient.owned;
    this.#http = new SecurityCenterHttp({
      baseUrl: normalizeBaseUrl(parsed.url),
      fetch: options.fetch ?? globalThis.fetch.bind(globalThis),
      httpClient: httpClient.client,
      timeoutMs: parsed.timeoutMs ?? 300_000,
      accessKey: parsed.accessKey,
      secretKey: parsed.secretKey,
      session: { cookies: new Map() },
    });
    this.#username = parsed.username;
    this.#password = parsed.password;

    this.analysis = new AnalysisResource(this.#http);
    this.assets = new AssetResource(this.#http);
    this.scans = new ScanResource(this.#http);
    this.scanResults = new ScanResultResource(this.#http);
    this.queries = new QueryResource(this.#http);
    this.repositories = new RepositoryResource(this.#http);
    this.organizations = new OrganizationResource(this.#http);
    this.plugins = new PluginResource(this.#http);
    this.policies = new PolicyResource(this.#http);
    this.groups = new GroupResource(this.#http);
    this.users = new UserResource(this.#http);
    this.currentUser = new CurrentUserResource(this.#http);
    this.status = new StatusResource(this.#http);
    this.system = new SystemResource(this.#http);
    this.acceptRiskRules = new AcceptRiskRuleResource(this.#http);
    this.recastRiskRules = new RecastRiskRuleResource(this.#http);
    this.token = new TokenResource(this.#http);
  }

  /**
   * Base URL with protocol/host, no trailing `/rest`.
   *
   * Required Deno permissions: none.
   *
   * @example Usage
   * ```ts ignore
   * import { SecurityCenter } from "@hmalinchock/security-center";
   *
   * const securityCenter = new SecurityCenter({
   *   url: "https://sc.example.com",
   *   accessKey: "ACCESS",
   *   secretKey: "SECRET",
   * });
   * securityCenter.baseUrl;
   * ```
   */
  get baseUrl(): string {
    return this.#http.baseUrl;
  }

  /**
   * Log in with username/password. Uses constructor credentials when called
   * with no arguments (`POST /token`).
   *
   * Required Deno permissions: `--allow-net`. Add `--allow-read` if the
   * client was constructed with mTLS file paths.
   *
   * @example Usage
   * ```ts ignore
   * import { SecurityCenter } from "@hmalinchock/security-center";
   *
   * const securityCenter = new SecurityCenter({
   *   url: "https://sc.example.com",
   *   accessKey: "ACCESS",
   *   secretKey: "SECRET",
   * });
   * await securityCenter.login();
   * ```
   *
   * @tags allow-net
   */
  async login(body?: Partial<TokenLoginBody>): Promise<void> {
    const username = body?.username ?? this.#username;
    const password = body?.password ?? this.#password;
    if (!username || !password) {
      throw new SecurityCenterValidationError(
        "username and password are required to login",
      );
    }
    await this.token.login({
      username,
      password,
      releaseSession: body?.releaseSession,
    });
  }

  /**
   * Destroy the session token (`DELETE /token`) and drop local cookies.
   *
   * Required Deno permissions: `--allow-net`. Add `--allow-read` if the
   * client was constructed with mTLS file paths.
   *
   * @example Usage
   * ```ts ignore
   * import { SecurityCenter } from "@hmalinchock/security-center";
   *
   * const securityCenter = new SecurityCenter({
   *   url: "https://sc.example.com",
   *   accessKey: "ACCESS",
   *   secretKey: "SECRET",
   * });
   * await securityCenter.logout();
   * ```
   *
   * @tags allow-net
   */
  async logout(): Promise<void> {
    await this.token.logout();
  }

  /**
   * Close an mTLS `HttpClient` created by this instance. No-op when the
   * caller supplied their own `httpClient`.
   *
   * Required Deno permissions: none.
   *
   * @example Usage
   * ```ts ignore
   * import { SecurityCenter } from "@hmalinchock/security-center";
   *
   * const securityCenter = new SecurityCenter({
   *   url: "https://sc.example.com",
   *   accessKey: "ACCESS",
   *   secretKey: "SECRET",
   * });
   * securityCenter.close();
   * ```
   */
  close(): void {
    if (!this.#ownsHttpClient) return;
    this.#http.closeClient();
    this.#ownsHttpClient = false;
  }

  /**
   * Call any Security Center REST path and unwrap the `response` envelope.
   *
   * Required Deno permissions: `--allow-net`. Add `--allow-read` if the
   * client was constructed with mTLS file paths.
   *
   * @example Usage
   * ```ts ignore
   * import { SecurityCenter } from "@hmalinchock/security-center";
   *
   * const securityCenter = new SecurityCenter({
   *   url: "https://sc.example.com",
   *   accessKey: "ACCESS",
   *   secretKey: "SECRET",
   * });
   * const feed = await securityCenter.request({ method: "GET", path: "/feed" });
   * ```
   *
   * @tags allow-net
   */
  request(options: RequestOptions): Promise<unknown> {
    return this.#http.request(options);
  }

  /**
   * Convenience GET wrapper around {@link SecurityCenter.request}.
   *
   * Required Deno permissions: `--allow-net`. Add `--allow-read` if the
   * client was constructed with mTLS file paths.
   *
   * @example Usage
   * ```ts ignore
   * import { SecurityCenter } from "@hmalinchock/security-center";
   *
   * const securityCenter = new SecurityCenter({
   *   url: "https://sc.example.com",
   *   accessKey: "ACCESS",
   *   secretKey: "SECRET",
   * });
   * const status = await securityCenter.get("/status");
   * ```
   *
   * @tags allow-net
   */
  get(
    path: string,
    query?: Record<string, string | number | boolean | undefined>,
  ): Promise<unknown> {
    return this.#http.request({ method: "GET", path, query });
  }

  /**
   * Convenience POST wrapper around {@link SecurityCenter.request}.
   *
   * Required Deno permissions: `--allow-net`. Add `--allow-read` if the
   * client was constructed with mTLS file paths.
   *
   * @example Usage
   * ```ts ignore
   * import { SecurityCenter } from "@hmalinchock/security-center";
   *
   * const securityCenter = new SecurityCenter({
   *   url: "https://sc.example.com",
   *   accessKey: "ACCESS",
   *   secretKey: "SECRET",
   * });
   * await securityCenter.post("/scan/1/launch", {});
   * ```
   *
   * @tags allow-net
   */
  post(path: string, body?: unknown): Promise<unknown> {
    return this.#http.request({ method: "POST" as HttpMethod, path, body });
  }
}

function resolveHttpClient(
  options: SecurityCenterOptions,
  parsed: SecurityCenterOptionsInput,
): { client?: Deno.HttpClient; owned: boolean } {
  const wantsMtls = hasMtlsOptions(parsed);
  if (options.httpClient && wantsMtls) {
    throw new SecurityCenterValidationError(
      "Pass either httpClient or pem/cert/key/ca, not both",
    );
  }
  if (options.httpClient) return { client: options.httpClient, owned: false };
  if (!wantsMtls) return { owned: false };
  return {
    client: createMtlsHttpClient(resolveMtlsMaterial(parsed)),
    owned: true,
  };
}

