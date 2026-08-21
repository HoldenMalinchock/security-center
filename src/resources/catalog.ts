import { type SecurityCenterHttp, toQueryRecord } from "../http.ts";
import type {
  Group,
  ListPluginsQuery,
  ListQuery,
  ListRepositoriesQuery,
  Organization,
  Plugin,
  Policy,
  Repository,
  ScId,
  SecurityCenterTransport,
} from "../types.ts";

/**
 * Repositories (`/repository`).
 *
 * Prefer {@link SecurityCenter.repositories} over constructing this directly.
 */
export class RepositoryResource {
  #http: SecurityCenterHttp;

  /**
   * Create this resource. Prefer accessing it from {@link SecurityCenter}.
   *
   * Required Deno permissions: none until a method is called.
   *
   * @param http Opaque transport from {@link SecurityCenter}.
   */
  constructor(http: SecurityCenterTransport) {
    this.#http = http as SecurityCenterHttp;
  }

  /**
   * GET /repository.
   *
   * Required Deno permissions: `--allow-net`. Add `--allow-read` if the
   * client was constructed with mTLS file paths (`pem`, `cert`, `key`, `ca`).
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
   * const repos = await securityCenter.repositories.list();
   * ```
   *
   * @tags allow-net
   */
  async list(query: ListRepositoriesQuery = {}): Promise<
    { usable?: Repository[]; manageable?: Repository[] } | Repository[]
  > {
    return await this.#http.request({
      method: "GET",
      path: "/repository",
      query: toQueryRecord(query),
    });
  }

  /**
   * GET /repository/{id}.
   *
   * Required Deno permissions: `--allow-net`. Add `--allow-read` if the
   * client was constructed with mTLS file paths (`pem`, `cert`, `key`, `ca`).
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
   * const repo = await securityCenter.repositories.get(1);
   * ```
   *
   * @tags allow-net
   */
  async get(id: ScId, query: ListRepositoriesQuery = {}): Promise<Repository> {
    return await this.#http.request({
      method: "GET",
      path: `/repository/${id}`,
      query: toQueryRecord(query),
    });
  }
}

/**
 * Organizations (`/organization`).
 *
 * Prefer {@link SecurityCenter.organizations} over constructing this directly.
 */
export class OrganizationResource {
  #http: SecurityCenterHttp;

  /**
   * Create this resource. Prefer accessing it from {@link SecurityCenter}.
   *
   * Required Deno permissions: none until a method is called.
   *
   * @param http Opaque transport from {@link SecurityCenter}.
   */
  constructor(http: SecurityCenterTransport) {
    this.#http = http as SecurityCenterHttp;
  }

  /**
   * GET /organization.
   *
   * Required Deno permissions: `--allow-net`. Add `--allow-read` if the
   * client was constructed with mTLS file paths (`pem`, `cert`, `key`, `ca`).
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
   * const orgs = await securityCenter.organizations.list();
   * ```
   *
   * @tags allow-net
   */
  async list(query: ListQuery = {}): Promise<Organization[]> {
    return await this.#http.request({
      method: "GET",
      path: "/organization",
      query: toQueryRecord(query),
    });
  }

  /**
   * GET /organization/{id}.
   *
   * Required Deno permissions: `--allow-net`. Add `--allow-read` if the
   * client was constructed with mTLS file paths (`pem`, `cert`, `key`, `ca`).
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
   * const org = await securityCenter.organizations.get(1);
   * ```
   *
   * @tags allow-net
   */
  async get(id: ScId, query: ListQuery = {}): Promise<Organization> {
    return await this.#http.request({
      method: "GET",
      path: `/organization/${id}`,
      query: toQueryRecord(query),
    });
  }
}

/**
 * Plugin catalog (`/plugin`).
 *
 * Prefer {@link SecurityCenter.plugins} over constructing this directly.
 */
export class PluginResource {
  #http: SecurityCenterHttp;

  /**
   * Create this resource. Prefer accessing it from {@link SecurityCenter}.
   *
   * Required Deno permissions: none until a method is called.
   *
   * @param http Opaque transport from {@link SecurityCenter}.
   */
  constructor(http: SecurityCenterTransport) {
    this.#http = http as SecurityCenterHttp;
  }

  /**
   * GET /plugin.
   *
   * Required Deno permissions: `--allow-net`. Add `--allow-read` if the
   * client was constructed with mTLS file paths (`pem`, `cert`, `key`, `ca`).
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
   * const plugins = await securityCenter.plugins.list({ startOffset: 0, endOffset: 50 });
   * ```
   *
   * @tags allow-net
   */
  async list(query: ListPluginsQuery = {}): Promise<
    | {
      results?: Plugin[];
      totalRecords?: string | number;
      startOffset?: string | number;
      endOffset?: string | number;
    }
    | Plugin[]
  > {
    return await this.#http.request({
      method: "GET",
      path: "/plugin",
      query: toQueryRecord(query),
    });
  }

  /**
   * GET /plugin/{id}.
   *
   * Required Deno permissions: `--allow-net`. Add `--allow-read` if the
   * client was constructed with mTLS file paths (`pem`, `cert`, `key`, `ca`).
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
   * const plugin = await securityCenter.plugins.get(11950);
   * ```
   *
   * @tags allow-net
   */
  async get(id: ScId, query: ListPluginsQuery = {}): Promise<Plugin> {
    return await this.#http.request({
      method: "GET",
      path: `/plugin/${id}`,
      query: toQueryRecord(query),
    });
  }
}

/**
 * Scan policies (`/policy`).
 *
 * Prefer {@link SecurityCenter.policies} over constructing this directly.
 */
export class PolicyResource {
  #http: SecurityCenterHttp;

  /**
   * Create this resource. Prefer accessing it from {@link SecurityCenter}.
   *
   * Required Deno permissions: none until a method is called.
   *
   * @param http Opaque transport from {@link SecurityCenter}.
   */
  constructor(http: SecurityCenterTransport) {
    this.#http = http as SecurityCenterHttp;
  }

  /**
   * GET /policy.
   *
   * Required Deno permissions: `--allow-net`. Add `--allow-read` if the
   * client was constructed with mTLS file paths (`pem`, `cert`, `key`, `ca`).
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
   * const policies = await securityCenter.policies.list();
   * ```
   *
   * @tags allow-net
   */
  async list(query: ListQuery = {}): Promise<{
    usable?: Policy[];
    manageable?: Policy[];
  }> {
    return await this.#http.request({
      method: "GET",
      path: "/policy",
      query: toQueryRecord(query),
    });
  }

  /**
   * GET /policy/{id}.
   *
   * Required Deno permissions: `--allow-net`. Add `--allow-read` if the
   * client was constructed with mTLS file paths (`pem`, `cert`, `key`, `ca`).
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
   * const policy = await securityCenter.policies.get(1);
   * ```
   *
   * @tags allow-net
   */
  async get(id: ScId, query: ListQuery = {}): Promise<Policy> {
    return await this.#http.request({
      method: "GET",
      path: `/policy/${id}`,
      query: toQueryRecord(query),
    });
  }
}

/**
 * User groups (`/group`).
 *
 * Prefer {@link SecurityCenter.groups} over constructing this directly.
 */
export class GroupResource {
  #http: SecurityCenterHttp;

  /**
   * Create this resource. Prefer accessing it from {@link SecurityCenter}.
   *
   * Required Deno permissions: none until a method is called.
   *
   * @param http Opaque transport from {@link SecurityCenter}.
   */
  constructor(http: SecurityCenterTransport) {
    this.#http = http as SecurityCenterHttp;
  }

  /**
   * GET /group.
   *
   * Required Deno permissions: `--allow-net`. Add `--allow-read` if the
   * client was constructed with mTLS file paths (`pem`, `cert`, `key`, `ca`).
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
   * const groups = await securityCenter.groups.list();
   * ```
   *
   * @tags allow-net
   */
  async list(query: ListQuery = {}): Promise<
    { usable?: Group[]; manageable?: Group[] } | Group[]
  > {
    return await this.#http.request({
      method: "GET",
      path: "/group",
      query: toQueryRecord(query),
    });
  }

  /**
   * GET /group/{id}.
   *
   * Required Deno permissions: `--allow-net`. Add `--allow-read` if the
   * client was constructed with mTLS file paths (`pem`, `cert`, `key`, `ca`).
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
   * const group = await securityCenter.groups.get(1);
   * ```
   *
   * @tags allow-net
   */
  async get(id: ScId, query: ListQuery = {}): Promise<Group> {
    return await this.#http.request({
      method: "GET",
      path: `/group/${id}`,
      query: toQueryRecord(query),
    });
  }
}
