import { type SecurityCenterHttp, toQueryRecord } from "../http.ts";
import type {
  CreateAcceptRiskRuleBody,
  CreateRecastRiskRuleBody,
  ListQuery,
  ListUsersQuery,
  RiskRule,
  ScId,
  Status,
  SwitchUserBody,
  System,
  UpdateCurrentUserBody,
  User,
  UserPreference,
  SecurityCenterTransport,
} from "../types.ts";

/**
 * Users (`/user`).
 *
 * Prefer {@link SecurityCenter.users} over constructing this directly.
 */
export class UserResource {
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
   * GET /user.
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
   * const users = await securityCenter.users.list();
   * ```
   *
   * @tags allow-net
   */
  async list(query: ListUsersQuery = {}): Promise<
    | User[]
    | {
      results?: User[];
      totalRecords?: string | number;
      returnedRecords?: string | number;
      startOffset?: string | number;
      endOffset?: string | number;
    }
  > {
    return await this.#http.request({
      method: "GET",
      path: "/user",
      query: toQueryRecord(query),
    });
  }

  /**
   * GET /user/{id}.
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
   * const user = await securityCenter.users.get(1);
   * ```
   *
   * @tags allow-net
   */
  async get(id: ScId, query: ListUsersQuery = {}): Promise<User> {
    return await this.#http.request({
      method: "GET",
      path: `/user/${id}`,
      query: toQueryRecord(query),
    });
  }
}

/**
 * Current user, preferences, and user-switch (`/currentUser`).
 *
 * Prefer {@link SecurityCenter.currentUser} over constructing this directly.
 */
export class CurrentUserResource {
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
   * GET /currentUser.
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
   * const me = await securityCenter.currentUser.get();
   * ```
   *
   * @tags allow-net
   */
  async get(query: ListQuery = {}): Promise<User> {
    return await this.#http.request({
      method: "GET",
      path: "/currentUser",
      query: toQueryRecord(query),
    });
  }

  /**
   * PATCH /currentUser.
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
   * await securityCenter.currentUser.update({ title: "Engineer" });
   * ```
   *
   * @tags allow-net
   */
  async update(body: UpdateCurrentUserBody): Promise<User> {
    return await this.#http.request({
      method: "PATCH",
      path: "/currentUser",
      body,
    });
  }

  /**
   * GET /currentUser/preferences.
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
   * const prefs = await securityCenter.currentUser.listPreferences();
   * ```
   *
   * @tags allow-net
   */
  async listPreferences(query: {
    name?: string;
    tag?: string;
  } = {}): Promise<UserPreference[]> {
    return await this.#http.request({
      method: "GET",
      path: "/currentUser/preferences",
      query,
    });
  }

  /**
   * PATCH /currentUser/preferences.
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
   * await securityCenter.currentUser.updatePreference({
   *   name: "timezone",
   *   value: "UTC",
   * });
   * ```
   *
   * @tags allow-net
   */
  async updatePreference(body: {
    name: string;
    value: string;
    tag?: string;
  }): Promise<UserPreference[]> {
    return await this.#http.request({
      method: "PATCH",
      path: "/currentUser/preferences",
      body,
    });
  }

  /**
   * DELETE /currentUser/preferences.
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
   * await securityCenter.currentUser.deletePreferences({ name: "timezone" });
   * ```
   *
   * @tags allow-net
   */
  async deletePreferences(query: {
    name?: string;
    tag?: string;
  } = {}): Promise<unknown> {
    return await this.#http.request({
      method: "DELETE",
      path: "/currentUser/preferences",
      query,
    });
  }

  /**
   * POST /currentUser/switch.
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
   * await securityCenter.currentUser.switchTo({ username: "auditor" });
   * ```
   *
   * @tags allow-net
   */
  async switchTo(body: SwitchUserBody): Promise<User> {
    return await this.#http.request({
      method: "POST",
      path: "/currentUser/switch",
      body,
    });
  }
}

/**
 * Appliance job/license status (`GET /status`).
 *
 * Prefer {@link SecurityCenter.status} over constructing this directly.
 */
export class StatusResource {
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
   * GET /status.
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
   * const status = await securityCenter.status.get();
   * ```
   *
   * @tags allow-net
   */
  async get(query: ListQuery = {}): Promise<Status> {
    return await this.#http.request({
      method: "GET",
      path: "/status",
      query: toQueryRecord(query),
    });
  }
}

/**
 * Appliance version and license (`GET /system`).
 *
 * Prefer {@link SecurityCenter.system} over constructing this directly.
 */
export class SystemResource {
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
   * GET /system.
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
   * const system = await securityCenter.system.get();
   * ```
   *
   * @tags allow-net
   */
  async get(): Promise<System> {
    return await this.#http.request({
      method: "GET",
      path: "/system",
    });
  }
}

/**
 * Accept-risk rules (`/acceptRiskRule`).
 *
 * Prefer {@link SecurityCenter.acceptRiskRules} over constructing this directly.
 */
export class AcceptRiskRuleResource {
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
   * GET /acceptRiskRule.
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
   * const rules = await securityCenter.acceptRiskRules.list();
   * ```
   *
   * @tags allow-net
   */
  async list(query: ListQuery = {}): Promise<
    RiskRule[] | { usable?: RiskRule[]; manageable?: RiskRule[] }
  > {
    return await this.#http.request({
      method: "GET",
      path: "/acceptRiskRule",
      query: toQueryRecord(query),
    });
  }

  /**
   * POST /acceptRiskRule.
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
   * await securityCenter.acceptRiskRules.create({
   *   plugin: { id: 11950 },
   *   repositories: [{ id: 1 }],
   *   comments: "accepted",
   * });
   * ```
   *
   * @tags allow-net
   */
  async create(body: CreateAcceptRiskRuleBody): Promise<RiskRule> {
    return await this.#http.request({
      method: "POST",
      path: "/acceptRiskRule",
      body,
    });
  }

  /**
   * DELETE /acceptRiskRule/{id}.
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
   * await securityCenter.acceptRiskRules.delete(1);
   * ```
   *
   * @tags allow-net
   */
  async delete(id: ScId): Promise<unknown> {
    return await this.#http.request({
      method: "DELETE",
      path: `/acceptRiskRule/${id}`,
    });
  }
}

/**
 * Recast-risk rules (`/recastRiskRule`).
 *
 * Prefer {@link SecurityCenter.recastRiskRules} over constructing this directly.
 */
export class RecastRiskRuleResource {
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
   * GET /recastRiskRule.
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
   * const rules = await securityCenter.recastRiskRules.list();
   * ```
   *
   * @tags allow-net
   */
  async list(query: ListQuery = {}): Promise<
    RiskRule[] | { usable?: RiskRule[]; manageable?: RiskRule[] }
  > {
    return await this.#http.request({
      method: "GET",
      path: "/recastRiskRule",
      query: toQueryRecord(query),
    });
  }

  /**
   * POST /recastRiskRule.
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
   * await securityCenter.recastRiskRules.create({
   *   plugin: { id: 11950 },
   *   repositories: [{ id: 1 }],
   *   newSeverity: 2,
   * });
   * ```
   *
   * @tags allow-net
   */
  async create(body: CreateRecastRiskRuleBody): Promise<RiskRule> {
    return await this.#http.request({
      method: "POST",
      path: "/recastRiskRule",
      body,
    });
  }

  /**
   * DELETE /recastRiskRule/{id}.
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
   * await securityCenter.recastRiskRules.delete(1);
   * ```
   *
   * @tags allow-net
   */
  async delete(id: ScId): Promise<unknown> {
    return await this.#http.request({
      method: "DELETE",
      path: `/recastRiskRule/${id}`,
    });
  }
}
