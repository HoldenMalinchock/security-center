import { type SecurityCenterHttp, toQueryRecord } from "../http.ts";
import type {
  CreateQueryBody,
  ListQueriesQuery,
  Query,
  ScId,
  SecurityCenterTransport,
  UpdateQueryBody,
} from "../types.ts";

/**
 * Saved queries (`/query`).
 *
 * Prefer {@link SecurityCenter.queries} over constructing this directly.
 */
export class QueryResource {
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
   * List saved queries (`GET /query`).
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
   * const queries = await securityCenter.queries.list({ type: "vuln" });
   * ```
   *
   * @tags allow-net
   */
  async list(query: ListQueriesQuery = {}): Promise<{
    usable?: Query[];
    manageable?: Query[];
  }> {
    return await this.#http.request({
      method: "GET",
      path: "/query",
      query: toQueryRecord(query),
    });
  }

  /**
   * Get one saved query (`GET /query/{id}`).
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
   * const query = await securityCenter.queries.get(1);
   * ```
   *
   * @tags allow-net
   */
  async get(id: ScId, query: ListQueriesQuery = {}): Promise<Query> {
    return await this.#http.request({
      method: "GET",
      path: `/query/${id}`,
      query: toQueryRecord(query),
    });
  }

  /**
   * Create a saved query (`POST /query`).
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
   * const query = await securityCenter.queries.create({
   *   name: "Criticals",
   *   type: "vuln",
   *   tool: "vulndetails",
   *   filters: [{ filterName: "severity", operator: "=", value: "4" }],
   * });
   * ```
   *
   * @tags allow-net
   */
  async create(body: CreateQueryBody): Promise<Query> {
    return await this.#http.request({
      method: "POST",
      path: "/query",
      body,
    });
  }

  /**
   * Update a saved query (`PATCH /query/{id}`).
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
   * await securityCenter.queries.update(1, { name: "Criticals (renamed)" });
   * ```
   *
   * @tags allow-net
   */
  async update(id: ScId, body: UpdateQueryBody): Promise<Query> {
    return await this.#http.request({
      method: "PATCH",
      path: `/query/${id}`,
      body,
    });
  }

  /**
   * Delete a saved query (`DELETE /query/{id}`).
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
   * await securityCenter.queries.delete(1);
   * ```
   *
   * @tags allow-net
   */
  async delete(id: ScId): Promise<unknown> {
    return await this.#http.request({
      method: "DELETE",
      path: `/query/${id}`,
    });
  }
}
