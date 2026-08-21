import { SecurityCenterValidationError } from "../errors.ts";
import { type SecurityCenterHttp, toQueryRecord } from "../http.ts";
import type {
  CopyScanBody,
  CreateScanBody,
  LaunchScanBody,
  ListScansQuery,
  Scan,
  ScId,
  SecurityCenterTransport,
  UpdateScanBody,
} from "../types.ts";

/**
 * Scan definitions (`/scan`).
 *
 * Prefer {@link SecurityCenter.scans} over constructing this directly.
 */
export class ScanResource {
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
   * List scans (`GET /scan`).
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
   * const scans = await securityCenter.scans.list({ fields: ["id", "name"] });
   * ```
   *
   * @tags allow-net
   */
  async list(query: ListScansQuery = {}): Promise<{
    usable?: Scan[];
    manageable?: Scan[];
  }> {
    return await this.#http.request({
      method: "GET",
      path: "/scan",
      query: toQueryRecord(query),
    });
  }

  /**
   * Get one scan (`GET /scan/{id}`).
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
   * const scan = await securityCenter.scans.get(1);
   * ```
   *
   * @tags allow-net
   */
  async get(id: ScId, query: ListScansQuery = {}): Promise<Scan> {
    return await this.#http.request({
      method: "GET",
      path: `/scan/${id}`,
      query: toQueryRecord(query),
    });
  }

  /**
   * Create a scan (`POST /scan`). `name` and `repository` are required.
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
   * const scan = await securityCenter.scans.create({
   *   name: "Weekly",
   *   repository: { id: 1 },
   * });
   * ```
   *
   * @tags allow-net
   */
  async create(body: CreateScanBody): Promise<Scan> {
    return await this.#http.request({
      method: "POST",
      path: "/scan",
      body,
    });
  }

  /**
   * Update a scan (`PATCH /scan/{id}`).
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
   * const scan = await securityCenter.scans.update(1, { name: "Weekly (renamed)" });
   * ```
   *
   * @tags allow-net
   */
  async update(id: ScId, body: UpdateScanBody): Promise<Scan> {
    return await this.#http.request({
      method: "PATCH",
      path: `/scan/${id}`,
      body,
    });
  }

  /**
   * Delete a scan (`DELETE /scan/{id}`).
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
   * await securityCenter.scans.delete(1);
   * ```
   *
   * @tags allow-net
   */
  async delete(id: ScId): Promise<unknown> {
    return await this.#http.request({
      method: "DELETE",
      path: `/scan/${id}`,
    });
  }

  /**
   * Copy a scan to another user (`POST /scan/{id}/copy`).
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
   * await securityCenter.scans.copy(1, { name: "Weekly copy", targetUser: { id: 2 } });
   * ```
   *
   * @tags allow-net
   */
  async copy(id: ScId, body: CopyScanBody): Promise<unknown> {
    return await this.#http.request({
      method: "POST",
      path: `/scan/${id}/copy`,
      body,
    });
  }

  /**
   * Launch a scan (`POST /scan/{id}/launch`).
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
   * await securityCenter.scans.launch(1);
   * ```
   *
   * @tags allow-net
   */
  async launch(id: ScId, body: LaunchScanBody = {}): Promise<unknown> {
    const hasTarget = body.diagnosticTarget !== undefined;
    const hasPassword = body.diagnosticPassword !== undefined;
    if (hasTarget !== hasPassword) {
      throw new SecurityCenterValidationError(
        "diagnosticTarget and diagnosticPassword must be provided together",
      );
    }
    return await this.#http.request({
      method: "POST",
      path: `/scan/${id}/launch`,
      body,
    });
  }
}
