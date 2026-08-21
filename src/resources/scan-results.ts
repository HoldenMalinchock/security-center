import { type SecurityCenterHttp, toQueryRecord } from "../http.ts";
import type {
  CopyScanResultBody,
  EmailScanResultBody,
  ImportScanResultBody,
  ListScanResultsQuery,
  ReimportScanResultBody,
  ScanResult,
  ScId,
  SecurityCenterTransport,
} from "../types.ts";

/**
 * Scan results (`/scanResult`).
 *
 * Prefer {@link SecurityCenter.scanResults} over constructing this directly.
 */
export class ScanResultResource {
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
   * List scan results (`GET /scanResult`).
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
   * const results = await securityCenter.scanResults.list({ completed: true });
   * ```
   *
   * @tags allow-net
   */
  async list(query: ListScanResultsQuery = {}): Promise<{
    usable?: ScanResult[];
    manageable?: ScanResult[];
  }> {
    return await this.#http.request({
      method: "GET",
      path: "/scanResult",
      query: toQueryRecord(query),
    });
  }

  /**
   * Get one scan result (`GET /scanResult/{id}`).
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
   * const result = await securityCenter.scanResults.get(1);
   * ```
   *
   * @tags allow-net
   */
  async get(id: ScId, query: ListScanResultsQuery = {}): Promise<ScanResult> {
    return await this.#http.request({
      method: "GET",
      path: `/scanResult/${id}`,
      query: toQueryRecord(query),
    });
  }

  /**
   * Delete a scan result (`DELETE /scanResult/{id}`).
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
   * await securityCenter.scanResults.delete(1);
   * ```
   *
   * @tags allow-net
   */
  async delete(id: ScId): Promise<unknown> {
    return await this.#http.request({
      method: "DELETE",
      path: `/scanResult/${id}`,
    });
  }

  /**
   * Copy a scan result to other users (`POST /scanResult/{id}/copy`).
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
   * await securityCenter.scanResults.copy(1, { users: [{ id: 2 }] });
   * ```
   *
   * @tags allow-net
   */
  async copy(id: ScId, body: CopyScanResultBody): Promise<unknown> {
    return await this.#http.request({
      method: "POST",
      path: `/scanResult/${id}/copy`,
      body,
    });
  }

  /**
   * Email a scan result (`POST /scanResult/{id}/email`).
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
   * await securityCenter.scanResults.email(1, { email: "soc@example.com" });
   * ```
   *
   * @tags allow-net
   */
  async email(id: ScId, body: EmailScanResultBody): Promise<unknown> {
    return await this.#http.request({
      method: "POST",
      path: `/scanResult/${id}/email`,
      body,
    });
  }

  /**
   * Import a Nessus results file already on the appliance (`POST /scanResult/import`).
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
   * await securityCenter.scanResults.import({
   *   filename: "scan.nessus",
   *   repository: { id: 1 },
   * });
   * ```
   *
   * @tags allow-net
   */
  async import(body: ImportScanResultBody): Promise<unknown> {
    return await this.#http.request({
      method: "POST",
      path: "/scanResult/import",
      body,
    });
  }

  /**
   * Re-import an existing result (`POST /scanResult/{id}/import`).
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
   * await securityCenter.scanResults.reimport(1);
   * ```
   *
   * @tags allow-net
   */
  async reimport(id: ScId, body: ReimportScanResultBody = {}): Promise<unknown> {
    return await this.#http.request({
      method: "POST",
      path: `/scanResult/${id}/import`,
      body,
    });
  }

  /**
   * Stop a running scan result (`POST /scanResult/{id}/stop`).
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
   * await securityCenter.scanResults.stop(1);
   * ```
   *
   * @tags allow-net
   */
  async stop(id: ScId): Promise<ScanResult> {
    return await this.#http.request({
      method: "POST",
      path: `/scanResult/${id}/stop`,
    });
  }

  /**
   * Pause a running scan result (`POST /scanResult/{id}/pause`).
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
   * await securityCenter.scanResults.pause(1);
   * ```
   *
   * @tags allow-net
   */
  async pause(id: ScId): Promise<ScanResult> {
    return await this.#http.request({
      method: "POST",
      path: `/scanResult/${id}/pause`,
    });
  }

  /**
   * Resume a paused scan result (`POST /scanResult/{id}/resume`).
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
   * await securityCenter.scanResults.resume(1);
   * ```
   *
   * @tags allow-net
   */
  async resume(id: ScId): Promise<ScanResult> {
    return await this.#http.request({
      method: "POST",
      path: `/scanResult/${id}/resume`,
    });
  }

  /**
   * Download a scan result as raw bytes (`POST /scanResult/{id}/download`).
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
   * const bytes = await securityCenter.scanResults.download(1);
   * ```
   *
   * @tags allow-net
   */
  async download(id: ScId): Promise<Uint8Array> {
    return await this.#http.request({
      method: "POST",
      path: `/scanResult/${id}/download`,
      raw: true,
    });
  }
}
