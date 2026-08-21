import { type SecurityCenterHttp, toQueryRecord } from "../http.ts";
import type {
  Asset,
  CreateAssetBody,
  ListAssetsQuery,
  ScId,
  SecurityCenterTransport,
  UpdateAssetBody,
} from "../types.ts";

/**
 * Assets (`/asset`).
 *
 * Prefer {@link SecurityCenter.assets} over constructing this directly.
 */
export class AssetResource {
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
   * List assets (`GET /asset`).
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
   * const assets = await securityCenter.assets.list();
   * ```
   *
   * @tags allow-net
   */
  async list(query: ListAssetsQuery = {}): Promise<
    | { usable?: Asset[]; manageable?: Asset[] }
    | { assets?: Asset[] }
  > {
    const record = toQueryRecord(query);
    if (query.template?.length) {
      record.template = query.template.join(",");
    }
    return await this.#http.request({
      method: "GET",
      path: "/asset",
      query: record,
    });
  }

  /**
   * Get one asset (`GET /asset/{id}`).
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
   * const asset = await securityCenter.assets.get(1);
   * ```
   *
   * @tags allow-net
   */
  async get(id: ScId, query: ListAssetsQuery = {}): Promise<Asset> {
    return await this.#http.request({
      method: "GET",
      path: `/asset/${id}`,
      query: toQueryRecord(query),
    });
  }

  /**
   * Create an asset (`POST /asset`). Required fields depend on `type`.
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
   * const asset = await securityCenter.assets.create({
   *   type: "static",
   *   name: "lab-range",
   *   definedIPs: "10.0.0.0/24",
   * });
   * ```
   *
   * @tags allow-net
   */
  async create(body: CreateAssetBody): Promise<Asset> {
    return await this.#http.request({
      method: "POST",
      path: "/asset",
      body,
    });
  }

  /**
   * Update an asset (`PATCH /asset/{id}`).
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
   * await securityCenter.assets.update(1, { name: "lab-range-2" });
   * ```
   *
   * @tags allow-net
   */
  async update(id: ScId, body: UpdateAssetBody): Promise<Asset> {
    return await this.#http.request({
      method: "PATCH",
      path: `/asset/${id}`,
      body,
    });
  }

  /**
   * Delete an asset (`DELETE /asset/{id}`).
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
   * await securityCenter.assets.delete(1);
   * ```
   *
   * @tags allow-net
   */
  async delete(id: ScId): Promise<unknown> {
    return await this.#http.request({
      method: "DELETE",
      path: `/asset/${id}`,
    });
  }
}
