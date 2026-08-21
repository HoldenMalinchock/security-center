import { SecurityCenterValidationError } from "../errors.ts";
import type { SecurityCenterHttp } from "../http.ts";
import type {
  AnalysisDownloadRequest,
  AnalysisResponse,
  EventAnalysisInput,
  EventAnalysisRequest,
  MobileAnalysisInput,
  MobileAnalysisRequest,
  QueryInput,
  SecurityCenterTransport,
  UserAnalysisRequest,
  VulnAnalysisInput,
  VulnAnalysisRequest,
} from "../types.ts";

function nestQuery(
  input: {
    query?: QueryInput;
    queryId?: string | number;
    tool?: string;
    filters?: unknown;
  },
  defaultType: "vuln" | "lce" | "mobile" | "user",
): QueryInput {
  if (input.queryId !== undefined) return { id: input.queryId };
  if (input.query) return input.query;
  if (input.tool) {
    return {
      tool: input.tool,
      type: defaultType,
      filters: input.filters as never,
    };
  }
  throw new SecurityCenterValidationError(
    "query, queryId, or tool is required",
  );
}

/**
 * Vulnerability, event, mobile, and user analysis (`POST /analysis`).
 *
 * Prefer {@link SecurityCenter.analysis} over constructing this directly.
 */
export class AnalysisResource {
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
   * Run vulnerability analysis (`POST /analysis`, `type=vuln`).
   *
   * Accepts a saved `query` / `queryId` or a flattened `tool` + `filters`.
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
   * const page = await securityCenter.analysis.vulns({
   *   tool: "vulndetails",
   *   sourceType: "cumulative",
   *   filters: [{ filterName: "severity", operator: "=", value: "3,4" }],
   * });
   * ```
   *
   * @tags allow-net
   */
  async vulns(input: VulnAnalysisInput): Promise<AnalysisResponse> {
    const sourceType = input.sourceType ?? "cumulative";
    if (sourceType === "individual" && input.scanID === undefined) {
      throw new SecurityCenterValidationError(
        "scanID is required when sourceType is individual",
      );
    }
    const body: VulnAnalysisRequest = {
      type: "vuln",
      query: nestQuery(input, "vuln"),
      sourceType,
      sortDir: input.sortDir,
      sortField: input.sortField,
      startOffset: input.startOffset ?? 0,
      endOffset: input.endOffset ?? 50,
      wasVuln: input.wasVuln,
      scanID: input.scanID,
      view: input.view,
    };
    return await this.#http.request<AnalysisResponse>({
      method: "POST",
      path: "/analysis",
      body,
    });
  }

  /**
   * Run event / LCE analysis (`POST /analysis`, `type=event`).
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
   * const page = await securityCenter.analysis.events({
   *   tool: "sumip",
   *   sourceType: "lce",
   * });
   * ```
   *
   * @tags allow-net
   */
  async events(input: EventAnalysisInput): Promise<AnalysisResponse> {
    const body: EventAnalysisRequest = {
      type: "event",
      query: nestQuery(input, "lce"),
      sourceType: input.sourceType ?? "lce",
      sortDir: input.sortDir,
      sortField: input.sortField,
      startOffset: input.startOffset,
      endOffset: input.endOffset,
      lceID: input.lceID,
      view: input.view,
    };
    return await this.#http.request<AnalysisResponse>({
      method: "POST",
      path: "/analysis",
      body,
    });
  }

  /**
   * Run mobile analysis (`POST /analysis`, `type=mobile`).
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
   * const page = await securityCenter.analysis.mobile({
   *   tool: "vulndetails",
   * });
   * ```
   *
   * @tags allow-net
   */
  async mobile(input: MobileAnalysisInput): Promise<AnalysisResponse> {
    const body: MobileAnalysisRequest = {
      type: "mobile",
      query: nestQuery(input, "mobile"),
      sourceType: "mobile",
      sortDir: input.sortDir,
      sortField: input.sortField,
      startOffset: input.startOffset ?? 0,
      endOffset: input.endOffset ?? 50,
    };
    return await this.#http.request<AnalysisResponse>({
      method: "POST",
      path: "/analysis",
      body,
    });
  }

  /**
   * Run user analysis (`POST /analysis`, `type=user`).
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
   * const page = await securityCenter.analysis.users({
   *   query: { tool: "listusers", type: "user" },
   * });
   * ```
   *
   * @tags allow-net
   */
  async users(body: UserAnalysisRequest): Promise<AnalysisResponse> {
    return await this.#http.request<AnalysisResponse>({
      method: "POST",
      path: "/analysis",
      body: { ...body, type: "user" },
    });
  }

  /**
   * Walk vulnerability analysis pages until `endOffset` or the record count.
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
   * const all = await securityCenter.analysis.vulnsAll({
   *   tool: "sumip",
   *   filters: [{ filterName: "severity", operator: "=", value: "4" }],
   * });
   * ```
   *
   * @tags allow-net
   */
  async vulnsAll(
    input: VulnAnalysisInput,
    pageSize = 1000,
  ): Promise<AnalysisResponse> {
    const results: NonNullable<AnalysisResponse["results"]> = [];
    let startOffset = input.startOffset ?? 0;
    const hardStop = input.endOffset;
    let totalRecords = Number.POSITIVE_INFINITY;

    while (startOffset < totalRecords) {
      const endOffset = hardStop === undefined
        ? startOffset + pageSize
        : Math.min(startOffset + pageSize, hardStop);
      if (endOffset <= startOffset) break;
      const page = await this.vulns({
        ...input,
        startOffset,
        endOffset,
      });
      results.push(...(page.results ?? []));
      const total = Number(page.totalRecords ?? results.length);
      totalRecords = Number.isFinite(total) ? total : results.length;
      if (!page.results?.length) break;
      startOffset = endOffset;
      if (hardStop !== undefined && startOffset >= hardStop) break;
    }

    return {
      totalRecords: String(totalRecords),
      returnedRecords: results.length,
      startOffset: String(input.startOffset ?? 0),
      endOffset: String(startOffset),
      results,
    };
  }

  /**
   * Download an analysis as raw bytes (`POST /analysis/download`).
   * User analysis cannot be downloaded.
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
   * const csv = await securityCenter.analysis.download({
   *   type: "vuln",
   *   query: { tool: "vulndetails", type: "vuln" },
   *   sourceType: "cumulative",
   * });
   * ```
   *
   * @tags allow-net
   */
  async download(body: AnalysisDownloadRequest): Promise<Uint8Array> {
    if ((body.type as string) === "user") {
      throw new SecurityCenterValidationError(
        "User analysis cannot be downloaded",
      );
    }
    return await this.#http.request<Uint8Array>({
      method: "POST",
      path: "/analysis/download",
      body,
      raw: true,
    });
  }
}
