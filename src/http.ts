/**
 * HTTP helpers for the Tenable Security Center REST API.
 *
 * @module
 */

import { SecurityCenterError } from "./errors.ts";
import type {
  ListQuery,
  SecurityCenterEnvelope,
  SecurityCenterFetch,
} from "./types.ts";

/** HTTP methods used by the Security Center REST API. */
export type HttpMethod = "GET" | "POST" | "PATCH" | "PUT" | "DELETE";

/**
 * Options for {@link SecurityCenter.request}.
 *
 * `path` is a Security Center REST path such as `/scan` or `/scan/1`.
 * `/rest` is added automatically.
 */
export type RequestOptions = {
  /** HTTP method. */
  method: HttpMethod;
  /** REST path, with or without a `/rest` prefix. */
  path: string;
  /** Query-string fields. Boolean `true` is sent as a bare flag. */
  query?: Record<string, string | number | boolean | undefined>;
  /** JSON request body. */
  body?: unknown;
  /** When true, return raw bytes instead of parsing the SC envelope. */
  raw?: boolean;
  /** Extra headers merged into the request. */
  headers?: Record<string, string>;
};

/**
 * Session token and cookies stored after `POST /token`.
 */
export type SessionState = {
  /** Value sent as `X-SecurityCenter`. */
  token?: string;
  /** Cookie jar, including `TNS_SESSIONID`. */
  cookies: Map<string, string>;
};

export type HttpClientOptions = {
  baseUrl: string;
  fetch: SecurityCenterFetch;
  httpClient?: Deno.HttpClient;
  timeoutMs: number;
  accessKey?: string;
  secretKey?: string;
  session: SessionState;
};

/**
 * Normalize a Security Center URL to `protocol://host[:port][/prefix]`.
 *
 * Strips a trailing `/rest` so callers can pass either the appliance origin
 * or a full REST base.
 *
 * Required Deno permissions: none.
 *
 * @example Usage
 * ```ts
 * import { normalizeBaseUrl } from "@hmalinchock/security-center";
 *
 * normalizeBaseUrl("sc.internal:8443");
 * // => "https://sc.internal:8443"
 * ```
 */
export function normalizeBaseUrl(url: string): string {
  const withProtocol = /^https?:\/\//i.test(url) ? url : `https://${url}`;
  const parsed = new URL(withProtocol);
  const pathname = parsed.pathname.replace(/\/+$/, "");
  const trimmedPath = pathname === "/rest" ? "" : pathname;
  return `${parsed.protocol}//${parsed.host}${trimmedPath}`;
}

/**
 * Build a full `/rest/...` URL, encoding list filters the way SC expects.
 *
 * Boolean `true` query values are sent as empty flags (`?usable`).
 *
 * Required Deno permissions: none.
 *
 * @example Usage
 * ```ts
 * import { buildUrl } from "@hmalinchock/security-center";
 *
 * const url = buildUrl("https://sc.example.com", "/scan", { usable: true });
 * ```
 */
export function buildUrl(
  baseUrl: string,
  path: string,
  query: Record<string, string | number | boolean | undefined> = {},
): string {
  const normalizedPath = path.startsWith("/") ? path : `/${path}`;
  const restPath = normalizedPath.startsWith("/rest/") || normalizedPath === "/rest"
    ? normalizedPath
    : `/rest${normalizedPath}`;
  const target = new URL(`${baseUrl}${restPath}`);
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined) continue;
    if (typeof value === "boolean") {
      if (value) target.searchParams.set(key, "");
      continue;
    }
    target.searchParams.set(key, String(value));
  }
  return target.toString();
}

/**
 * Flatten list-query options into the primitive record {@link buildUrl} encodes.
 */
export function toQueryRecord(
  query: ListQuery & Record<string, unknown> = {},
): Record<string, string | number | boolean | undefined> {
  const record: Record<string, string | number | boolean | undefined> = {};
  if (query.fields?.length) record.fields = query.fields.join(",");
  if (query.expand?.length) record.expand = query.expand.join(",");
  if (query.editable) record.editable = "";
  if (query.usable) record.usable = "";
  if (query.manageable) record.manageable = "";
  for (const [key, value] of Object.entries(query)) {
    if (
      key === "fields" || key === "expand" || key === "editable" ||
      key === "usable" || key === "manageable"
    ) {
      continue;
    }
    if (value === undefined || value === null) continue;
    if (
      typeof value === "string" || typeof value === "number" ||
      typeof value === "boolean"
    ) {
      record[key] = value;
    } else {
      record[key] = JSON.stringify(value);
    }
  }
  return record;
}

/**
 * Parse the first `name=value` pair of a `Set-Cookie` header.
 *
 * Required Deno permissions: none.
 */
export function parseSetCookie(header: string): { name: string; value: string } | undefined {
  const firstPart = header.split(";")[0];
  const separatorIndex = firstPart.indexOf("=");
  if (separatorIndex <= 0) return undefined;
  return {
    name: firstPart.slice(0, separatorIndex).trim(),
    value: firstPart.slice(separatorIndex + 1).trim(),
  };
}

export function applySetCookies(
  cookies: Map<string, string>,
  response: Response,
): void {
  const headersWithGetSetCookie = response.headers as Headers & {
    getSetCookie?: () => string[];
  };
  const setCookies = headersWithGetSetCookie.getSetCookie?.() ??
    (response.headers.get("set-cookie")
      ? [response.headers.get("set-cookie") as string]
      : []);
  for (const header of setCookies) {
    const cookie = parseSetCookie(header);
    if (cookie) cookies.set(cookie.name, cookie.value);
  }
}

function cookieHeader(cookies: Map<string, string>): string | undefined {
  if (cookies.size === 0) return undefined;
  return [...cookies.entries()]
    .map(([name, value]) => `${name}=${value}`)
    .join("; ");
}

/**
 * Authenticated HTTP transport for Security Center.
 *
 * Prefer {@link SecurityCenter} over constructing this directly.
 */
export class SecurityCenterHttp {
  /** Normalized appliance URL with no trailing `/rest`. */
  readonly baseUrl: string;
  /** Current session token and cookie jar. */
  readonly session: SessionState;
  #fetch: SecurityCenterFetch;
  #httpClient?: Deno.HttpClient;
  #timeoutMs: number;
  #accessKey?: string;
  #secretKey?: string;

  constructor(options: HttpClientOptions) {
    this.baseUrl = options.baseUrl;
    this.session = options.session;
    this.#fetch = options.fetch;
    this.#httpClient = options.httpClient;
    this.#timeoutMs = options.timeoutMs;
    this.#accessKey = options.accessKey;
    this.#secretKey = options.secretKey;
  }

  /** Close a `Deno.HttpClient` owned by this transport. */
  closeClient(): void {
    this.#httpClient?.close();
    this.#httpClient = undefined;
  }

  /** Replace API keys used for the `x-apikey` header. */
  setApiKeys(accessKey?: string, secretKey?: string): void {
    this.#accessKey = accessKey;
    this.#secretKey = secretKey;
  }

  /** Drop the session token and cookies. */
  clearSession(): void {
    this.session.token = undefined;
    this.session.cookies.clear();
  }

  /**
   * Send one Security Center request and unwrap the envelope.
   *
   * Required Deno permissions: `--allow-net` for the Security Center host.
   * Add `--allow-read` if the client was constructed with mTLS file paths.
   */
  async request<T = unknown>(options: RequestOptions): Promise<T> {
    const url = buildUrl(this.baseUrl, options.path, options.query);
    const headers = new Headers(options.headers);
    headers.set("Accept", "application/json");

    if (this.#accessKey && this.#secretKey) {
      headers.set(
        "x-apikey",
        `accesskey=${this.#accessKey}; secretkey=${this.#secretKey};`,
      );
    }
    if (this.session.token) {
      headers.set("X-SecurityCenter", String(this.session.token));
    }
    const cookies = cookieHeader(this.session.cookies);
    if (cookies) headers.set("Cookie", cookies);

    const init: RequestInit & { client?: Deno.HttpClient } = {
      method: options.method,
      headers,
    };
    if (this.#httpClient) init.client = this.#httpClient;

    if (options.body !== undefined) {
      headers.set("Content-Type", "application/json");
      init.body = JSON.stringify(options.body);
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.#timeoutMs);
    init.signal = controller.signal;

    let response: Response;
    try {
      response = await this.#fetch(url, init);
    } catch (cause) {
      throw new SecurityCenterError({
        message: `Request to ${options.path} failed: ${
          cause instanceof Error ? cause.message : String(cause)
        }`,
        status: 0,
        body: cause,
      });
    } finally {
      clearTimeout(timeout);
    }

    applySetCookies(this.session.cookies, response);

    if (options.raw) {
      if (!response.ok) {
        const text = await response.text();
        throw new SecurityCenterError({
          message: `Security Center returned HTTP ${response.status}`,
          status: response.status,
          body: text,
        });
      }
      return new Uint8Array(await response.arrayBuffer()) as T;
    }

    const text = await response.text();
    let parsed: unknown = text;
    if (text.length > 0) {
      try {
        parsed = JSON.parse(text);
      } catch {
        if (!response.ok) {
          throw new SecurityCenterError({
            message: `Security Center returned HTTP ${response.status}`,
            status: response.status,
            body: text,
          });
        }
        return text as T;
      }
    }

    if (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)) {
      const envelope = parsed as SecurityCenterEnvelope;
      const errorCode = Number(envelope.error_code ?? 0);
      if (!response.ok || errorCode !== 0) {
        throw new SecurityCenterError({
          message: envelope.error_msg ||
            `Security Center returned error_code ${errorCode}`,
          status: response.status,
          errorCode,
          errorMessage: envelope.error_msg ?? "",
          warnings: envelope.warnings ?? [],
          body: envelope,
        });
      }
      return envelope.response as T;
    }

    if (!response.ok) {
      throw new SecurityCenterError({
        message: `Security Center returned HTTP ${response.status}`,
        status: response.status,
        body: parsed,
      });
    }

    return parsed as T;
  }
}
