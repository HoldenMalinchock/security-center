import type { SecurityCenterHttp } from "../http.ts";
import type {
  SecurityCenterTransport,
  TokenLoginBody,
  TokenResponse,
} from "../types.ts";

/**
 * Session tokens (`/token`).
 *
 * Prefer {@link SecurityCenter.login} / {@link SecurityCenter.logout}.
 */
export class TokenResource {
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
   * Create a session token (`POST /token`) and store it for later calls.
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
   * await securityCenter.token.login({ username: "admin", password: "secret" });
   * ```
   *
   * @tags allow-net
   */
  async login(body: TokenLoginBody): Promise<TokenResponse> {
    const response = await this.#http.request<TokenResponse>({
      method: "POST",
      path: "/token",
      body,
    });
    if (response.token !== undefined) {
      this.#http.session.token = String(response.token);
    }
    return response;
  }

  /**
   * Destroy the current session token (`DELETE /token`).
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
   * await securityCenter.token.logout();
   * ```
   *
   * @tags allow-net
   */
  async logout(): Promise<unknown> {
    const response = await this.#http.request({
      method: "DELETE",
      path: "/token",
    });
    this.#http.clearSession();
    return response;
  }
}
