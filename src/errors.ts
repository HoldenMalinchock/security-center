/**
 * Errors thrown by the Security Center client.
 *
 * @module
 */

/** Envelope or HTTP failure from a Tenable Security Center request. */
export class SecurityCenterError extends Error {
  /** HTTP status. `0` when the request never reached the server. */
  readonly status: number;
  /** Security Center `error_code`. `-1` when the envelope had none. */
  readonly errorCode: number;
  /** Security Center `error_msg`, or a client-generated fallback. */
  readonly errorMessage: string;
  /** Envelope `warnings` array when present. */
  readonly warnings: unknown[];
  /** Raw response body or thrown cause. */
  readonly body: unknown;

  /**
   * Create an error from an HTTP or envelope failure.
   *
   * Required Deno permissions: none.
   *
   * @param options.status HTTP status, or `0` for a transport failure.
   * @param options.errorCode Security Center `error_code`.
   */
  constructor(options: {
    message: string;
    status: number;
    errorCode?: number;
    errorMessage?: string;
    warnings?: unknown[];
    body?: unknown;
  }) {
    super(options.message);
    this.name = "SecurityCenterError";
    this.status = options.status;
    this.errorCode = options.errorCode ?? -1;
    this.errorMessage = options.errorMessage ?? options.message;
    this.warnings = options.warnings ?? [];
    this.body = options.body;
  }
}

/** Constructor options or a request helper failed a client-side check. */
export class SecurityCenterValidationError extends Error {
  /**
   * Create an error for invalid constructor options or request input.
   *
   * Required Deno permissions: none.
   *
   * @param message Human-readable validation summary.
   */
  constructor(message: string) {
    super(message);
    this.name = "SecurityCenterValidationError";
  }
}
