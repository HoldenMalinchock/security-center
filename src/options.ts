import { SecurityCenterValidationError } from "./errors.ts";
import type {
  SecurityCenterOptions,
  SecurityCenterOptionsInput,
} from "./types.ts";

function present(value: string | undefined): boolean {
  return typeof value === "string" && value.length > 0;
}

/**
 * Check constructor options that TypeScript cannot express (auth pairing,
 * mTLS pairing, empty url).
 */
export function parseConstructorOptions(
  options: SecurityCenterOptions,
): SecurityCenterOptionsInput {
  if (!present(options.url)) {
    throw new SecurityCenterValidationError(
      "Invalid SecurityCenter options: url is required",
    );
  }

  const hasAccess = present(options.accessKey);
  const hasSecret = present(options.secretKey);
  if (hasAccess !== hasSecret) {
    throw new SecurityCenterValidationError(
      "Invalid SecurityCenter options: Provide both accessKey and secretKey, both username and password, or neither",
    );
  }

  const hasUser = present(options.username);
  const hasPassword = present(options.password);
  if (hasUser !== hasPassword) {
    throw new SecurityCenterValidationError(
      "Invalid SecurityCenter options: Provide both accessKey and secretKey, both username and password, or neither",
    );
  }

  if (
    options.timeoutMs !== undefined &&
    (!Number.isInteger(options.timeoutMs) || options.timeoutMs <= 0)
  ) {
    throw new SecurityCenterValidationError(
      "Invalid SecurityCenter options: timeoutMs must be a positive integer",
    );
  }

  const hasPem = present(options.pem);
  const hasCert = present(options.cert);
  const hasKey = present(options.key);
  if (hasPem && (hasCert || hasKey) || hasCert !== hasKey) {
    throw new SecurityCenterValidationError(
      "Invalid SecurityCenter options: mTLS accepts a combined pem or a cert/key pair (plus optional ca), not a mix",
    );
  }

  if (options.ca !== undefined) {
    const values = Array.isArray(options.ca) ? options.ca : [options.ca];
    if (values.length === 0 || values.some((item) => !present(item))) {
      throw new SecurityCenterValidationError(
        "Invalid SecurityCenter options: ca must be a non-empty string or array of strings",
      );
    }
  }

  return {
    url: options.url,
    accessKey: options.accessKey,
    secretKey: options.secretKey,
    username: options.username,
    password: options.password,
    timeoutMs: options.timeoutMs,
    pem: options.pem,
    cert: options.cert,
    key: options.key,
    ca: options.ca,
  };
}
