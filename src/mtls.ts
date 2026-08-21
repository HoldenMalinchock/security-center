import { SecurityCenterValidationError } from "./errors.ts";

const PEM_BLOCK =
  /-----BEGIN ([A-Z0-9 ]+)-----[\s\S]*?-----END \1-----/g;

/** True when the string already contains PEM armor instead of a file path. */
export function looksLikePem(value: string): boolean {
  return value.includes("-----BEGIN ");
}

export type PemBlock = {
  type: string;
  pem: string;
};

/** Pull every PEM block out of a bundle. */
export function extractPemBlocks(pem: string): PemBlock[] {
  const blocks: PemBlock[] = [];
  for (const match of pem.matchAll(PEM_BLOCK)) {
    const type = match[1]?.trim();
    const body = match[0]?.trim();
    if (!type || !body) continue;
    blocks.push({ type, pem: body });
  }
  return blocks;
}

export type SplitPemBundle = {
  cert: string;
  key: string;
};

/**
 * Split a combined PEM (cert + key, optionally with intermediates)
 * into the values `Deno.createHttpClient` expects.
 */
export function splitPemBundle(pem: string): SplitPemBundle {
  const blocks = extractPemBlocks(pem);
  const certs = blocks.filter((block) =>
    block.type === "CERTIFICATE" || block.type === "X509 CERTIFICATE"
  );
  const keys = blocks.filter((block) => block.type.endsWith("PRIVATE KEY"));
  if (certs.length === 0) {
    throw new SecurityCenterValidationError(
      "PEM does not contain a CERTIFICATE block",
    );
  }
  if (keys.length === 0) {
    throw new SecurityCenterValidationError(
      "PEM does not contain a PRIVATE KEY block",
    );
  }
  return {
    cert: certs.map((block) => block.pem).join("\n"),
    key: keys[0].pem,
  };
}

export type MtlsInput = {
  pem?: string;
  cert?: string;
  key?: string;
  ca?: string | string[];
};

export type MtlsMaterial = {
  cert?: string;
  key?: string;
  caCerts?: string[];
};

function readPemSource(value: string): string {
  if (looksLikePem(value)) return value;
  return Deno.readTextFileSync(value);
}

function resolveCaCerts(ca: string | string[]): string[] {
  const sources = Array.isArray(ca) ? ca : [ca];
  const certs: string[] = [];
  for (const source of sources) {
    const pem = readPemSource(source);
    const blocks = extractPemBlocks(pem);
    const caBlocks = blocks.filter((block) =>
      block.type === "CERTIFICATE" ||
      block.type === "X509 CERTIFICATE" ||
      block.type === "TRUSTED CERTIFICATE"
    );
    if (caBlocks.length > 0) {
      for (const block of caBlocks) certs.push(block.pem);
    } else {
      certs.push(pem.trim());
    }
  }
  return certs;
}

export function hasMtlsOptions(input: MtlsInput): boolean {
  return Boolean(input.pem || input.cert || input.key || input.ca);
}

/**
 * Resolve `pem`, `cert`/`key`, and optional `ca` into PEM material.
 * File paths are read synchronously; PEM strings are used as-is.
 */
export function resolveMtlsMaterial(input: MtlsInput): MtlsMaterial {
  const hasPem = Boolean(input.pem);
  const hasCert = Boolean(input.cert);
  const hasKey = Boolean(input.key);

  if (hasPem && (hasCert || hasKey)) {
    throw new SecurityCenterValidationError(
      "Use either pem or cert/key, not both",
    );
  }
  if (hasCert !== hasKey) {
    throw new SecurityCenterValidationError(
      "Both cert and key are required for mTLS",
    );
  }

  const material: MtlsMaterial = {};

  if (hasPem) {
    const split = splitPemBundle(readPemSource(input.pem!));
    material.cert = split.cert;
    material.key = split.key;
  } else if (hasCert && hasKey) {
    material.cert = readPemSource(input.cert!);
    material.key = readPemSource(input.key!);
  }

  if (input.ca !== undefined) {
    material.caCerts = resolveCaCerts(input.ca);
  }

  if (!material.cert && !material.key && !material.caCerts?.length) {
    throw new SecurityCenterValidationError(
      "mTLS requires pem, cert/key, or ca",
    );
  }

  return material;
}

/**
 * Build a Deno HTTP client that presents a client certificate.
 *
 * `Deno.createHttpClient` panics on malformed keys, so callers should pass
 * real PEM (file path or string).
 */
export function createMtlsHttpClient(material: MtlsMaterial): Deno.HttpClient {
  const options: {
    cert?: string;
    key?: string;
    caCerts?: string[];
  } = {};
  if (material.cert && material.key) {
    options.cert = material.cert;
    options.key = material.key;
  }
  if (material.caCerts?.length) options.caCerts = material.caCerts;
  return Deno.createHttpClient(options);
}
