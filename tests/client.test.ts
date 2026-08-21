import { assertEquals, assertRejects } from "jsr:@std/assert@1.0.15";
import {
  buildUrl,
  normalizeBaseUrl,
  SecurityCenter,
  SecurityCenterError,
  SecurityCenterValidationError,
} from "../mod.ts";
import { parseSetCookie } from "../src/http.ts";
import {
  looksLikePem,
  resolveMtlsMaterial,
  splitPemBundle,
} from "../src/mtls.ts";

const fixtureDir = new URL("./fixtures/", import.meta.url);
const fixtureCertPath = new URL("client.crt", fixtureDir).pathname;
const fixtureKeyPath = new URL("client.key", fixtureDir).pathname;
const fixturePemPath = new URL("client.pem", fixtureDir).pathname;

function jsonResponse(body: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), {
    status: init.status ?? 200,
    headers: {
      "content-type": "application/json",
      ...(init.headers ?? {}),
    },
  });
}

Deno.test("normalizeBaseUrl strips /rest and trailing slashes", () => {
  assertEquals(
    normalizeBaseUrl("sc.internal:8443"),
    "https://sc.internal:8443",
  );
  assertEquals(
    normalizeBaseUrl("https://sc.example.com/rest/"),
    "https://sc.example.com",
  );
  assertEquals(
    normalizeBaseUrl("https://sc.example.com:443/sc"),
    "https://sc.example.com/sc",
  );
});

Deno.test("buildUrl prefixes /rest and encodes list filters", () => {
  const url = buildUrl("https://sc.example.com", "/scan", {
    fields: "id,name",
    usable: true,
    startTime: 1,
  });
  const parsed = new URL(url);
  assertEquals(parsed.pathname, "/rest/scan");
  assertEquals(parsed.searchParams.get("fields"), "id,name");
  assertEquals(parsed.searchParams.has("usable"), true);
  assertEquals(parsed.searchParams.get("startTime"), "1");
});

Deno.test("parseSetCookie reads the first pair", () => {
  const cookie = parseSetCookie("TNS_SESSIONID=abc123; Path=/; HttpOnly");
  assertEquals(cookie, { name: "TNS_SESSIONID", value: "abc123" });
});

function unusedFetch(): Promise<Response> {
  throw new Error("fetch should not be called");
}

function clientWithoutNetwork(): SecurityCenter {
  return new SecurityCenter({
    url: "https://sc.example.com",
    accessKey: "access",
    secretKey: "secret",
    fetch: unusedFetch,
  });
}

Deno.test("launch requires diagnostic fields together", async () => {
  const securityCenter = clientWithoutNetwork();
  await assertRejects(
    () => securityCenter.scans.launch(1, { diagnosticTarget: "10.0.0.1" }),
    SecurityCenterValidationError,
    "diagnosticTarget and diagnosticPassword must be provided together",
  );
});

Deno.test("analysis request requires scanID for individual source", async () => {
  const securityCenter = clientWithoutNetwork();
  await assertRejects(
    () =>
      securityCenter.analysis.vulns({
        query: { tool: "vulndetails" },
        sourceType: "individual",
      }),
    SecurityCenterValidationError,
    "scanID is required when sourceType is individual",
  );
});

Deno.test("analysis download rejects user type", async () => {
  const securityCenter = clientWithoutNetwork();
  await assertRejects(
    () =>
      securityCenter.analysis.download({
        type: "user",
        query: { tool: "listusers" },
      } as never),
    SecurityCenterValidationError,
    "User analysis cannot be downloaded",
  );
});

Deno.test("constructor rejects a half-specified API key pair", () => {
  try {
    new SecurityCenter({ url: "https://sc.example.com", accessKey: "only" });
    throw new Error("expected constructor to throw");
  } catch (error) {
    assertEquals(error instanceof SecurityCenterValidationError, true);
  }
});

Deno.test("API key requests set x-apikey and unwrap the envelope", async () => {
  const calls: Array<{ url: string; init?: RequestInit }> = [];
  const securityCenter = new SecurityCenter({
    url: "https://sc.example.com",
    accessKey: "access",
    secretKey: "secret",
    fetch: (input, init) => {
      calls.push({ url: String(input), init });
      return Promise.resolve(jsonResponse({
        type: "regular",
        response: {
          usable: [{ id: "2", name: "Weekly", status: "0" }],
          manageable: [],
        },
        error_code: 0,
        error_msg: "",
        warnings: [],
        timestamp: 1,
      }));
    },
  });

  const scans = await securityCenter.scans.list({ fields: ["id", "name"] });
  assertEquals(scans.usable?.[0]?.name, "Weekly");
  assertEquals(calls.length, 1);
  const headers = new Headers(calls[0].init?.headers);
  assertEquals(headers.get("x-apikey"), "accesskey=access; secretkey=secret;");
  assertEquals(new URL(calls[0].url).searchParams.get("fields"), "id,name");
});

Deno.test("login stores token and cookie for later calls", async () => {
  const headersSeen: string[] = [];
  const securityCenter = new SecurityCenter({
    url: "https://sc.example.com",
    username: "head",
    password: "s3cret",
    fetch: (input, init) => {
      const url = String(input);
      const headers = new Headers(init?.headers);
      if (url.endsWith("/rest/token") && init?.method === "POST") {
        return Promise.resolve(new Response(JSON.stringify({
          type: "regular",
          response: { token: 123456789 },
          error_code: 0,
          error_msg: "",
        }), {
          status: 200,
          headers: {
            "content-type": "application/json",
            "set-cookie": "TNS_SESSIONID=session-1; Path=/",
          },
        }));
      }
      headersSeen.push(
        `${headers.get("X-SecurityCenter")}|${headers.get("Cookie")}`,
      );
      return Promise.resolve(jsonResponse({
        type: "regular",
        response: { jobd: "Running", licenseStatus: "Valid" },
        error_code: 0,
        error_msg: "",
      }));
    },
  });

  await securityCenter.login();
  const status = await securityCenter.status.get();
  assertEquals(status.licenseStatus, "Valid");
  assertEquals(headersSeen[0], "123456789|TNS_SESSIONID=session-1");
});

Deno.test("error_code in a 200 envelope becomes SecurityCenterError", async () => {
  const securityCenter = new SecurityCenter({
    url: "https://sc.example.com",
    accessKey: "access",
    secretKey: "secret",
    fetch: () =>
      Promise.resolve(jsonResponse({
        type: "regular",
        response: {},
        error_code: 146,
        error_msg: "Invalid credentials",
      })),
  });

  await assertRejects(
    () => securityCenter.status.get(),
    SecurityCenterError,
    "Invalid credentials",
  );
});

Deno.test("analysis.vulns nests a flattened tool query", async () => {
  let body: unknown;
  const securityCenter = new SecurityCenter({
    url: "https://sc.example.com",
    accessKey: "access",
    secretKey: "secret",
    fetch: (_input, init) => {
      body = init?.body ? JSON.parse(String(init.body)) : undefined;
      return Promise.resolve(jsonResponse({
        type: "regular",
        response: {
          totalRecords: "1",
          returnedRecords: 1,
          startOffset: "0",
          endOffset: "50",
          results: [{ pluginID: "119500", ip: "10.0.0.8" }],
        },
        error_code: 0,
        error_msg: "",
      }));
    },
  });

  const analysis = await securityCenter.analysis.vulns({
    tool: "vulndetails",
    filters: [{ filterName: "severity", operator: "=", value: "4" }],
  });
  assertEquals(analysis.results?.[0]?.ip, "10.0.0.8");
  assertEquals(body, {
    type: "vuln",
    query: {
      tool: "vulndetails",
      type: "vuln",
      filters: [{ filterName: "severity", operator: "=", value: "4" }],
    },
    sourceType: "cumulative",
    startOffset: 0,
    endOffset: 50,
  });
});

Deno.test("looksLikePem distinguishes PEM text from a path", () => {
  assertEquals(looksLikePem("-----BEGIN CERTIFICATE-----\nabc"), true);
  assertEquals(looksLikePem("./client.pem"), false);
});

Deno.test("splitPemBundle reads cert and key from a combined PEM", async () => {
  const pem = await Deno.readTextFile(fixturePemPath);
  const split = splitPemBundle(pem);
  assertEquals(split.cert.includes("BEGIN CERTIFICATE"), true);
  assertEquals(split.key.includes("PRIVATE KEY"), true);
});

Deno.test("resolveMtlsMaterial loads cert/key paths", () => {
  const material = resolveMtlsMaterial({
    cert: fixtureCertPath,
    key: fixtureKeyPath,
  });
  assertEquals(material.cert?.includes("BEGIN CERTIFICATE"), true);
  assertEquals(material.key?.includes("PRIVATE KEY"), true);
});

Deno.test("constructor rejects a cert without a key", () => {
  try {
    new SecurityCenter({
      url: "https://sc.example.com",
      accessKey: "access",
      secretKey: "secret",
      cert: fixtureCertPath,
    });
    throw new Error("expected constructor to throw");
  } catch (error) {
    assertEquals(error instanceof SecurityCenterValidationError, true);
  }
});

Deno.test("constructor accepts combined pem plus API keys", () => {
  const securityCenter = new SecurityCenter({
    url: "https://sc.example.com",
    accessKey: "access",
    secretKey: "secret",
    pem: fixturePemPath,
  });
  securityCenter.close();
});

Deno.test("constructor accepts cert/key plus API keys", () => {
  const securityCenter = new SecurityCenter({
    url: "https://sc.example.com",
    accessKey: "access",
    secretKey: "secret",
    cert: fixtureCertPath,
    key: fixtureKeyPath,
    ca: fixtureCertPath,
  });
  securityCenter.close();
});

Deno.test("constructor rejects httpClient mixed with pem", () => {
  const httpClient = Deno.createHttpClient({});
  try {
    new SecurityCenter({
      url: "https://sc.example.com",
      accessKey: "access",
      secretKey: "secret",
      pem: fixturePemPath,
      httpClient,
    });
    throw new Error("expected constructor to throw");
  } catch (error) {
    assertEquals(error instanceof SecurityCenterValidationError, true);
  } finally {
    httpClient.close();
  }
});
