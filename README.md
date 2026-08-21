# @hmalinchock/security-center

[![JSR](https://jsr.io/badges/@hmalinchock/security-center)](https://jsr.io/@hmalinchock/security-center)
[![JSR Score](https://jsr.io/badges/@hmalinchock/security-center/score)](https://jsr.io/@hmalinchock/security-center)

Typed Deno client for the **Tenable Security Center** (on-prem / data-center)
REST API. Request and response shapes are TypeScript types.

API reference:
[Tenable Security Center API](https://docs.tenable.com/security-center/api/index.htm)

## Install

```ts
import { SecurityCenter } from "jsr:@hmalinchock/security-center";
```

Or pin a version:

```json
{
  "imports": {
    "@hmalinchock/security-center": "jsr:@hmalinchock/security-center@^1.0.0"
  }
}
```

## Authenticate

Most endpoints accept API keys via the `x-apikey` header:

```
x-apikey: accesskey=ACCESS_KEY; secretkey=SECRET_KEY;
```

```ts
const securityCenter = new SecurityCenter({
  url: "https://sc.example.com",
  accessKey: Deno.env.get("SC_ACCESS_KEY")!,
  secretKey: Deno.env.get("SC_SECRET_KEY")!,
});
```

Session login (username / password) uses `POST /token` and sends
`X-SecurityCenter` plus cookies:

```ts
const securityCenter = new SecurityCenter({
  url: "https://sc.example.com",
  username: Deno.env.get("SC_USERNAME")!,
  password: Deno.env.get("SC_PASSWORD")!,
});
await securityCenter.login();
```

### mTLS (self-hosted / firewalled appliances)

Data-center Security Center instances often sit behind a private PKI and require
a client certificate **in addition to** API keys. Pass a combined PEM, or a
cert + key. Each field accepts PEM text or a file path.

```ts
const securityCenter = new SecurityCenter({
  url: "https://sc.internal",
  accessKey: Deno.env.get("SC_ACCESS_KEY")!,
  secretKey: Deno.env.get("SC_SECRET_KEY")!,
  pem: Deno.env.get("SC_CLIENT_PEM") ?? "./client.pem",
});
```

```ts
const securityCenter = new SecurityCenter({
  url: "https://sc.internal",
  accessKey: Deno.env.get("SC_ACCESS_KEY")!,
  secretKey: Deno.env.get("SC_SECRET_KEY")!,
  cert: "./client.crt",
  key: "./client.key",
  ca: "./corporate-ca.pem",
});
```

Call `securityCenter.close()` when you created the client this way so the
internal `Deno.HttpClient` is released.

The client certificate must be unencrypted PEM and X.509 v3 (`openssl req -x509`
with `x509_extensions`). File-path loading needs `--allow-read`.

Self-signed appliance with a prebuilt client:

```ts
const httpClient = Deno.createHttpClient({
  caCerts: [await Deno.readTextFile("./sc-ca.pem")],
});
const securityCenter = new SecurityCenter({
  url: "https://sc.internal",
  accessKey: "...",
  secretKey: "...",
  httpClient,
});
```

## Examples

List scans and launch one:

```ts
const scans = await securityCenter.scans.list({
  fields: ["id", "name", "status"],
});
await securityCenter.scans.launch(scans.usable![0].id!);
```

Vulnerability analysis (`POST /analysis`):

```ts
const page = await securityCenter.analysis.vulns({
  tool: "vulndetails",
  sourceType: "cumulative",
  startOffset: 0,
  endOffset: 50,
  filters: [{ filterName: "severity", operator: "=", value: "3,4" }],
});

const allCritical = await securityCenter.analysis.vulnsAll({
  tool: "sumip",
  filters: [{ filterName: "severity", operator: "=", value: "4" }],
});
```

Use a saved query by id:

```ts
await securityCenter.analysis.vulns({ queryId: 12, sourceType: "cumulative" });
```

Create a static asset:

```ts
await securityCenter.assets.create({
  type: "static",
  name: "lab-range",
  definedIPs: "10.0.0.0/24",
});
```

Call an endpoint this package does not wrap yet:

```ts
const feed = await securityCenter.request({
  method: "GET",
  path: "/feed",
});
```

## Resources

| Client property                  | REST prefix       | Actions                                                               |
| -------------------------------- | ----------------- | --------------------------------------------------------------------- |
| `token` / `login()` / `logout()` | `/token`          | login, logout                                                         |
| `system`                         | `/system`         | get                                                                   |
| `status`                         | `/status`         | get                                                                   |
| `currentUser`                    | `/currentUser`    | get, update, preferences, switch                                      |
| `analysis`                       | `/analysis`       | vulns, events, mobile, users, download, vulnsAll                      |
| `scans`                          | `/scan`           | list, get, create, update, delete, copy, launch                       |
| `scanResults`                    | `/scanResult`     | list, get, delete, copy, email, import, stop, pause, resume, download |
| `assets`                         | `/asset`          | list, get, create, update, delete                                     |
| `queries`                        | `/query`          | list, get, create, update, delete                                     |
| `repositories`                   | `/repository`     | list, get                                                             |
| `organizations`                  | `/organization`   | list, get                                                             |
| `plugins`                        | `/plugin`         | list, get                                                             |
| `policies`                       | `/policy`         | list, get                                                             |
| `groups`                         | `/group`          | list, get                                                             |
| `users`                          | `/user`           | list, get                                                             |
| `acceptRiskRules`                | `/acceptRiskRule` | list, create, delete                                                  |
| `recastRiskRules`                | `/recastRiskRule` | list, create, delete                                                  |

URI shape is `https://host[:port]/rest/resource[/{id}]`. GET helpers accept
`fields`, `expand`, `editable`, `usable`, and `manageable` as documented by
Tenable.

## Permissions

| When                                                     | Flags                                      |
| -------------------------------------------------------- | ------------------------------------------ |
| Any request (`list`, `login`, `analysis.vulns`, ...)     | `--allow-net` for the Security Center host |
| Constructor `pem` / `cert` / `key` / `ca` is a file path | `--allow-read`                             |
| Custom `fetch` / `httpClient` only                       | whatever that implementation needs         |

JSDoc on every public method lists the flags that method needs. Hover in the IDE
to see them.

## Errors

Constructor options and a few request combinations TypeScript cannot express
(`scanID` when `sourceType` is `"individual"`, paired diagnostic launch fields)
throw `SecurityCenterValidationError` before the HTTP call.

Successful JSON responses are unwrapped from the standard envelope (`type`,
`response`, `error_code`, `error_msg`, `warnings`, `timestamp`). A non-zero
`error_code` throws `SecurityCenterError` even when HTTP status is 200.

## Develop

```bash
export PATH="$HOME/.deno/bin:$PATH"
deno task test
deno task check
deno task doc
deno task publish:dry
```

CI runs `deno fmt --check`, lint, type check, tests, and a publish dry-run on
every push and pull request.

## Publish

GitHub Actions publishes to [JSR](https://jsr.io/@hmalinchock/security-center)
when you push a `v*` tag that matches `jsr.json` and `deno.json`:

```bash
git tag v1.0.0
git push origin v1.0.0
```

## License

MIT
