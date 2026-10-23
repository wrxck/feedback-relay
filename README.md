# feedback-relay

Add "report a bug" and "suggest an idea" to any app. Each report becomes a GitHub issue in your repository.

```text
app ──► your server ──► GitHub issue (labels: feedback, bug|idea, needs-triage)
         │
         ├─ proves the request came from your genuine app (Apple App Attest built in)
         ├─ scrubs personal data from the text
         ├─ validates the request against a strict schema
         └─ rate limits per IP and per device key
```

- **Your server, your repository.** There is no hosted service. The reporter never needs a GitHub account.
- **No personal data by design.** The request schema has no field for a user id or a device id. The server removes emails, phone numbers, long digit runs and IP addresses from the text.
- **Pluggable app proof.** Apple App Attest ships in the box. You can add Play Integrity, a captcha or anything else through one interface.
- **Small.** One runtime dependency (`cborg`, a CBOR decoder). Node 20 or later. ESM only. No UI.

## Contents

- [Quick start](#quick-start)
- [Create the GitHub App](#create-the-github-app)
- [App Attest on iOS](#app-attest-on-ios)
- [Run more than one server process](#run-more-than-one-server-process)
- [Security model](#security-model)
- [Add another verifier](#add-another-verifier)
- [Triage with an agent](#triage-with-an-agent)
- [API reference](#api-reference)
- [Wire protocol](#wire-protocol)

## Quick start

Install the package on the server and in the app:

```sh
npm install @matthesketh/feedback-relay
```

### Server (Express)

```ts
import express from 'express';
import {
  createAppleAppAttestVerifier,
  createFeedbackRelay,
  createGitHubIssueSink,
  expressHandlers,
} from '@matthesketh/feedback-relay/server';

const relay = createFeedbackRelay({
  verifier: createAppleAppAttestVerifier({
    teamId: 'ABCDE12345', // your Apple developer team id
    bundleId: 'com.example.app',
  }),
  issues: createGitHubIssueSink({
    appId: process.env.GITHUB_APP_ID!,
    privateKey: process.env.GITHUB_APP_PRIVATE_KEY!, // the .pem contents
    installationId: process.env.GITHUB_APP_INSTALLATION_ID!,
    owner: 'your-name',
    repo: 'your-app',
  }),
  onEvent: (event) => console.log('feedback', event), // rejection reasons appear here only
});

const app = express();
app.set('trust proxy', 1); // match your proxy setup, or every client shares one IP
const feedback = expressHandlers(relay);
app.post('/feedback/challenge', feedback.challenge);
app.post('/feedback', feedback.feedback);
app.listen(3000);
```

The adapter does not import Express. It accepts any object with the shape of a Node `IncomingMessage` and `ServerResponse`, so it also works with plain `node:http`. For another framework, call the core directly:

```ts
const response = await relay.handleFeedback({ method: 'POST', body: rawBodyString, ip });
// response is { status, headers, body } — copy it onto your framework's response
```

### Client (the app)

```ts
import { createAppAttestProvider, createFeedbackClient } from '@matthesketh/feedback-relay/client';

const feedback = createFeedbackClient({
  endpoint: 'https://api.example.com/feedback',
  attest: createAppAttestProvider({ bridge, storage }), // see "App Attest on iOS"
  context: { appVersion: '1.2.0', build: '45', os: 'iOS', osVersion: '18.1', locale: 'en-GB' },
});

const result = await feedback.submit({
  type: 'bug',
  text: 'The timer stops when I lock the phone',
  screen: 'Timer',
});
if (!result.ok) showError(result.error, result.retryAfterSeconds);
```

`submit` never throws for an expected failure. It returns `{ ok: false, error, message }`, where `error` is one of `bad_request`, `rate_limited`, `bad_challenge`, `unverified`, `unknown_key`, `too_large`, `upstream_failed`, `network` or `attest_failed`.

### What the issue looks like

Title: `[Bug] The timer stops when I lock the phone`

````md
### Report

```text
The timer stops when I lock the phone
```

### Context

| Field       | Value              |
| ----------- | ------------------ |
| Type        | `bug`              |
| Screen      | `Timer`            |
| App version | `1.2.0`            |
| ...         | ...                |
| App proof   | `apple-app-attest` |
````

## Create the GitHub App

A GitHub App, not a personal token, opens the issues. The app can touch only the repositories you install it on, and only with the one permission you give it.

1. Open **GitHub → Settings → Developer settings → GitHub Apps → New GitHub App**. For an organisation, use the organisation's settings.
2. Set a name and a homepage URL. Clear **Webhook → Active**; the relay needs no webhook.
3. Under **Repository permissions**, set **Issues** to **Read and write**. Leave every other permission at **No access**. (GitHub adds **Metadata: Read-only** to every app automatically.)
4. Set **Where can this GitHub App be installed?** to **Only on this account**.
5. Create the app. Write down the **App ID**.
6. Under **Private keys**, generate a key. Store the downloaded `.pem` file as a server secret.
7. Select **Install App**, then install it on **only** the repository that receives feedback.
8. The installation id is the number at the end of the installation page URL (`.../settings/installations/<id>`).

The relay signs a short-lived RS256 JWT with the private key, exchanges it for an installation token, and caches that token until five minutes before it expires.

## App Attest on iOS

### How it works

App Attest lets your server check that a request comes from your genuine app on a genuine Apple device.

1. **Once per install**, the app makes a key pair in the Secure Enclave (`generateKey`). Apple then signs a certificate for that key (`attestKey`). The certificate says "this key belongs to app `TEAMID.bundle.id` on a real device". The server checks the certificate chain up to Apple's App Attestation root CA and stores the public key.
2. **For each report**, the server issues a random, single-use challenge that expires after two minutes. The app signs the challenge together with a hash of the exact report (`generateAssertion`). The server checks the signature with the stored key and checks that the signature counter went up, so a captured request cannot be sent again.

The server runs every check in Apple's [Validating apps that connect to your server](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server):

| Check                                                                               | Attestation | Assertion |
| ----------------------------------------------------------------------------------- | ----------- | --------- |
| Format is `apple-appattest`                                                         | yes         |           |
| Certificate chain ends at Apple's pinned root, every certificate in date            | yes         |           |
| Nonce extension `1.2.840.113635.100.8.2` equals `SHA256(authData ‖ clientDataHash)` | yes         |           |
| Key id equals `SHA256` of the leaf public key                                       | yes         |           |
| RP id hash equals `SHA256("<teamId>.<bundleId>")`                                   | yes         | yes       |
| Counter is 0                                                                        | yes         |           |
| AAGUID is `appattest` (production) or `appattestdevelop` (development)              | yes         |           |
| Credential id equals the key id                                                     | yes         |           |
| ECDSA P-256 signature over `SHA256(authenticatorData ‖ SHA256(clientData))`         |             | yes       |
| Counter is higher than the stored counter (compare and set)                         |             | yes       |
| Client data holds a live, unused challenge and the hash of this exact report        |             | yes       |

### What the iOS app must do

1. In Xcode, add the **App Attest** capability. This adds the `com.apple.developer.devicecheck.appattest-environment` entitlement. Apple uses the production environment for TestFlight and App Store builds whatever the entitlement says, so set the server's `environment` to `'production'` (the default) for those builds and to `'development'` only for builds you run from Xcode.
2. Expose four calls to your JavaScript. With Capacitor, a small plugin does it:

```swift
import Capacitor
import DeviceCheck

@objc(AppAttestPlugin)
public class AppAttestPlugin: CAPPlugin, CAPBridgedPlugin {
    public let identifier = "AppAttestPlugin"
    public let jsName = "AppAttest"
    public let pluginMethods: [CAPPluginMethod] = [
        CAPPluginMethod(name: "isSupported", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "generateKey", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "attestKey", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "generateAssertion", returnType: CAPPluginReturnPromise),
    ]
    private let service = DCAppAttestService.shared

    @objc func isSupported(_ call: CAPPluginCall) {
        call.resolve(["value": service.isSupported])
    }

    @objc func generateKey(_ call: CAPPluginCall) {
        service.generateKey { keyId, error in
            guard let keyId else { return call.reject(error?.localizedDescription ?? "generateKey failed") }
            call.resolve(["value": keyId])
        }
    }

    @objc func attestKey(_ call: CAPPluginCall) {
        guard let keyId = call.getString("keyId"),
              let hash = call.getString("clientDataHash").flatMap({ Data(base64Encoded: $0) })
        else { return call.reject("keyId and clientDataHash are required") }
        service.attestKey(keyId, clientDataHash: hash) { attestation, error in
            guard let attestation else { return call.reject(error?.localizedDescription ?? "attestKey failed") }
            call.resolve(["value": attestation.base64EncodedString()])
        }
    }

    @objc func generateAssertion(_ call: CAPPluginCall) {
        guard let keyId = call.getString("keyId"),
              let hash = call.getString("clientDataHash").flatMap({ Data(base64Encoded: $0) })
        else { return call.reject("keyId and clientDataHash are required") }
        service.generateAssertion(keyId, clientDataHash: hash) { assertion, error in
            guard let assertion else { return call.reject(error?.localizedDescription ?? "generateAssertion failed") }
            call.resolve(["value": assertion.base64EncodedString()])
        }
    }
}
```

3. Wrap the plugin as an `AppAttestBridge` and give the provider somewhere to keep the key id:

```ts
import { registerPlugin } from '@capacitor/core';
import type { AppAttestBridge, AppAttestStorage } from '@matthesketh/feedback-relay/client';

type Value<T> = Promise<{ value: T }>;
const AppAttest = registerPlugin<{
  isSupported(): Value<boolean>;
  generateKey(): Value<string>;
  attestKey(args: { keyId: string; clientDataHash: string }): Value<string>;
  generateAssertion(args: { keyId: string; clientDataHash: string }): Value<string>;
}>('AppAttest');

export const bridge: AppAttestBridge = {
  isSupported: async () => (await AppAttest.isSupported()).value,
  generateKey: async () => (await AppAttest.generateKey()).value,
  attestKey: async (keyId, clientDataHash) =>
    (await AppAttest.attestKey({ keyId, clientDataHash })).value,
  generateAssertion: async (keyId, clientDataHash) =>
    (await AppAttest.generateAssertion({ keyId, clientDataHash })).value,
};

// the key id is not a secret, but keep it in the keychain if you can; any persistent store works
export const storage: AppAttestStorage = {
  load: async () => JSON.parse(localStorage.getItem('feedback-attest') ?? 'null'),
  save: async (state) => localStorage.setItem('feedback-attest', JSON.stringify(state)),
};
```

A fully native Swift app does the same steps without a bridge: fetch a challenge, build the client data string (see [Wire protocol](#wire-protocol)), hash it with `SHA256`, and call `attestKey` (first time only) and `generateAssertion` with that hash.

The provider handles the key life cycle. It makes a key on first use, sends the attestation until the server accepts one, and makes a new key if Apple refuses an attestation or the server answers `unknown_key`.

### Keep keys in a database

The default `KeyStore` lives in memory, so a restart forgets every key. Each device then attests again, which works but costs a call to Apple. For production, back it with your database. The `advanceCounter` call must be an atomic compare-and-set; that is what stops a replay.

```ts
import type { KeyStore } from '@matthesketh/feedback-relay/server';

// create table app_attest_keys (
//   key_id text primary key, public_key text not null, counter bigint not null,
//   receipt bytea not null, created_at timestamptz not null default now());
export const keyStore: KeyStore = {
  async get(keyId) {
    const { rows } = await pool.query('select * from app_attest_keys where key_id = $1', [keyId]);
    const row = rows[0];
    return (
      row && {
        publicKey: row.public_key,
        counter: Number(row.counter),
        receipt: row.receipt,
        createdAt: row.created_at.getTime(),
      }
    );
  },
  async create(keyId, key) {
    const result = await pool.query(
      'insert into app_attest_keys (key_id, public_key, counter, receipt) values ($1, $2, $3, $4) on conflict do nothing',
      [keyId, key.publicKey, key.counter, key.receipt],
    );
    return result.rowCount === 1;
  },
  async advanceCounter(keyId, next) {
    const result = await pool.query(
      'update app_attest_keys set counter = $2 where key_id = $1 and counter < $2',
      [keyId, next],
    );
    return result.rowCount === 1;
  },
};
```

Pass it as `createAppleAppAttestVerifier({ teamId, bundleId, keyStore })`.

## Run more than one server process

Three stores default to process memory: the challenge store, the rate limiters and the App Attest key store. With more than one process or container, give all three a shared backing (Postgres, Redis or similar):

| Interface                 | Must guarantee                                                                                                       |
| ------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| `ChallengeStore.take`     | Returns `true` at most once per challenge, and only before it expires. Use `DELETE ... RETURNING` or Redis `GETDEL`. |
| `RateLimiter.hit`         | Counts across all processes. A Redis `INCR` with `EXPIRE` is enough.                                                 |
| `KeyStore.advanceCounter` | Atomic compare-and-set, as above.                                                                                    |

## Security model

What the relay guarantees:

- **The request came from your app on a real Apple device**, unless that device is compromised (see limits). A script, an emulator or a modified copy of your app cannot produce a valid attestation.
- **The report was not changed in transit or replayed.** The signature covers a hash of the exact report and a single-use challenge, and the counter must go up.
- **One device cannot flood you.** Each key gets 10 reports per hour and each IP gets 30 requests per hour per route, by default.
- **GitHub sees no identifier.** The schema rejects every field it does not know, so an app cannot send a user id or a device id by mistake. The App Attest key id is used for rate limiting only and never reaches the issue.
- **The issue cannot be used to attack the people who triage it.** The report text sits inside a code fence that is longer than any backtick run in the text. So `@mentions` notify nobody, links and images do not render (no tracking pixels), and HTML stays inert. Control characters, zero-width characters and bidi overrides are removed. The title has its `@` signs replaced with a look-alike that does not mention anyone.
- **Probing teaches an attacker nothing.** A failed proof answers `401 app proof was not accepted`. The real reason goes only to your `onEvent` hook.

The limits:

- **A jailbroken or compromised device can defeat App Attest.** An attacker with such a device can sign requests for your app. The per-key and per-IP rate limits still apply, and each new key costs them a fresh attestation from Apple.
- **PII scrubbing is best effort.** It catches the common shapes: emails, phone numbers, card numbers and other runs of seven or more digits, IPv4 and IPv6 addresses. It cannot catch a name or a street address. Tell users not to include personal details, and treat the repository as if it may hold some. Use a private repository unless you are sure.
- **The relay does not check the App Attest receipt or Apple's fraud metric.** It stores the receipt so you can add that check later.
- **Rate limits in memory reset on restart.** See [Run more than one server process](#run-more-than-one-server-process).
- **Your proxy decides the client IP.** If `trust proxy` (or your equivalent) is wrong, every client shares one IP bucket, or a client can choose its own.

## Add another verifier

A verifier is one object on the server. A matching `AttestProvider` produces its proof on the client.

```ts
// server
export interface Verifier {
  readonly name: string; // shown in the issue as "App proof"
  verify(input: {
    proof: Record<string, unknown>; // whatever your AttestProvider returned
    clientData: Uint8Array; // the bytes your proof must cover
    ip: string | undefined;
  }): Promise<
    | { ok: true; subject: string }
    | { ok: false; code: 'unverified' | 'unknown_key'; reason: string }
  >;
}

// client
export interface AttestProvider {
  readonly name: string;
  prove(input: {
    clientData: string;
    clientDataHash: Uint8Array;
  }): Promise<Record<string, unknown>>;
  accepted?(): Promise<void>;
  rejected?(error: string): Promise<void>;
}
```

`subject` is the key for the per-client rate limit, so make it stable per client (a key id, a hashed account id, or the IP).

**Google Play Integrity.** On Android, request a standard integrity token with `requestHash` set to `base64url(clientDataHash)`. On the server, decode the token through Google's `decodeIntegrityToken` API. Check `requestDetails.requestHash`, `appIntegrity.appRecognitionVerdict === 'PLAY_RECOGNIZED'`, the package name and the device verdict. Use a hash of the token's device or app instance details as the `subject`.

**A captcha (for a web form).** Use the hash as the captcha action or data field if the provider supports one. Verify the token with the provider's siteverify API and use the IP as the `subject`:

```ts
const turnstile: Verifier = {
  name: 'turnstile',
  async verify({ proof, ip }) {
    const form = new URLSearchParams({
      secret: process.env.TURNSTILE_SECRET!,
      response: String(proof.token ?? ''),
    });
    if (ip) form.set('remoteip', ip);
    const result = await (
      await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
        method: 'POST',
        body: form,
      })
    ).json();
    return result.success
      ? { ok: true, subject: ip ?? 'unknown' }
      : { ok: false, code: 'unverified', reason: 'captcha failed' };
  },
};
```

A captcha does not bind the token to the report body the way App Attest does. It proves a human was present, not that your app sent the request.

## Triage with an agent

Every issue carries three labels: `feedback`, `bug` or `idea`, and `needs-triage`. An agent (or a person) can work from that queue:

```sh
gh issue list --label needs-triage --label feedback --json number,title,body,labels
```

A typical loop: read the issue, reproduce or assess it, add a priority or area label, link a duplicate or close it, then remove `needs-triage`. The issue footer says the text is untrusted input. An agent that reads it should treat it as data, never as instructions: the report is a stranger's text.

GitHub creates a label the first time an issue uses it. Create the three labels in advance if you want to choose their colours.

## API reference

### `@matthesketh/feedback-relay/server`

| Export                         | Signature                                                                                                                     |
| ------------------------------ | ----------------------------------------------------------------------------------------------------------------------------- |
| `createFeedbackRelay`          | `(options: FeedbackRelayOptions) => { handleChallenge(req), handleFeedback(req) }`, each `Promise<{ status, headers, body }>` |
| `expressHandlers`              | `(relay, { maxBodyBytes? }) => { challenge, feedback }`, each `(req, res, next?) => Promise<void>`                            |
| `createAppleAppAttestVerifier` | `({ teamId, bundleId, environment?, keyStore?, rootPem?, now? }) => Verifier`                                                 |
| `createGitHubIssueSink`        | `({ appId, privateKey, installationId, owner, repo, baseUrl?, fetch?, now? }) => IssueSink`                                   |
| `createMemoryKeyStore`         | `() => KeyStore`                                                                                                              |
| `createMemoryChallengeStore`   | `({ maxEntries? }) => ChallengeStore`                                                                                         |
| `createMemoryRateLimiter`      | `({ max, windowMs, maxKeys? }) => RateLimiter`                                                                                |
| `buildIssue`                   | `(payload, { verifierName, extraLabels?, titleLength? }) => { title, body, labels }`                                          |
| `scrubPersonalData`            | `(text: string) => string`                                                                                                    |

`FeedbackRelayOptions`:

| Option           | Default     | Meaning                                                               |
| ---------------- | ----------- | --------------------------------------------------------------------- |
| `verifier`       | required    | The app proof check.                                                  |
| `issues`         | required    | Where reports go; `createGitHubIssueSink` or your own `IssueSink`.    |
| `challengeStore` | in memory   | Single-use challenges.                                                |
| `challengeTtlMs` | `120000`    | How long a challenge lives.                                           |
| `ipLimiter`      | 30 per hour | Counted per IP, separately for each route.                            |
| `subjectLimiter` | 10 per hour | Counted per verified subject (the App Attest key).                    |
| `maxBodyBytes`   | `65536`     | Larger bodies get `413`.                                              |
| `maxTextLength`  | `4000`      | Longer text gets `400`. Empty text gets `400`.                        |
| `extraLabels`    | none        | Added after `feedback`, the type and `needs-triage`.                  |
| `onEvent`        | none        | Receives `created`, `rejected` (with the reason) and `failed` events. |

### `@matthesketh/feedback-relay/client`

| Export                    | Signature                                                                         |
| ------------------------- | --------------------------------------------------------------------------------- |
| `createFeedbackClient`    | `({ endpoint, attest, context?, fetch? }) => { submit({ type, text, screen? }) }` |
| `createAppAttestProvider` | `({ bridge: AppAttestBridge, storage: AppAttestStorage }) => AttestProvider`      |

The client uses only `fetch` and Web Crypto, so it runs in a browser, a WebView, React Native with a Web Crypto polyfill, or Node 20+.

### `@matthesketh/feedback-relay`

The shared types (`FeedbackPayload`, `FeedbackContext`, `FeedbackEnvelope`, `ErrorCode` and others) and `clientDataFor`.

## Wire protocol

1. `POST {endpoint}/challenge` answers `200 { "challenge": "<43 base64url chars>", "expiresAt": <ms> }`.
2. The client serialises the report to a JSON string, `payload`:
   `{ "type": "bug" | "idea", "text": "...", "screen"?: "...", "context"?: { "appVersion", "build", "os", "osVersion", "locale" } }`
3. The client builds the client data string and signs it:
   `clientData = "feedback-relay/v1|" + challenge + "|" + base64url(SHA256(payload))`
4. `POST {endpoint}` with `{ "payload": "<the JSON string>", "challenge": "...", "proof": { ... } }`.
   For App Attest, `proof` is `{ "keyId", "assertion", "attestation"? }`, all base64.
5. The server answers `201 { "ok": true }`, or `{ "ok": false, "error", "message" }` with `400`, `401`, `405`, `413`, `429` (with `Retry-After`) or `502`.

The payload travels as a string so both sides hash the same bytes. No JSON canonicalisation is needed.

## Development

```sh
npm test            # vitest
npm run test:coverage
npm run lint        # eslint and prettier --check
npm run build       # tsc to dist/
```

The App Attest tests build a fake certificate chain (root, intermediate, leaf with the nonce extension) at run time, then run each check against a genuine object and a broken one.

## Licence

MIT © Matt Hesketh
