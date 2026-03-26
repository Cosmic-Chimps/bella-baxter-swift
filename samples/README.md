# Bella Baxter Swift SDK — Samples

These samples demonstrate five ways to use the Bella Baxter Swift SDK (`BellaBaxterSwift`) in real Swift applications. Run them all with the automated test script:

```bash
./test-samples.sh bax-your-api-key-here
```

---

## Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Swift | 6.0+ | `xcode-select --install` or [swift.org](https://swift.org/download/) |
| Bella CLI | latest | [Installation guide](https://docs.bellabaxter.io/cli) |

Log in once before running samples:

```bash
bella login --api-key bax-your-api-key --url https://your-instance.example.com
```

---

## Samples

| # | Name | Pattern | Uses SDK? |
|---|------|---------|-----------|
| [01](#01-dotenv-file) | `01-dotenv-file` | Read from `.env` file written by `bella secrets get` | No |
| [02](#02-process-inject) | `02-process-inject` | Read from env vars injected by `bella run` | No |
| [03](#03-swift-cli) | `03-swift-cli` | Pull secrets at runtime via the SDK | Yes |
| [04](#04-ios-app) | `04-ios-app` | iOS / SwiftUI integration (documentation sample) | Yes |
| [05](#05-typed-secrets) | `05-typed-secrets` | Typed, validated secrets via `AppSecrets` | Yes |

---

## Decision tree

```
Do you control the launch command?
├── YES — use bella run (no SDK in your binary)
│   ├── One-shot script or CLI → 01-dotenv-file
│   └── Long-running process   → 02-process-inject
└── NO — SDK must run inside the binary
    ├── Simple key→value map  → 03-swift-cli
    └── Typed + validated     → 05-typed-secrets
```

---

## 01-dotenv-file

**Pattern:** `bella secrets get` writes a `.env` file once; your Swift app reads it on startup. No network calls at runtime.

```bash
bella secrets get -o .env
swift run
```

Best for: CI/CD pipelines, scripts, or apps that restart infrequently.

---

## 02-process-inject

**Pattern:** `bella run` injects all project secrets as environment variables before launching your process. Your code reads them with `ProcessInfo`.

```bash
bella run -- swift run
```

Best for: microservices or CLI tools where you control the launch command and want zero SDK dependency in your binary.

---

## 03-swift-cli

**Pattern:** The SDK (`BellaBaxterSwift`) pulls secrets directly from the Bella Baxter API at startup using HMAC-signed requests. Project and environment are auto-discovered from the API key.

```bash
BELLA_BAXTER_URL=https://your-instance.example.com \
BELLA_API_KEY=bax-your-api-key \
swift run
```

Best for: binaries that run without a wrapper, containers, or serverless functions.

---

## 04-ios-app

**Pattern:** SwiftUI iOS application that loads secrets via the SDK. This is a **documentation sample** showing the integration pattern — it cannot be run as a macOS CLI executable.

Open in Xcode and run on a simulator or device. Set your API key via the Xcode scheme environment variables or an `.xcconfig` file.

Best for: iOS apps that need secrets at runtime without bundling them in the binary.

---

## 05-typed-secrets

**Pattern:** `AppSecrets` provides a strongly-typed interface over `ProcessInfo.processInfo.environment`. Secret values are validated and converted to the correct Swift types at startup, not at the call site.

```bash
bella run -- swift run
```

```swift
// ✅ Type-safe access — no raw string parsing in application code
let port: Int    = AppSecrets.shared.port           // Int, not String
let enabled: Bool = AppSecrets.shared.enableFeatures // Bool
let id: UUID     = AppSecrets.shared.appId           // UUID
let cfg          = AppSecrets.shared.appConfig        // Decoded JSON struct
```

Best for: applications that want compile-time safety and early validation of required secrets.
