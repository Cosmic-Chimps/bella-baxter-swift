# Sample 05: Typed Secrets (Swift)

**Pattern:** `AppSecrets` provides a strongly-typed interface over `ProcessInfo.processInfo.environment`. Secrets are validated and converted to the correct Swift types at startup — not scattered across the codebase as raw string lookups.

---

## How it works

```
bella run -- swift run
       ↓
bella injects all secrets as env vars into the child process
       ↓
AppSecrets.shared initialises at startup:
  - PORT             →  Int       (fatalError if missing or not a valid Int)
  - ENABLE_FEATURES  →  Bool
  - APP_ID           →  UUID
  - DATABASE_URL     →  URL
  - APP_CONFIG       →  AppConfigShape (decoded from JSON)
  - EXTERNAL_API_KEY →  String (masked in logs)
  - ...
       ↓
Application code uses typed properties — no raw string parsing
```

## Setup

```bash
# Authenticate
bella login --api-key bax-xxxxxxxxxxxxxxxxxxxx

export BELLA_BAXTER_URL=http://localhost:5522   # your Bella Baxter instance

# Run with secrets injected as env vars
bella run -- swift run
```

## Why typed secrets?

| | Raw `ProcessInfo.processInfo.environment` | `AppSecrets` |
|---|---|---|
| Type safety | ❌ always `String?` | ✅ `Int`, `Bool`, `UUID`, `URL`, `Decodable` |
| Missing secret | Silent `nil` | `fatalError` at startup |
| Parse errors | Scattered `Int(str)!` | Caught at one place |
| IDE autocomplete | ❌ | ✅ |

## Example usage

```swift
import Foundation

let secrets = AppSecrets.shared

// Typed — no casting, no optional chaining
let port     = secrets.port            // Int
let enabled  = secrets.enableFeatures  // Bool
let id       = secrets.appId           // UUID
let dbUrl    = secrets.databaseUrl     // URL
let cfg      = secrets.appConfig       // AppConfigShape (decoded JSON)

print("Listening on port \(port)")
```

## Required environment variables

| Variable | Type | Description |
|---|---|---|
| `PORT` | `Int` | Server listen port |
| `DATABASE_URL` | `URL` | Database connection URL |
| `EXTERNAL_API_KEY` | `String` | External API key |
| `GLEAP_API_KEY` | `String` | Gleap API key |
| `ENABLE_FEATURES` | `Bool` | Feature flag toggle |
| `APP_ID` | `UUID` | Application UUID |
| `ConnectionStrings__Postgres` | `String` | ADO.NET-style connection string |
| `APP_CONFIG` | JSON | Decoded into `AppConfigShape` struct |

Run with `bella run -- swift run` — Bella injects all secrets automatically.

