# Sample 03: Swift CLI — Pull Secrets via SDK

**Pattern:** The `BellaBaxterSwift` SDK pulls secrets directly from the Bella Baxter API at runtime using HMAC-signed requests. Project and environment are auto-discovered from the API key.

---

## How it works

```
BELLA_API_KEY + BELLA_BAXTER_URL
       ↓
BellaClient.getKeyContext()    →  discover project + environment slug
       ↓
BellaClient.pullSecrets()      →  fetch all secrets as [String: String]
       ↓
write to .env file  OR  print KEY=VALUE lines
```

## Setup

```bash
# No bella login needed — API key is passed directly as an env var

BELLA_BAXTER_URL=https://your-instance.example.com \
BELLA_API_KEY=bax-xxxxxxxxxxxxxxxxxxxx \
swift run

# Optionally write to a .env file
BELLA_BAXTER_URL=https://your-instance.example.com \
BELLA_API_KEY=bax-xxxxxxxxxxxxxxxxxxxx \
DOTENV_OUTPUT=.env \
swift run
```

## When to use this pattern

Use the SDK when you **cannot** wrap the process with `bella run` (containers, serverless, cloud functions) or need to pull secrets conditionally at runtime.

## Package.swift dependency

```swift
// In your Package.swift
dependencies: [
    .package(url: "https://github.com/cosmic-chimps/bella-baxter-swift", from: "1.0.0"),
],
targets: [
    .executableTarget(
        name: "MyApp",
        dependencies: [
            .product(name: "BellaBaxterSwift", package: "bella-baxter-swift"),
        ]
    ),
]
```

## Required environment variables

| Variable | Description |
|---|---|
| `BELLA_BAXTER_URL` | URL of your Bella Baxter instance |
| `BELLA_API_KEY` | API key (`bax-...`) |

> **Note:** `DOTENV_OUTPUT` is optional. If set, secrets are written to that file path instead of printed to stdout.
