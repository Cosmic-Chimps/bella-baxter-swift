# Sample 04: iOS App — SwiftUI Integration

**Pattern:** SwiftUI app that loads secrets via `BellaBaxterSwift` at launch. This is a **documentation sample** showing the integration pattern — open it in Xcode, not the terminal.

---

## How it works

```
App launches
    ↓
BellaClient.injectIntoEnvironment()   →  fetches secrets, sets env vars
    ↓
Views read from ProcessInfo / AppSecrets
```

## Running the sample

1. Open the package in Xcode:
   ```bash
   open samples/04-ios-app/
   ```

2. Select your simulator or device target

3. Add environment variables in the Xcode scheme (**Product → Scheme → Edit Scheme → Run → Arguments → Environment Variables**):
   - `BELLA_BAXTER_URL` = `https://your-instance.example.com`
   - `BELLA_API_KEY` = `bax-xxxxxxxxxxxxxxxxxxxx`

4. Build and run (`⌘R`)

## Package.swift dependency

```swift
dependencies: [
    .package(url: "https://github.com/cosmic-chimps/bella-baxter-swift", from: "1.0.0"),
],
```

## Required environment variables

| Variable | Description |
|---|---|
| `BELLA_BAXTER_URL` | URL of your Bella Baxter instance |
| `BELLA_API_KEY` | API key (`bax-...`) |

## Notes

- This sample cannot be run with `swift run` — it requires a SwiftUI host (simulator or device)
- For production iOS apps, store the API key securely (Keychain) rather than as a plain environment variable
- Consider loading secrets lazily on first use rather than at app launch for faster startup
