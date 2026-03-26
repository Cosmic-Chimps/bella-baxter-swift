# Sample 02: Process Inject (`bella run`) — Swift

**Pattern:** `bella run -- swift run` — secrets injected as environment variables, no file written to disk. Your code reads them with `ProcessInfo.processInfo.environment`.

---

## Setup

```bash
# Authenticate
bella login --api-key bax-xxxxxxxxxxxxxxxxxxxx

export BELLA_BAXTER_URL=http://localhost:5522   # your Bella Baxter instance

# Run with secrets injected
bella run -- swift run
```

## Works with any Swift command

```bash
# Built binary (faster startup)
swift build -c release
bella run -- .build/release/MyApp

# Development
bella run -- swift run

# Tests
bella run -- swift test

# With arguments
bella run -- swift run -- --port 8080 --verbose
```

## vs. `.env` file approach

| | `bella secrets get -o .env` | `bella run --` |
|---|---|---|
| File written to disk | ✅ Yes | ❌ No |
| Extra dependency | dotenv parser | None |
| Secret security | Filesystem | Memory only |
| Works with any command | ✅ Yes | ✅ Yes |

## Secret rotation

Environment variables are set once at process startup and are immutable for the lifetime of the process.

To pick up rotated secrets, restart with `bella run -- swift run`.
