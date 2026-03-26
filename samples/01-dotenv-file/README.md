# Sample 01: `.env` File Approach (Swift)

**Pattern:** `bella secrets get -o .env` writes secrets once → Swift app reads the file on startup. No SDK, no network calls at runtime.

---

## How it works

```
bella secrets get -o .env   →   .env file on disk   →   loadDotenv()   →   app reads values
```

## Setup

```bash
# Authenticate
bella login --api-key bax-xxxxxxxxxxxxxxxxxxxx

export BELLA_BAXTER_URL=http://localhost:5522   # your Bella Baxter instance

# Pull secrets into .env, then run
bella secrets get -o .env && swift run
```

## Works with any Swift target

```bash
# Swift Package Manager binary
bella secrets get -o .env && .build/release/MyApp

# Run during development
bella secrets get -o .env && swift run

# CI/CD — pull once before tests
bella secrets get -o .env && swift test
```

## Security notes

- Add `.env` to `.gitignore` — never commit secrets
- The file is only as secure as the filesystem permissions
- For production, prefer the process-inject or SDK approach to avoid writing secrets to disk
