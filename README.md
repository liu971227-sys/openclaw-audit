# openclaw-audit

Local security audit for OpenClaw.

`openclaw-audit` scans a local OpenClaw installation for exposed gateways, unsafe authentication, risky proxy settings, weak filesystem permissions, browser-control exposure, risky state-directory placement, and possible secret leakage.

It runs locally and does not upload your configs, logs, or scan results.

## Why

Recent OpenClaw security issues have shown that risk is not limited to public exposure. A deployment can still be unsafe because of weak local auth, dangerous Control UI settings, over-trusted proxies, browser SSRF posture, unsafe external-content bypasses, leaked tokens in logs or session transcripts, or sensitive state stored in synced folders or hidden behind symlinks.

`openclaw-audit` is designed to catch these problems early and give clear remediation steps.

## Scope

`v0.1` focuses on local single-node OpenClaw audits.

Included:
- configuration audit
- gateway exposure classification
- authentication checks
- Control UI security checks
- trusted proxy and trusted-proxy auth checks
- browser SSRF, remote CDP, and relay checks
- unsafe external-content bypass checks
- filesystem permission checks
- state_dir, credentials path, symlink, and synced-folder checks
- secrets leakage scan across config, sessions, and logs
- tool blast-radius checks
- plugin trust checks
- version baseline check
- terminal output
- JSON output
- optional HTML report

Not included:
- automatic remediation
- continuous monitoring
- cloud dashboard
- runtime interception
- multi-node fleet management

## Installation

### Build from source

```bash
git clone https://github.com/yourname/openclaw-audit.git
cd openclaw-audit
go build ./cmd/openclaw-audit
```

### Run directly

```bash
go run ./cmd/openclaw-audit scan
```

## Usage

### Basic scan

```bash
openclaw-audit scan
```

### Scan a specific config

```bash
openclaw-audit scan --config ~/.openclaw/config.yaml
```

### Scan with a specific log directory

```bash
openclaw-audit scan --logs ~/.openclaw/logs
```

### JSON output

```bash
openclaw-audit scan --format json
```

### Export HTML report

```bash
openclaw-audit scan --report report.html
```

## Example Output

```text
OpenClaw Security Audit
Score: 46/100
Risk: High

Findings:
- [CRITICAL] Gateway listens on all interfaces
  OpenClaw appears to listen on all interfaces, which can expose the gateway to the local network or public internet.
  Evidence: gateway.bind=0.0.0.0 (gateway.bind)
  Fix: Set gateway.bind to loopback or 127.0.0.1.
  Fix: Only expose the gateway behind strong authentication and a trusted reverse proxy.
```

## Security Model

- local-first by default
- no telemetry
- no cloud account required
- no raw secret dumping in output
- findings are redacted where possible

If a secret is detected, rotate it immediately.

## Exit Codes

- `0`: scan completed with no actionable findings
- `1`: scan completed with findings
- `2`: scan failed

## License

MIT