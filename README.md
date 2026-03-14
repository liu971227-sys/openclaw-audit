# openclaw-audit

OpenClaw security audit and hardening CLI for AI agents.

`openclaw-audit` helps operators secure OpenClaw deployments used for AI agents, LLM agent workflows, browser automation, and local agent infrastructure. It scans for exposed gateways, weak auth, risky proxy settings, browser SSRF posture, unsafe external-content bypasses, state-directory mistakes, and secret leakage, then generates hardening artifacts you can actually use.

It runs locally and does not upload your configs, logs, or scan results.

## What This Project Is

This repo is an `AI agent security` tool focused on `OpenClaw hardening`.

It is designed for:
- OpenClaw operators
- AI agent platform engineers
- local LLM / agent security reviewers
- browser automation users who need safer agent runtimes
- teams evaluating OpenClaw exposure before putting it behind remote access

If someone searches for any of these, this repo should be relevant:
- OpenClaw security
- OpenClaw hardening
- AI agent security
- LLM agent security
- browser agent security
- prompt-injection blast radius
- local agent runtime hardening
- reverse proxy for OpenClaw

## Why It Matters

Recent OpenClaw issues have shown that risk is not limited to public exposure. A deployment can still be unsafe because of:
- weak local auth
- dangerous Control UI settings
- over-trusted proxies
- browser SSRF posture
- unsafe external-content bypasses
- leaked tokens in logs or session transcripts
- sensitive state stored in synced folders or hidden behind symlinks

`openclaw-audit` is built to catch those problems early and turn them into concrete remediation steps.

## What It Does

Included today:
- gateway exposure classification
- authentication checks
- Control UI security checks
- trusted proxy and trusted-proxy auth checks
- browser SSRF, remote CDP, and relay checks
- unsafe external-content bypass checks
- filesystem permission checks
- `fs.state_dir`, credentials path, symlink, and synced-folder checks
- secret leakage scan across config, sessions, and logs
- tool blast-radius checks
- plugin trust checks
- version baseline check
- terminal output
- JSON output
- optional HTML report
- `harden` command that generates:
  - `Caddyfile`
  - `HARDENING.md`
  - `openclaw.fix-preview.json`

Not included yet:
- automatic remediation
- continuous monitoring
- cloud dashboard
- runtime interception
- multi-node fleet management

## Installation

### Build from source

```bash
git clone https://github.com/liu971227-sys/openclaw-audit.git
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
openclaw-audit scan --config ~/.openclaw/openclaw.json
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

### Generate hardening artifacts

```bash
openclaw-audit harden --config ~/.openclaw/openclaw.json --site openclaw.example.com
```

This creates:
- `dist/hardening/Caddyfile`
- `dist/hardening/HARDENING.md`
- `dist/hardening/openclaw.fix-preview.json`

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