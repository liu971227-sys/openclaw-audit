# Checks

`openclaw-audit` currently evaluates:

- gateway exposure
- authentication posture
- Control UI security
- trusted proxy risk and trusted-proxy auth setup
- browser SSRF posture, remote CDP, and browser relay settings
- unsafe external-content bypasses
- filesystem permissions
- state_dir, credentials path, symlink/junction, and synced-folder risks
- secrets leakage in config, session transcripts, and logs
- tool blast radius
- plugin trust
- version baseline