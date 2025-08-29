# Velocity2FA

A lightweight **staff-only 2FA** plugin for **Velocity 3** (MC 1.21.x). Premium-only (online-mode) friendly.
[![Build Velocity Plugin](https://github.com/Queazified-co-uk/2-factor/actions/workflows/build.yml/badge.svg)](https://github.com/Queazified-co-uk/2-factor/actions/workflows/build.yml)

## Features
- Only prompts users with permission `staff.2fa`
- TOTP (Google Authenticator/Authy) 6-digit codes
- Blocks backend connection until verified
- Persists secrets in `plugins/Velocity2FA/secrets.json`
- Session cache (default 12h) to avoid re-verifying too often
- Commands: `/verify <code>`, `/2fasetup`

## Build
```bash
cd Velocity2FA
mvn -q -e -U -B clean package
```
Output JAR: `target/velocity2fa-1.0.0.jar`

## Install
1. Drop the JAR into your Velocity `plugins/` folder.
2. Restart Velocity.
3. Ensure staff have permission:
   ```
   /lp group staff permission set staff.2fa true
   ```
4. Staff join → see setup + otpauth URL → add to Authenticator → run:
   ```
   /verify 123456
   ```

## Notes
- Blocks joining backend servers until verified (via `ServerPreConnectEvent`).
- Change session TTL in code if you want shorter/longer persistence.
