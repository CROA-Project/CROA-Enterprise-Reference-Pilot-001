# ADR-0004: C6 refuses ECCs issued before its own boot

**Status:** accepted (v0.2.0)

## Context
The replay registry is in-memory. After a C6 restart, any ECC redeemed within the last `ECC_TTL_SECONDS`
would be replayable. Persisting the registry adds state the pilot has deliberately avoided.

## Decision
Record `BOOT_TIME` at process start and block any ECC with `iat < BOOT_TIME`
(`ECC_PREDATES_FIREWALL_EPOCH`). Configurable via `C6_REJECT_PRE_BOOT_ECCS`.

## Consequences
- At-most-once holds across restarts with no persistent state.
- Unredeemed ECCs issued before the restart are also refused; the agent must re-propose. This trades
  liveness for safety and is not a substitute for a durable registry in production.
