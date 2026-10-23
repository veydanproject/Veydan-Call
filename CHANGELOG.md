# Changelog

## 0.1.2 (2026-10-23): the limits of the audit round, tokio 1.54.1

- `tokio` 1.54.1 (RUSTSEC-2026-0386: the constructors of `AsyncFd` that took
  any raw descriptor violate I/O safety; VCall never builds an `AsyncFd`),
  and VLink 0.3.4 underneath.
- Wrong room tokens (join, leave, token) are counted per address: 20 a
  minute, then 429 `rate_limited` before the room is asked. The requests
  of the control may take a quarter of a room's queue at the most, the
  rest is the media's.
- The quotas of the cascade (seats of a node, uplinks) are taken in one step
  with their check; asked at once, no more than the quota gets through.
- Text frames of a participant on `ctl` have the pace of the bytes (50 a
  second).
- A repeated Allocate (the same transaction) is answered only when it is
  signed with the key that made the allocation.

## 0.1.1 (2026-10-13): the registry has a name of its own

- The registry of the Veydan network is `https://hub.veydan.net/vlink`:
  the README and `deploy/docker-compose.yml` name it instead of the name
  it was reached at before. The old name still answers; a node that
  reports there needs no change.
- Built with VLink's client library 0.3.0, which carries the key of the
  VLink root alone.
- Nothing of the node or of its protocol changed.

## 0.1.0

The first release: STUN and TURN, the SFU of group calls, the cascade
between nodes, the registry of volunteers' nodes.
