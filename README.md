# VCall

A **call node** for Veydan Chat: the server part of a voice or video call.
Calls go directly between the two people whenever they can; when a network
is in the way, the node relays the packets (TURN). A group meets in a room
of the node's SFU, which passes each participant's stream to the others.

```
caller ───── direct, encrypted end to end (DTLS-SRTP) ───── caller
   └──▶ a node's TURN relays the packets when the direct way is closed ◀──┘

group:  A ──▶ room ──▶ B, C      each stream to everybody else, as it came
```

What travels through a node is encrypted between the callers: a relayed
packet is DTLS-SRTP the node cannot open; a frame in a room is encrypted
between the participants under keys the node never sees. **A node cannot
hear a call, cannot see a face, and does not know who is talking.** It
passes packets on, counts bytes, and forgets.

Anybody may run a node, as anybody may run a VLink bridge. A private node
(`VCALL_PRIVATE=true`) serves only the people you give an access key or an
invitation to; a team can run one for itself.

## Run one

A server with a public IPv4 address, port 443 free, and UDP open:

```
curl -fsSLO https://raw.githubusercontent.com/veydanproject/Veydan-Call/main/deploy/docker-compose.yml
echo "VCALL_PUBLIC_IP=<your-ip>" > .env
docker compose up -d
```

(`deploy/docker-compose.yml`: the image, the volume, host networking, the
Veydan registry and every setting as a comment; or the one command
`docker run -d --name vcall --restart=unless-stopped --network=host -v
vcall:/data -e VCALL_PUBLIC_IP=<your-ip> -e
VCALL_REGISTRY=https://eu-1-vpush.veydan.net/vlink rookbeam/vcall`.)

Or the binary as a service: `deploy/vcall.service`, the binary in
`/opt/vcall/bin/vcall`, the key and the other files of `VCALL_DATA` in
`/opt/vcall/data`, settings in `/opt/vcall/etc/vcall.env`.

Open in the firewall: **443/tcp**, **3478/udp**, **3478/tcp**,
**3479/udp**, **3479/tcp** (the SFU), and the relay ports
**49152–65535/udp** (or the range `VCALL_RELAY_PORTS` names).

The node makes its own key on the first start. Its reference, which the
app takes, is what `vcall id --addr <your-ip>:443` prints:
`<ip>:443#<id>`. Check it from another machine with
`vcall probe <ip>:443#<id>` (and `--transport tcp`, `--transport tls`),
and the rooms with `vcall room-test <ip>:443#<id>`.

Where 443 is taken by a web server, move the node: `VCALL_LISTEN=0.0.0.0:8443`.
The address the app is given comes from the node itself, so nothing else
changes.

A public node is listed for everybody once it names the registry
(`VCALL_REGISTRY=https://<registry host>/vlink`, and `VCALL_REGION=eu` or
the like as a hint). It reports every five minutes how full it is; the
registry checks that it answers before listing it, and lists of what it
can do only what its own answer to that check says. Clients take the list
from `GET <VCALL_REGISTRY>/v1/calls`, nodes from `/v1/calls/all` (trust,
below). A registry older than 2026-10-09 refuses the report of this
version (a 403 in the log). A private node is never listed; it gets its
callers by invitation (below).

## Settings

Environment variables, all optional:

| Variable | Default | What |
|---|---|---|
| `VCALL_LISTEN` | `0.0.0.0:443` | control and TURN over TLS |
| `VCALL_TURN_LISTEN` | `0.0.0.0:3478` | STUN and TURN over UDP, TURN over TCP |
| `VCALL_SFU_LISTEN` | `0.0.0.0:3479` | the SFU over UDP, and over TCP on the same port |
| `VCALL_PUBLIC_IP` | found by itself | the address the world reaches the node at; set it in a container or behind a NAT |
| `VCALL_PUBLIC_PORT` | the listen port | when the world reaches the TLS port at another port |
| `VCALL_RELAY_PORTS` | `49152-65535` | UDP ports allocations are given from |
| `VCALL_DATA` | `data` | the node's key and TURN secret, `devices.json` (the invited devices: the only record of who may use a private node) and `registry-nodes.json` (the registry's list, kept); a volume in docker, and in the backup |
| `VCALL_CTL` | `<data>/ctl.sock` | the socket `vcall ctl` talks to |
| `VCALL_PRIVATE` | `false` | credentials only to callers with an access key or an invited device |
| `VCALL_ACCESS_KEYS` | — | a file with the keys of a private node, one per line; invitations work without it |
| `VCALL_MAX_MBPS` | `100` | all the traffic the node relays; 0 for no limit |
| `VCALL_TURN_MAX_MBPS` | `50` | the part of it TURN may take |
| `VCALL_TURN_ALLOC_KBPS` | `2000` | what one allocation may carry, each way |
| `VCALL_TURN_MAX_ALLOCATIONS` | `1000` | allocations at once |
| `VCALL_TURN_MAX_PER_IP` | `32` | allocations one address may hold: a caller makes one per interface per transport, and callers share a NAT |
| `VCALL_TURN_MAX_LIFETIME` | `3600` | seconds an allocation may last without a refresh |
| `VCALL_CREDENTIALS_TTL` | `600` | seconds credentials are good for |
| `VCALL_CREDENTIALS_PER_IP` | `30` | credentials and rooms one address may ask for in ten minutes |
| `VCALL_ROOMS_MAX` | `64` | rooms of the SFU at once |
| `VCALL_ROOM_MAX` | `12` | seats in a room |
| `VCALL_ROOM_KBPS` | `2500` | what one participant of a room may send, kbit/s; 0 for no limit |
| `VCALL_ROOM_AUDIO_N` | `3` | speakers whose audio is forwarded, in a room with more participants than that and one |
| `VCALL_ROOM_BWE_KBPS` | `2500` | what a participant is assumed to take before its TWCC feedback says: the first simulcast layers are chosen against it |
| `VCALL_CASCADE` | `on` | the cascade: `on` (seats of any node within the quota, of a node on the registry's list without it; joins through this node into other nodes' rooms), `off`, `registry` (seats of nodes on the registry's list only), or a file with the ids of the nodes whose seats this node takes, one per line (those only, without the quota) |
| `VCALL_CASCADE_SEATS_PER_NODE` | `256` | seats one other node may hold here, over all rooms; 0 for no limit |
| `VCALL_CASCADE_UPLINKS` | `256` | uplinks to other nodes this node holds at once |
| `VCALL_CASCADE_JOINS_PER_IP` | `10` | joins with a home one address may make in ten minutes, on a public node |
| `VCALL_REGISTRY` | — | the registry to report to and to take the list of nodes from, `https://host/vlink`; unset, the node stays unlisted and has no list: with `VCALL_CASCADE=on` every node is held to the quota, `registry` does not start, and a file names the trusted nodes on its own |
| `VCALL_REGISTRY_ROOT` | the VLink root | the key (hex) the registry's list of nodes is checked against; only for a registry of your own |
| `VCALL_REGION` | — | a hint for clients in the report: `eu`, `ru` |
| `VCALL_MAX_CONNECTIONS` | `4096` | TCP and TLS connections at once |
| `VCALL_MAX_CONNECTIONS_PER_IP` | `32` | of them, how many one address may hold |
| `VCALL_REALM` | `veydan` | the realm of the TURN credentials |
| `VCALL_LOG` | `info` | `debug` shows every allocation and refusal |

A room lives twelve hours at the longest and ends after five minutes with
nobody in it. The creator may ask for fewer seats or less bandwidth than
the node gives, never for more. A seat whose participant does not connect
within thirty seconds is given up.

`vcall ctl stats` (on the server: `vcall ctl --socket /run/vcall/ctl.sock stats`)
shows allocations, rooms, participants, satellites and uplinks of the
cascade, trusted nodes, devices, bytes and refusals by reason. No
addresses, no names. `sfu_dropped_socket` counting up under load means the
SFU socket's send buffer is too small for the bursts a room sends: the node
asks for 4 MiB, and Linux cuts that to `net.core.wmem_max` (about 200 KiB
by default); `sysctl -w net.core.wmem_max=4194304 net.core.rmem_max=4194304`
on the server lifts it.

## A private node and invitations

A node with `VCALL_PRIVATE=true` serves nobody it does not know. There
are two ways to be known: a key from `VCALL_ACCESS_KEYS`, which you hand
out yourself and which a group may keep in its settings; and an
**invitation**, which the node makes for one person and one phone:

```
vcall ctl --socket /run/vcall/ctl.sock invite --label "Anna's phone"
veydan://call-node/<id>?a=<ip>%3A443&t=<token>
good for 1 device until 2026-10-16 10:00 UTC (unix 1792000000); label: Anna's phone
```

Give the first line to the person. Opened in Veydan Chat, the link reaches
the node (TLS pinned to its id) and exchanges the token for the credentials
of that device, which the app keeps in its secret store; the token itself
is then spent. `--uses 5` lets five devices take one link, `--ttl 12h`
(or `30m`, `3d`, seconds) says how long it is open; a week by default.
The node keeps only hashes of tokens and secrets (`devices.json` in
`VCALL_DATA`): the file lets nobody in.

```
vcall ctl --socket /run/vcall/ctl.sock devices        who is in, and which invitations are still open
vcall ctl --socket /run/vcall/ctl.sock revoke <device id>   out, from now on
vcall ctl --socket /run/vcall/ctl.sock revoke <hash>        an invitation withdrawn
```

A private node starts without keys, as long as it has its control socket:
make the first invitation after it is up. Guessing a token gets an address
ten tries an hour. A device's credentials open everything a key opens:
TURN credentials, rooms, and the cascade through this node.

## Trust and the registry

Other nodes take seats in this node's rooms for their participants (the
cascade, below). Whom to let in is `VCALL_CASCADE`:

- `on` (the default): any node, each within `VCALL_CASCADE_SEATS_PER_NODE`
  seats; a node the registry lists holds seats without that quota;
- `registry`: nodes the registry lists, and nobody else;
- a file with ids, one per line: those nodes only, without the quota — a
  private network that has no registry;
- `off`: no seats of other nodes, no joins through this node.

The registry's list (`GET <VCALL_REGISTRY>/v1/calls/all`) is signed by the
registry's list key under the VLink root's delegation, the same root the
app checks its lists against; the node checks it the same way and takes
nothing that does not verify. It is fetched every five minutes and kept in
`registry-nodes.json` in `VCALL_DATA`, so a node that restarts while the
registry is away trusts whom it trusted until the list runs out (a day).
The list runs out in memory the same way: a registry away for longer than
that leaves the node trusting nobody by the list (with `on`, every node is
back under the quota; with `registry`, no seats at all) until it answers
again. `vcall ctl stats` shows `cascade` (the mode) and `trusted_nodes_now`.
A registry of your own signs under another root: name it in
`VCALL_REGISTRY_ROOT`. A private node fetches the list too, when it
names a registry; it reports nothing to it.

## The cascade

A participant of a group may sit on a node of its own that holds a seat
for it in the room's home node: the client takes a one-time pass from the home and
joins its own node naming the home; the node joins the home with the pass
and its signed word, and carries the streams both ways. The home sees the
other node's id, counts its seats and gives a silent one up in seconds; the
other node gets back nothing of its own. Try two nodes with
`vcall cascade-test <home ip>:443#<id> <own ip>:443#<id>`. A private node
of your own takes joins with a home from its key holders and invited
devices only; a public one counts them per address.

## What it does and does not see

- **Sees:** the IP address a caller connects from, how much it sends, and
  the address of the other side of the call; in a room, who sends to whom
  by seat number, and the kind of each frame (the codec's open header).
- **Does not see:** who is calling whom, the voice, the video, or any
  name. All of that is encrypted between the callers' apps.

A node relays only to public addresses: never into the network it stands
in, never to itself (only to its own relay ports, where another caller of
the same node is). Credentials come from the node itself, nobody else can
make them; they open an allocation for ten minutes after they are given,
and an allocation that is open keeps going for as long as the call does.

Running a node carries the usual responsibility of running a public
server. Consider the rules of your hosting provider and your country.

## What is in this folder

```
crates/vcall-proto    the control channel: HELLO/WELCOME, TURN credentials, rooms, invitations; the report to the registry and its list of nodes
crates/vcall          the node (STUN, TURN, SFU, the cascade), and vcall id / probe / room-test / cascade-test / ctl
deploy/               the systemd unit, the docker image and docker-compose.yml
scripts/              the build
```

Build and test: `make build`, `make test`, `make check`, `make e2e` (a
node on loopback, a client against it over UDP, TCP and TLS, rooms with
participants over UDP and TCP). The static Linux binary: `make release` →
`dist/vcall`. The image: `make image`.

## License

PolyForm Perimeter 1.0.1 — see `LICENSE`, and `LICENSE-SUMMARY.md` for a
plain-language summary. The notices of the crates the node is built from
are in `THIRD-PARTY-LICENSES.md`.

Copyright © 2026 Veydan Project

Developed by Rookbeam Technologies LLC, USA
