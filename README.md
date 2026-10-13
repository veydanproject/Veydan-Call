# VCall

## Support the Veydan network

You can support the Veydan network by installing **Veydan Link** (a bridge)
and **Veydan Call** (a call node) on a server of yours. One command, as
root, on a server with a public IPv4 address, best of all inside the
country whose people you want to help:

```sh
curl -fsSL https://raw.githubusercontent.com/veydanproject/Veydan-Server/main/install.sh | sudo bash -s -- --volunteer
```

It installs both as services of the system, without docker, and they join
the network by themselves: nothing to configure, no domain, no account.
The bridge gives people in a country that closes the way to Veydan a way
in; the call node makes the calls of people near it fast. Neither can read
anything of anyone. The call node alone: `--call` instead of
`--volunteer`; the bridge is [Veydan-Link](https://github.com/veydanproject/Veydan-Link).
What each of them needs, what the command does to the server and how to
see that it works is below.

## What it is

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

## What you need

- A server with a public IPv4 address. A node helps the people **near
  it**: a call is fast when the node is close to the callers, so a node
  inside a country helps the people of that country most.
- These ports open from the Internet: one TCP port for control and TURN
  over TLS, 3478 and 3479 (UDP and TCP), and a range of UDP ports for the
  relayed calls. UDP must not be blocked by your provider.
- Bandwidth: one relayed call may take up to two megabits a second each
  way. The node limits itself (`VCALL_MAX_MBPS`, 100 by default); a
  provider that counts traffic will count this.
- Linux, and the right to run a command as root. No domain, no certificate.

## Install

Two ways. Both give the same node; take the one you are used to.

### As a service of the system (no docker)

One command, as root:

```sh
# a call node and a VLink bridge on one server: what helps people in a
# country that closes the way to Veydan most
curl -fsSL https://raw.githubusercontent.com/veydanproject/Veydan-Server/main/install.sh | sudo bash -s -- --volunteer

# a call node alone
curl -fsSL https://raw.githubusercontent.com/veydanproject/Veydan-Server/main/install.sh | sudo bash -s -- --call
```

It asks the public address of the server (Enter keeps the one it found),
the control port (Enter keeps 8443) and a word for where the node is
(`eu`, `us`, `ru`, …; a hint for the apps, Enter keeps `default`); with
`--volunteer` also the two questions of the bridge. Without questions: add
`--yes`.

What it does to the server, all of it:

1. installs a few small packages it needs itself (`curl`, `jq`,
   `openssl`, `ufw` and the like);
2. downloads `vcall` for this machine (x86_64 or aarch64) from the
   [releases](https://github.com/veydanproject/Veydan-Call/releases) of this
   repository and checks it against `SHA256SUMS`;
3. puts it in `/opt/vcall` under a user of its own, `vcall`, with a
   systemd unit; the settings are in `/opt/vcall/etc/vcall.env`;
4. turns the firewall `ufw` on with ssh and the node's ports open and the
   rest closed. If the server already serves something else, keep the
   firewall as it is: put a file `server.conf` with the line
   `FIREWALL=none` in the directory you run the command from;
5. keeps its answers in `/opt/veydan/server.conf`, so that the same
   command, run again, asks nothing;
6. starts the node, tells the registry of the Veydan network about it and
   prints its reference, `<ip>:8443#<id>`.

It is tested on Debian 13; any Linux with systemd should do. The installer
is the kit [Veydan-Server](https://github.com/veydanproject/Veydan-Server),
which you can read before you run it.

The ports the installer opens, to open at your provider as well:
**8443/tcp**, **3478/udp**, **3478/tcp**, **3479/udp**, **3479/tcp**,
**49152–49999/udp**.

By hand: the binary from the releases, `deploy/vcall.service`, the binary
in `/opt/vcall/bin/vcall`, the key and the other files of `VCALL_DATA` in
`/opt/vcall/data`, settings in `/opt/vcall/etc/vcall.env`.

### In docker

```sh
docker run -d --name vcall --restart=unless-stopped --network=host -v vcall:/data \
  -e VCALL_PUBLIC_IP=<your-ip> -e VCALL_REGISTRY=https://hub.veydan.net/vlink rookbeam/vcall
```

or with compose (`deploy/docker-compose.yml`: the image, the volume, host
networking, the Veydan registry and every setting as a comment):

```sh
curl -fsSLO https://raw.githubusercontent.com/veydanproject/Veydan-Call/main/deploy/docker-compose.yml
echo "VCALL_PUBLIC_IP=<your-ip>" > .env
docker compose up -d
```

The image is built for amd64 and arm64 and listens on 443. Open at your
provider: **443/tcp**, **3478/udp**, **3478/tcp**, **3479/udp**,
**3479/tcp**, and the relay ports **49152–65535/udp** (or the range
`VCALL_RELAY_PORTS` names). Where 443 is taken by a web server, move the
node: `-e VCALL_LISTEN=0.0.0.0:8443`. The address the app is given comes
from the node itself, so nothing else changes.

## What happens after the install

Nothing more is asked of you. In order:

1. On its first start the node makes its own key. The key *is* the node:
   its id is in the reference, `<ip>:<port>#<id>`, which
   `vcall id --addr <your-ip>:<port>` prints.
2. It tells the registry of the Veydan network that it exists and how full
   it is, and says so again every five minutes.
3. The registry checks that the node answers at its address, with its key,
   and lists of what it can do only what that check showed.
4. The network may hold a new node until its owner approves it.
5. After ten minutes without a failed check the node is given to the apps.
   They choose the nearest nodes that are not full.

To see where your node is:

```sh
journalctl -u vcall -f          # a service
docker logs -f vcall            # docker
```

| The log says | It means |
|---|---|
| `node is up` | it runs and listens |
| `registry knows this node state=new` | reported; the registry has not checked it yet |
| `… state=verified` | it answers; waiting for approval or for the ten minutes to pass |
| `… state=active` | given to apps: it works |
| `registry was not told … 403` | the registry refused the report: the address is not public, or the node is older than the registry takes |
| `registry was not told`, another error | this server cannot reach the registry; it tries again by itself |

Check it from **another** machine, outside its network:
`vcall probe <ip>:<port>#<id>` (and `--transport tcp`, `--transport tls`),
and the rooms with `vcall room-test <ip>:<port>#<id>`. What it carries
now: `vcall ctl --socket /run/vcall/ctl.sock stats` on the server.

A private node (`VCALL_PRIVATE=true`) is never listed; it gets its callers
by invitation (below). Clients take the list of public nodes from
`GET <VCALL_REGISTRY>/v1/calls`, nodes from `/v1/calls/all` (trust, below).

## Update, move, remove

- **Update.** A service: the same install command again; it replaces the
  program when a newer release is out and keeps the key and the settings.
  Docker: `docker pull rookbeam/vcall`, then remove the container and run
  it again (`docker compose pull && docker compose up -d`).
- **Move to another server.** Copy `/opt/vcall/data` (or the volume) and
  install there. The id stays; at a new address the registry checks the
  node again, and a network that approves by hand approves it again.
- **Remove.** A service:
  `systemctl disable --now vcall && rm /etc/systemd/system/vcall.service && rm -rf /opt/vcall && userdel vcall`.
  Docker: `docker rm -f vcall && docker volume rm vcall`. The registry
  forgets a node that went silent by itself.

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

## Project monitoring (optional)

The image carries a second, small program: the agent of the project's
monitoring. It is off unless you turn it on with `-e VEYDAN_AGENT=on` (or
`VEYDAN_AGENT: "on"` under `environment:` in `docker-compose.yml`). Once
on, it sends a short report every five minutes to the project's servers,
signed with the node's own key (`node.key` in `/data`): the node's
kind, version and uptime, the CPU and memory of the container, its last
errors (no address of anyone in them), and the results of the checks it
was asked for. Those checks are only ever two: carrying test bytes
through a bridge of the project, and asking a relay of the project for
nothing; the agent refuses any target that is not in the project's signed
lists. That shows the project how its network looks from where you are.
It reports nothing about the server beyond the container, nothing about
who uses the node, and never sees
anyone's messages, files or calls. It opens no port: it only sends out, so
your firewall and NAT stay as they are. To turn it off, remove the variable
and start the container again; the node works the same either way.

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
