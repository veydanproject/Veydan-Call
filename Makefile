# VCall: the call node (STUN, TURN, SFU), and the tools to try one.

.PHONY: build test check e2e release build-deploy image deploy third-party clean

SHELL := /bin/bash
ENV := source scripts/env.sh &&

# Debug build.
build:
	@$(ENV) cargo build

# Unit tests and the end-to-end tests, all in this process, no server needed.
test:
	@$(ENV) cargo test --locked

check:
	@$(ENV) cargo clippy --all-targets --locked -- -D warnings

# The end-to-end tests alone: a node on loopback, a TURN client against it
# over UDP, TCP and TLS, the refusals, the credentials and the limits; rooms
# of the SFU with participants on str0m over UDP and TCP; a report to a
# registry.
e2e:
	@$(ENV) cargo test --locked -p vcall --test e2e -- --nocapture

# The node as a static Linux binary in dist/.
release:
	@bash scripts/build-release.sh

# The node copied into the bin folder of a server kit, as the kit takes
# it (vcall, vcall.sha256 that sha256sum -c reads, vcall.RELEASE):
#   make build-deploy DEPLOY_BIN=<folder>
build-deploy: release
	@if [ -z "$(DEPLOY_BIN)" ]; then echo ">> make build-deploy DEPLOY_BIN=<folder>"; exit 1; fi
	@mkdir -p "$(DEPLOY_BIN)"
	@cp dist/vcall "$(DEPLOY_BIN)/"
	@(cd dist && sha256sum vcall) > "$(DEPLOY_BIN)/vcall.sha256"
	@cp dist/RELEASE "$(DEPLOY_BIN)/vcall.RELEASE"
	@echo ">> $(DEPLOY_BIN)/vcall  $$(cat dist/RELEASE)"

# The node as a docker image.
IMAGE ?= rookbeam/vcall
# The agent of the project's monitoring goes into the image beside the
# node (off unless VEYDAN_AGENT=on): taken from the kit, the build of
# vagent next to this folder by default:  make image VAGENT=<file>
VAGENT ?= ../cloud/dist/vagent
image: release
	@[ -s "$(VAGENT)" ] || { echo ">> no agent at $(VAGENT): build vagent first, or make image VAGENT=<file>"; exit 1; }
	@cp "$(VAGENT)" dist/vagent
	@docker build -q -t $(IMAGE):$$(cut -d- -f1 dist/RELEASE) -t $(IMAGE):latest -f deploy/Dockerfile . >/dev/null
	@echo ">> $(IMAGE):$$(cut -d- -f1 dist/RELEASE)"

# One server by ssh: make deploy HOST=root@1.2.3.4 IP=1.2.3.4 [PORT=443] [RELAY=49152-49999]
# [SSH_OPTS="-i key"]. The project's servers hold 443 for nginx and take PORT=8443.
deploy: release
	@SSH_OPTS="$(SSH_OPTS)" bash scripts/deploy-node.sh "$(HOST)" "$(IP)" "$(or $(PORT),443)" "$(or $(RELAY),49152-49999)"

# THIRD-PARTY-LICENSES.md from Cargo.lock: run it after the lock changes.
third-party:
	@$(ENV) node scripts/third-party.mjs

clean:
	@rm -rf target dist
