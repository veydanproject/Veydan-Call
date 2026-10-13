# The node as an image:  make image
#
#   docker run -d --name vcall --restart=unless-stopped \
#     --network=host -v vcall:/data -e VCALL_PUBLIC_IP=<your-ip> rookbeam/vcall
#
# Host networking on purpose: TURN hands out relay ports from a whole range
# (VCALL_RELAY_PORTS), and mapping thousands of ports one by one is slow
# and easy to get wrong.
#
# The image holds two static binaries, their licence and the notices of the
# crates they are built from, nothing else: no shell, no system. /data keeps
# the node's key; with the volume gone, the node comes back as another node.
#
# The second binary is the agent of the project's monitoring, off unless the
# volunteer turns it on (-e VEYDAN_AGENT=on, README.md, "Project
# monitoring"). It is the first process: without the switch it hands the
# process over to the node at once, so the node runs exactly as alone.
FROM scratch
LABEL org.opencontainers.image.title="VCall" \
      org.opencontainers.image.description="The VCall node: STUN and TURN for Veydan Chat calls" \
      org.opencontainers.image.vendor="Veydan Project" \
      org.opencontainers.image.authors="Veydan Project" \
      org.opencontainers.image.licenses="LicenseRef-PolyForm-Perimeter-1.0.1" \
      org.opencontainers.image.source="https://github.com/veydanproject/Veydan-Call"
# PolyForm Perimeter 1.0.1: whoever gets the image gets the terms with it.
COPY LICENSE /LICENSE
# The notices of the crates the binary is built from.
COPY THIRD-PARTY-LICENSES.md /THIRD-PARTY-LICENSES.md
COPY dist/vcall /vcall
# The agent: the image build takes it from the kit of the project's
# servers (make image VAGENT=<file>; the release passes the build of each
# architecture).
COPY dist/vagent /vagent
ENV VCALL_DATA=/data VCALL_LISTEN=0.0.0.0:443 VCALL_TURN_LISTEN=0.0.0.0:3478 VCALL_CTL=/data/ctl.sock
VOLUME /data
EXPOSE 443/tcp 3478/tcp 3478/udp
ENTRYPOINT ["/vagent", "entrypoint", "/vcall"]
CMD ["node"]
