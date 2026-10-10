# The node as an image:  make image
#
#   docker run -d --name vcall --restart=unless-stopped \
#     --network=host -v vcall:/data -e VCALL_PUBLIC_IP=<your-ip> rookbeam/vcall
#
# Host networking on purpose: TURN hands out relay ports from a whole range
# (VCALL_RELAY_PORTS), and mapping thousands of ports one by one is slow
# and easy to get wrong.
#
# The image holds one static binary, its licence and the notices of the
# crates it is built from, nothing else: no shell, no system. /data keeps
# the node's key; with the volume gone, the node comes back as another node.
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
ENV VCALL_DATA=/data VCALL_LISTEN=0.0.0.0:443 VCALL_TURN_LISTEN=0.0.0.0:3478 VCALL_CTL=/data/ctl.sock
VOLUME /data
EXPOSE 443/tcp 3478/tcp 3478/udp
ENTRYPOINT ["/vcall"]
CMD ["node"]
