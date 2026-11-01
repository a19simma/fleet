FROM rust:1.99-bookworm
RUN apt-get update \
    && apt-get install -y --no-install-recommends util-linux sudo \
    && rm -rf /var/lib/apt/lists/*
RUN groupadd -g 987 fleet-work \
    && groupadd -g 986 fleetd \
    && useradd -u 986 -g fleetd -G fleet-work -M fleetd \
    && useradd -u 985 -g 987 -M fleet-job \
    && echo 'fleetd ALL=(root) NOPASSWD: /usr/bin/setpriv' > /etc/sudoers.d/fleet-it \
    && chmod 0440 /etc/sudoers.d/fleet-it \
    && touch /etc/fleet-it
RUN mkdir -p /opt/fleet-it /run/fleet-it /run/fleet /jobs \
    && chmod 0755 /opt/fleet-it \
    && chown fleetd:fleetd /run/fleet-it
COPY --chmod=0755 systemctl agent /opt/fleet-it/
