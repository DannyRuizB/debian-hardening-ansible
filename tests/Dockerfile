# Disposable "fresh Debian server" for the e2e test: systemd as PID 1 (so
# ufw, fail2ban and unattended-upgrades run as real services) plus sshd.
# Root logs in with the CI key only — like a fresh VPS provisioned with a key.
FROM debian:13

ENV container=docker

# The apt lists are kept on purpose (no rm -rf /var/lib/apt/lists): a real
# server has them, and site.yml's --check mode needs them to resolve packages.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       systemd systemd-sysv openssh-server python3 python3-apt sudo ca-certificates cron \
       libpwquality-tools

ARG PUBKEY
RUN mkdir -p /root/.ssh \
    && echo "$PUBKEY" > /root/.ssh/authorized_keys \
    && chmod 700 /root/.ssh \
    && chmod 600 /root/.ssh/authorized_keys

EXPOSE 22

CMD ["/sbin/init"]
