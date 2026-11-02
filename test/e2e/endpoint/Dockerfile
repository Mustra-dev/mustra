# A disposable Linux endpoint for the end-to-end tests: Ubuntu with systemd
# as PID 1, so the console's install one-liner runs exactly as it does on a
# real host (unit file, StateDirectory, systemd-run for updates) rather
# than against a fake service manager.
#
# 22.04 rather than a newer release because its systemd (249) still boots
# on a cgroup v1 host; it runs on cgroup v2 runners too. Started with
# --privileged by the harness, which systemd needs for its own mounts.
ARG BASE=ubuntu:22.04
FROM ${BASE}
ENV container=docker DEBIAN_FRONTEND=noninteractive
# sudo: the one-liner pipes to `sudo bash`. dpkg-dev: the patching fixture
# builds and indexes a local apt repository on the endpoint.
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends \
      systemd systemd-sysv dbus curl ca-certificates iproute2 procps sudo dpkg-dev python3 \
 && rm -rf /var/lib/apt/lists/* \
 && find /lib/systemd/system/sysinit.target.wants/ -mindepth 1 ! -name 'systemd-tmpfiles-setup*' -delete \
 && rm -f /lib/systemd/system/multi-user.target.wants/* /etc/systemd/system/*.wants/* \
          /lib/systemd/system/local-fs.target.wants/* /lib/systemd/system/sockets.target.wants/*udev* \
          /lib/systemd/system/sockets.target.wants/*initctl* /lib/systemd/system/basic.target.wants/*
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
