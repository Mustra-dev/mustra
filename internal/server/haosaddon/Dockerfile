ARG BUILD_FROM
FROM $BUILD_FROM

# bash for install.sh (pipefail); curl for its downloads.
RUN apk add --no-cache bash curl jq ca-certificates

# install.sh writes to its usual paths; both point into /data, the add-on's
# persistent volume. The identity database survives restarts and rebuilds,
# and the last good agent can start while the server is unreachable.
RUN mkdir -p /opt /var/lib \
 && ln -s /data/agent /opt/mustra-agent \
 && ln -s /data/state /var/lib/mustra-agent

COPY run.sh /run.sh
RUN chmod a+x /run.sh
CMD ["/run.sh"]
