FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install --no-install-recommends -y openssh-server \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10002 --shell /bin/sh secscan-audit \
    && passwd -d secscan-audit \
    && install -d -m 0700 -o secscan-audit -g secscan-audit /home/secscan-audit/.ssh

COPY entrypoint.sh /usr/local/bin/secscan-fixture-entrypoint
RUN chmod 0755 /usr/local/bin/secscan-fixture-entrypoint

EXPOSE 22
ENTRYPOINT ["/usr/local/bin/secscan-fixture-entrypoint"]
