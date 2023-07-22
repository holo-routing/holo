# Build image
FROM ghcr.io/rust-lang/rust:nightly-bookworm as build

RUN apt-get update && \
    apt-get install -y build-essential \
    cmake \
    libpcre2-dev \
    protobuf-compiler

WORKDIR /usr/src/holo
COPY .. .
RUN cargo build --features zebra-8-4-compat --release

# Final base
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y frr \
    ifupdown \
    iputils-ping \
    less \
    tcpdump \
  && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/run/holo
RUN chown frr:frr /var/run/holo

# Define Bash aliases
RUN echo "alias holo-cli-show='holo-cli -c \"show state xpath /ietf-routing:routing format json\"'" >> /root/.bashrc
RUN echo "alias ipr='ip -4 ro ; ip -6 ro ; ip -M ro'" >> /root/.bashrc

COPY --from=build /usr/src/holo/holo-daemon/holod.toml /etc/holod.toml
COPY --from=build /usr/src/holo/target/release/holod /usr/local/sbin/
COPY --from=build /usr/src/holo/target/release/holo-cli /usr/local/sbin/

ENV RUST_BACKTRACE=1
ENV RUST_LOG=holo=debug

COPY docker/docker-start /usr/src/docker-start
CMD ["/usr/src/docker-start"]
