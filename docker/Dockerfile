# Build image
# ==============================================================================

FROM ghcr.io/rust-lang/rust:nightly-bookworm AS build

RUN apt-get update && \
    apt-get install -y build-essential \
    cmake \
    libpcre2-dev \
    protobuf-compiler

# holo
# ==============================================================================

WORKDIR /usr/src/holo
COPY . .
RUN cargo build --release

# holo-cli
# ==============================================================================

RUN git clone https://github.com/holo-routing/holo-cli.git /usr/src/holo-cli
WORKDIR /usr/src/holo-cli
RUN cargo build --release

# Final base
# ==============================================================================

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y ifupdown \
    iputils-ping \
    less \
    tcpdump \
  && rm -rf /var/lib/apt/lists/*

RUN groupadd -r holo
RUN useradd --system --shell /sbin/nologin --home-dir /var/run/holo/ -g holo holo
RUN mkdir -p /var/run/holo
RUN chown holo:holo /var/run/holo

# /usr/local/share/holo-cli/modules is where holo-cli will store its modules
RUN mkdir -p /usr/local/share/holo-cli/modules

RUN echo "alias holo-cli-show='holo-cli -c \"show state xpath /ietf-routing:routing format json\"'" >> /root/.bashrc
RUN echo "alias ipr='ip -4 ro ; ip -6 ro ; ip -M ro'" >> /root/.bashrc

COPY --from=build /usr/src/holo/holo-daemon/holod.toml /etc/holod.toml
COPY --from=build /usr/src/holo/target/release/holod /usr/local/sbin/
COPY --from=build /usr/src/holo-cli/target/release/holo-cli /usr/local/sbin/

ENV RUST_BACKTRACE=1
ENV RUST_LOG=holo=debug

CMD ["sh", "-c", "holod 2>> /tmp/holod.err"]
