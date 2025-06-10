FROM rust:1.86 AS cargo-build

# Make and build stub
WORKDIR /usr/src/hello-world
COPY Cargo.toml Cargo.toml
RUN mkdir src/
RUN echo "fn main() {}" > src/main.rs
RUN cargo build --release

# Cleanup stub build
RUN rm -f target/release/deps/hello-world*

# Build release
COPY . .
ENV RUSTFLAGS="-C target-feature=+crt-static"
RUN cargo build --release --target x86_64-unknown-linux-gnu

# Prepare system dependencies for coping
RUN mkdir -p ./sys/lib/x86_64-linux-gnu/ && \
    cp /lib/x86_64-linux-gnu/libc.so.6 ./sys/lib/x86_64-linux-gnu/ && \
    mkdir -p ./sys/lib64/ && \
    cp /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 ./sys/lib64/ && \
    mkdir -p ./sys/bin/ && \
    cp /bin/sh ./sys/bin/

# Prepare Application dependencies for coping
RUN mkdir -p ./app/certs && \
    cp ./target/x86_64-unknown-linux-gnu/release/hello-world ./app/ && \
    cp ./certs/* ./app/certs/


# Main image
FROM scratch

ARG UID=1000
ARG GID=1000
ARG APPPATH=/app
ENV HTTP_BIND_ADDRESS=0.0.0.0 \
    HTTP_BIND_PORT=3000 \
    HTTP_THREADS=4 \
    HTTP_TLS_CERT=./certs/localhost.crt \
    HTTP_TLS_KEY=./certs/localhost.key

COPY --from=cargo-build /usr/src/hello-world/sys/ /

WORKDIR $APPPATH
USER ${UID}:${GID}
COPY --from=cargo-build --chown=${UID}:${GID} /usr/src/hello-world/app/ ./

EXPOSE 3000/tcp
ENTRYPOINT ["./hello-world"]