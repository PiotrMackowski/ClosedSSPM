FROM alpine:3.21@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d

RUN apk add --no-cache ca-certificates tzdata && \
    apk upgrade --no-cache

ARG TARGETPLATFORM
COPY $TARGETPLATFORM/closedsspm /usr/local/bin/closedsspm
COPY $TARGETPLATFORM/closedsspm-mcp /usr/local/bin/closedsspm-mcp
COPY entrypoint.sh /entrypoint.sh

USER nobody:nobody

ENTRYPOINT ["closedsspm"]
