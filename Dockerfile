FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

RUN apk add --no-cache ca-certificates tzdata && \
    apk upgrade --no-cache

ARG TARGETPLATFORM
COPY $TARGETPLATFORM/closedsspm /usr/local/bin/closedsspm
COPY $TARGETPLATFORM/closedsspm-mcp /usr/local/bin/closedsspm-mcp
COPY entrypoint.sh /entrypoint.sh

USER nobody:nobody

ENTRYPOINT ["closedsspm"]
