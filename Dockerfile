FROM alpine:3.23.4@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11

RUN apk add --no-cache ca-certificates tzdata && \
    apk upgrade --no-cache

ARG TARGETPLATFORM
COPY $TARGETPLATFORM/closedsspm /usr/local/bin/closedsspm
COPY $TARGETPLATFORM/closedsspm-mcp /usr/local/bin/closedsspm-mcp
COPY entrypoint.sh /entrypoint.sh

USER nobody:nobody

ENTRYPOINT ["closedsspm"]
