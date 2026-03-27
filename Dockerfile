FROM alpine:3.21@sha256:c3f8e73fdb79deaebaa2037150150191b9dcbfba68b4a46d70103204c53f4709

RUN apk add --no-cache ca-certificates tzdata

ARG TARGETPLATFORM
COPY $TARGETPLATFORM/closedsspm /usr/local/bin/closedsspm
COPY $TARGETPLATFORM/closedsspm-mcp /usr/local/bin/closedsspm-mcp
COPY entrypoint.sh /entrypoint.sh

USER nobody:nobody

ENTRYPOINT ["closedsspm"]
