FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata

COPY closedsspm /usr/local/bin/closedsspm
COPY closedsspm-mcp /usr/local/bin/closedsspm-mcp

USER nobody:nobody

ENTRYPOINT ["closedsspm"]
