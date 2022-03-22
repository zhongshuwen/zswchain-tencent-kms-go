FROM scratch
COPY zswchain-tecent-kms-go /usr/bin/zswchain-tecent-kms-go
ENTRYPOINT ["/usr/bin/zswchain-tecent-kms-go"]
