#!/bin/sh
goreleaser build --single-target --rm-dist --snapshot -o ./dist/zswchain-tecent-kms-go

source ./.env.sh
./dist/zswchain-tecent-kms-go
