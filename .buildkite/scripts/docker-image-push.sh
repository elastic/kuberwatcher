#!/bin/bash
set -eo pipefail

set +x

DOCKER_PASSWORD=$(vault read -field password secret/infra/prod/flavorchef)

docker login -u flavorchef -p $DOCKER_PASSWORD docker.elastic.co

unset DOCKER_PASSWORD
set -x

make deploy