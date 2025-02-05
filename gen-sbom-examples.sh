#!/bin/bash

platform="linux/amd64"

for format in spdx-json \
              syft-json \
              cyclonedx-json \
              cyclonedx-xml \
              github-json; do
  shortformat=$(echo $format | awk -F '-' '{print $1}')
  sbomext=$(echo $format | awk -F '-' '{print $2}')
  for container in mcr.microsoft.com/azure-cognitive-services/vision/read:latest \
                   docker.io/huggingface/transformers-all-latest-torch-nightly-gpu:latest \
                   docker.io/nextcloud:latest \
                   docker.io/alpine:latest; do
    syftver=$(syft --version | awk -F ' ' '{print $2}')
    sbomfile=$(echo $container | tr '/' '_' | tr ':' '_')
    syft "$container" -o "$format"="syft"_"$syftver"_"$sbomfile"_"$shortformat"."$sbomext" "--platform=$platform"

  done

done
