# Build image for ArangoDB's in-tree libFuzzer harnesses (fuzz/).
#
# db-fuzz builds this with the oss-fuzz base image and runs fuzz/build.sh
# inside. The packages are the server's configure-time dependencies: flex and
# bison generate the AQL lexer/parser, OpenMP and BLAS/LAPACK are found by
# find_package at configure time even though no fuzz target links them
# (3rdParty is EXCLUDE_FROM_ALL), and ninja is the generator the recipe uses.
FROM gcr.io/oss-fuzz-base/base-builder:ubuntu-24-04

RUN apt-get update && apt-get install -y --no-install-recommends \
        flex \
        bison \
        libopenblas-dev \
        libomp-20-dev \
        ninja-build \
    && rm -rf /var/lib/apt/lists/*

# The image carries the recipe at $SRC/build.sh — the base image's `compile`
# entrypoint runs `bash -eux $SRC/build.sh` — and the tree is mounted by the
# driver at $SRC/$PROJECT_NAME, which build.sh resolves itself. No WORKDIR:
# helper.py refuses a local checkout when WORKDIR is $SRC.
COPY build.sh $SRC/
