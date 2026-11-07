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

# The recipe and the tree are placed by the driver (helper.py copies the
# project into $SRC and runs `bash $SRC/build.sh`); nothing to COPY here.
WORKDIR $SRC
