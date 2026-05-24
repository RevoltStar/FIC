FROM alt:p11

RUN apt-get update && apt-get install -y \
    cmake \
    gcc-c++ \
    glibc-devel \
    libglvnd-devel \
    libsqlite3-devel \
    make \
    nlohmann-json-devel \
    openssl-devel \
    pkg-config \
    qt6-base-devel \
    rpm-build \
    && apt-get clean && rm -rf /var/cache/apt/archives/*

WORKDIR /workspace

CMD ["bash"]
