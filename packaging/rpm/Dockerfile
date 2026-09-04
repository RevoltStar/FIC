FROM registry.altlinux.org/p11/alt:latest

ENV LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

RUN sed -i '/^rpm /s/^/#/' /etc/apt/sources.list.d/alt.list \
    && sed -i '/^#rpm \[p11\] http:/s/^#//' /etc/apt/sources.list.d/yandex.list \
    && apt-get update && apt-get install -y \
    cmake \
    gcc-c++ \
    glibc-devel \
    libglvnd-devel \
    libpam0-devel \
    libsqlite3-devel \
    libsystemd-devel \
    make \
    nlohmann-json-devel \
    openssl-devel \
    pkg-config \
    python3 \
    qt6-base-devel \
    rpm-build \
    xauth \
    xvfb-run \
    && apt-get clean && rm -rf /var/cache/apt/archives/*

WORKDIR /workspace

CMD ["bash"]
