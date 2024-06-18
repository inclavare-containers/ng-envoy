FROM envoyproxy/envoy-build-ubuntu:75238004b0fcfd8a7f71d380d7a774dda5c39622 as builder

ENV DEBIAN_FRONTEND noninteractive

# Copy rats-rs products as dependency
COPY --from=rats-rs:builder-c-api /usr/local/include/rats-rs /usr/local/include/rats-rs
COPY --from=rats-rs:builder-c-api /usr/local/lib/rats-rs/ /usr/local/lib/rats-rs/

# prepare envoy source code
RUN useradd -m -s /bin/bash newuser
WORKDIR /home/newuser/envoy
COPY . .
RUN chown -R newuser:newuser .
USER newuser

# build envoy
RUN bazel/setup_clang.sh /opt/llvm/
RUN echo "build --config=clang" >> user.bazelrc
RUN bazel build -c opt envoy
RUN chmod 0777 bazel-bin/source/exe/envoy-static && \
    strip bazel-bin/source/exe/envoy-static


FROM ubuntu:20.04 as envoy

ENV SGX_DCAP_VERSION 1.20

# copy envoy-static
COPY --from=builder /home/newuser/envoy/bazel-bin/source/exe/envoy-static /usr/local/bin/envoy-static

# copy dependencies
COPY --from=rats-rs:builder-c-api /usr/local/lib/rats-rs/ /usr/local/lib/rats-rs/

RUN apt-get update && \
    apt-get install curl gnupg -y && \
    curl -L https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | tee intel-sgx-deb.key | apt-key add - && \
    echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' | tee /etc/apt/sources.list.d/intel-sgx.list && \
    apt-get update && \
    apt-get install -y \
        libsgx-dcap-default-qpl-dev="$SGX_DCAP_VERSION*" \
        libsgx-dcap-default-qpl="$SGX_DCAP_VERSION*" \
        libsgx-dcap-quote-verify-dev="$SGX_DCAP_VERSION*" \
        libsgx-dcap-quote-verify="$SGX_DCAP_VERSION*" \
        libtdx-attest-dev="$SGX_DCAP_VERSION*" \
        libtdx-attest="$SGX_DCAP_VERSION*" \
        && \
    rm -rf /var/lib/apt/lists/* && \
    rm -rf intel-sgx-deb.key

VOLUME [ "/etc/sgx_default_qcnl.conf", "/etc/envoy.yaml" ]
CMD ["envoy-static", "-c", "/etc/envoy.yaml", "-l", "off", "--component-log-level", "upstream:error,connection:debug,rats-rs:debug"]
