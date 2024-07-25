FROM envoyproxy/envoy-build-ubuntu:26c6bcc3af3d6ad166c42b550de672d40209bc1c as builder

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


FROM ubuntu:22.04 as envoy

ENV SGX_DCAP_VERSION 1.20

# copy envoy-static
COPY --from=builder /home/newuser/envoy/bazel-bin/source/exe/envoy-static /usr/local/bin/envoy-static

# copy dependencies
COPY --from=rats-rs:builder-c-api /usr/local/lib/rats-rs/ /usr/local/lib/rats-rs/

CMD ["envoy-static", "-c", "/etc/envoy.yaml", "-l", "off", "--component-log-level", "upstream:error,connection:debug,rats-rs:debug"]
