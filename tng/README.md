## Usage

Build docker image

In root dir of this project, run
```shell
docker build -t tng-envoy:latest --target envoy -f tng/Dockerfile .
```

Then start an envoy with specified yaml and also DCAP qcnl config
```shell
docker run -d \
    --name envoy_test \
    --net=host --device=/dev/tdx_guest \
    -v <host-path-to-yaml>:/etc/envoy.yaml \
    -v <host-path-to-sgx_default_qcnl.conf>:/etc/sgx_default_qcnl.conf \
    tng-envoy:light
```