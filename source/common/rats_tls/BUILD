load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
    "envoy_package",
)

licenses(["notice"])  # Apache 2

envoy_package()

envoy_cc_library(
    name = "worker_lib",
    srcs = [
        "worker.cc",
    ],
    hdrs = [
        "worker.h",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//envoy/api:api_interface",
        "//source/common/common:assert_lib",
        "//source/common/common:minimal_logger_lib",
        "//source/common/common:utility_lib",
    ],
)

envoy_cc_library(
    name = "attestation_info_lib",
    srcs = [
        "attestation_info.cc",
    ],
    hdrs = [
        "attestation_info.h",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//envoy/api:api_interface",
        "//source/common/common:assert_lib",
        "//source/common/common:minimal_logger_lib",
        "//source/common/common:utility_lib",
    ],
)
