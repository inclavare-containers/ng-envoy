#include "source/extensions/transport_sockets/tls/cert_validator/librats_validator.h"

#include <array>
#include <functional>
#include <string>
#include <vector>
#include <map>

#include "envoy/network/transport_socket.h"
#include "envoy/ssl/context.h"
#include "envoy/ssl/context_config.h"
#include "envoy/ssl/private_key/private_key.h"
#include "envoy/ssl/ssl_socket_extended_info.h"
#include "envoy/extensions/transport_sockets/tls/v3/tls_librats_config.pb.h"

#include "source/common/common/assert.h"
#include "source/common/common/fmt.h"
#include "source/common/common/hex.h"
#include "source/common/config/utility.h"
#include "source/common/protobuf/message_validator_impl.h"
#include "source/extensions/transport_sockets/tls/cert_validator/cert_validator.h"
#include "source/extensions/transport_sockets/tls/cert_validator/factory.h"
#include "source/extensions/transport_sockets/tls/cert_validator/utility.h"
#include "source/extensions/transport_sockets/tls/stats.h"
#include "source/extensions/transport_sockets/tls/utility.h"

#include "openssl/bio.h"
#include "openssl/x509v3.h"
#include "librats/api.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {
using LibratsCertValidatorConfig =
    envoy::extensions::transport_sockets::tls::v3::LibratsCertValidatorConfig;

LibratsCertValidator::LibratsCertValidator(
    const Envoy::Ssl::CertificateValidationContextConfig* config, SslStats& stats,
    TimeSource& time_source)
    : DefaultCertValidator(config, stats, time_source), config_(config), stats_(stats){};

int LibratsCertValidator::initializeSslContexts(std::vector<SSL_CTX*> contexts,
                                                bool provides_certificates) {
  [[maybe_unused]] auto& ctx = contexts;
  [[maybe_unused]] bool tpp = provides_certificates;
  return SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
}

int verifyClaimsCallback(claim_t* claims_from_peer, size_t claims_from_peer_size, void* args_in) {
  auto& logger = Envoy::Logger::Registry::getLog(Envoy::Logger::Id::connection);

  auto claims_in_config = *reinterpret_cast<std::map<std::string, std::vector<uint8_t>>*>(args_in);
  ENVOY_LOG_TO_LOGGER(logger, debug,
                      "start checking claims, number of cliams from peer: {}, number of claims "
                      "in user config: {}",
                      claims_from_peer_size, claims_in_config.size());

  for (size_t i = 0; i < claims_from_peer_size; ++i) {
    auto it = claims_in_config.find(claims_from_peer[i].name);
    if (it == claims_in_config.end()) {
      // if claim name was not found in config, we just skip it.
      continue;
    }
    if (it->second.size() != claims_from_peer[i].value_size ||
        std::equal(it->second.begin(), it->second.end(), claims_from_peer[i].value)) {
      // or else, the claim value must be equal.
      ENVOY_LOG_TO_LOGGER(
          logger, debug,
          "claim mismatch detected, with claim name: {}\n\t\t\tclaim value from "
          "peer:\t{}\n\t\t\tcalim value in config:\t{}",
          it->first, Envoy::Hex::encode(it->second),
          Envoy::Hex::encode(claims_from_peer[i].value, claims_from_peer[i].value_size));
      return 1;
    }
    claims_in_config.erase(it);
  }

  if (!claims_in_config.empty()) {
    std::vector<std::string> keys;
    keys.reserve(claims_in_config.size());
    for (const auto& it : claims_in_config) {
      keys.push_back(it.first);
    }
    ENVOY_LOG_TO_LOGGER(
        logger, debug,
        "{} claims are found in config but not provided by peer. name of those claims are {}",
        claims_in_config.size(), keys);
    return 1;
  }
  ENVOY_LOG_TO_LOGGER(logger, debug,
                      "all claims from the peer match the claims in the configuration file");
  return 0;
}

void logSslErrorChain() {
  while (uint64_t err = ERR_get_error()) {
    ENVOY_LOG_MISC(debug, "SSL error: {}:{}:{}:{}:{}", err,
                   absl::NullSafeStringView(ERR_lib_error_string(err)),
                   absl::NullSafeStringView(ERR_func_error_string(err)), ERR_GET_REASON(err),
                   absl::NullSafeStringView(ERR_reason_error_string(err)));
  }
}

bool x509ToDer(X509* cert, std::string& der_cert) {
  // Create a BIO object to hold the DER certificate
  BIO* bio = BIO_new(BIO_s_mem());
  RELEASE_ASSERT(bio != nullptr, "");

  // Write the X509 certificate to the BIO object in DER format
  if (i2d_X509_bio(bio, cert) != 1) {
    BIO_free(bio);
    logSslErrorChain();
    return false;
  }

  // Get the DER certificate from the BIO object
  BUF_MEM* mem = nullptr;
  BIO_get_mem_ptr(bio, &mem);
  if (mem == nullptr) {
    BIO_free(bio);
    logSslErrorChain();
    return false;
  }

  der_cert = std::string(mem->data, mem->length);
  BIO_free(bio);

  return true;
}

ValidationResults LibratsCertValidator::doVerifyCertChain(
    STACK_OF(X509)& cert_chain, Ssl::ValidateResultCallbackPtr /*callback*/,
    [[maybe_unused]] const Network::TransportSocketOptionsConstSharedPtr& transport_socket_options,
    [[maybe_unused]] SSL_CTX& ssl_ctx,
    const CertValidator::ExtraValidationContext& /*validation_context*/,
    [[maybe_unused]] bool is_server, absl::string_view /*host_name*/) {

  ENVOY_LOG(info, "librats preparing for verifing cert chain");

  LibratsCertValidatorConfig validator_config;
  // TODO: maybe check if customValidatorConfig is not empty
  Config::Utility::translateOpaqueConfig(config_->customValidatorConfig().value().typed_config(),
                                         ProtobufMessage::getStrictValidationVisitor(),
                                         validator_config);

  // TODO: extract duplicate code into a single function
  // Parse librats log level
  rats_conf_t conf = {};
  auto& log_level = validator_config.log_level();
  if (log_level == "debug") {
    conf.log_level = RATS_LOG_LEVEL_DEBUG;
  } else if (log_level == "info") {
    conf.log_level = RATS_LOG_LEVEL_INFO;
  } else if (log_level == "warn") {
    conf.log_level = RATS_LOG_LEVEL_WARN;
  } else if (log_level == "error") {
    conf.log_level = RATS_LOG_LEVEL_ERROR;
  } else if (log_level == "fatal") {
    conf.log_level = RATS_LOG_LEVEL_FATAL;
  } else if (log_level == "off") {
    conf.log_level = RATS_LOG_LEVEL_NONE;
  } else {
    if (!log_level.empty()) {
      ENVOY_LOG(warn, "bad librats logging level '{}', default level will be selected", log_level);
    }
    conf.log_level = RATS_LOG_LEVEL_DEFAULT;
  }
  ENVOY_LOG(debug, "librats: conf.log_level: {}", conf.log_level);

  auto& static_policy = validator_config.static_policy();

  // set verifier type
  strncpy(conf.verifier_type, static_policy.verifier().c_str(), sizeof(conf.verifier_type) - 1);
  ENVOY_LOG(debug, "librats: conf.verifier_type: {}", conf.verifier_type);

  std::map<std::string, std::vector<uint8_t>> claims;
  for (const auto& claim : static_policy.claims()) {
    // Convert claim value from hex ("0102030a0b0c") to bytes
    auto value = Envoy::Hex::decode(claim.second);
    if (!claim.second.empty() && value.empty()) {
      stats_.fail_verify_error_.inc();
      auto error =
          fmt::format("failed to parsing value of claim with name '{}' as hex string", claim.first);
      ENVOY_LOG(debug, error);
      return ValidationResults{ValidationResults::ValidationStatus::Failed,
                               Envoy::Ssl::ClientValidationStatus::Failed, absl::nullopt, error};
    }
    claims[claim.first] = value;
  }

  // get certificate and convert to DER format
  if (sk_X509_num(&cert_chain) != 1) {
    stats_.fail_verify_error_.inc();
    auto error = fmt::format("verify cert failed: depth of cert chain chould be 1, but got {}",
                             sk_X509_num(&cert_chain));
    ENVOY_LOG(debug, error);
    return ValidationResults{ValidationResults::ValidationStatus::Failed,
                             Envoy::Ssl::ClientValidationStatus::Failed, SSL_AD_BAD_CERTIFICATE,
                             error};
  }

  X509* leaf_cert = sk_X509_value(&cert_chain, 0);
  ASSERT(leaf_cert);

  std::string certificate;
  if (!x509ToDer(leaf_cert, certificate)) {
    stats_.fail_verify_error_.inc();
    auto error =
        fmt::format("verify cert failed: failed to encode openssl X509 cert to DER binary");
    ENVOY_LOG(debug, error);
    return ValidationResults{ValidationResults::ValidationStatus::Failed,
                             Envoy::Ssl::ClientValidationStatus::Failed, SSL_AD_BAD_CERTIFICATE,
                             error};
  }

  // verify cert with librats
  rats_verifier_err_t rats_ret = librats_verify_attestation_certificate(
      conf, reinterpret_cast<uint8_t*>(const_cast<char*>(certificate.c_str())), certificate.size(),
      verifyClaimsCallback, &claims);

  if (rats_ret != RATS_VERIFIER_ERR_NONE) {
    stats_.fail_verify_error_.inc();
    auto error = fmt::format("librats verify certificate failed: {:#X}", rats_ret);
    ENVOY_LOG(debug, error);
    return ValidationResults{ValidationResults::ValidationStatus::Failed,
                             Envoy::Ssl::ClientValidationStatus::Failed, SSL_AD_CERTIFICATE_UNKNOWN,
                             error};
  }

  ENVOY_LOG(debug, "librats verify certificate success");
  return ValidationResults{ValidationResults::ValidationStatus::Successful,
                           Envoy::Ssl::ClientValidationStatus::Validated, absl::nullopt,
                           absl::nullopt};
}

class LibratsCertValidatorFactory : public CertValidatorFactory {
public:
  CertValidatorPtr createCertValidator(const Envoy::Ssl::CertificateValidationContextConfig* config,
                                       SslStats& stats, TimeSource& time_source) override {
    return std::make_unique<LibratsCertValidator>(config, stats, time_source);
  }

  std::string name() const override { return "envoy.tls.cert_validator.librats"; }
};

REGISTER_FACTORY(LibratsCertValidatorFactory, CertValidatorFactory);

} // namespace Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
