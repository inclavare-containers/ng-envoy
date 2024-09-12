#include "source/common/tls/cert_validator/rats_tls_validator.h"

#include <array>
#include <functional>
#include <memory>
#include <string>
#include <vector>
#include <map>
#include <thread>
#include <chrono>

#include "envoy/network/transport_socket.h"
#include "envoy/ssl/context.h"
#include "envoy/ssl/context_config.h"
#include "envoy/ssl/private_key/private_key.h"
#include "envoy/ssl/ssl_socket_extended_info.h"
#include "envoy/extensions/transport_sockets/tls/v3/rats_tls.pb.h"

#include "source/common/rats_tls/attestation_info.h"
#include "source/common/common/assert.h"
#include "source/common/common/fmt.h"
#include "source/common/common/hex.h"
#include "source/common/config/utility.h"
#include "source/common/protobuf/message_validator_impl.h"
#include "source/common/tls/cert_validator/cert_validator.h"
#include "source/common/tls/cert_validator/factory.h"
#include "source/common/tls/cert_validator/utility.h"
#include "source/common/tls/stats.h"
#include "source/common/tls/utility.h"
#include "source/common/buffer/buffer_impl.h"
#include "source/common/json/json_streamer.h"
#include "source/common/common/hex.h"

#include "openssl/pem.h"
#include "rats-rs/rats-rs.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {

constexpr const char* kTngFilterStateObjectName = "io.inclavare-containers.tng.authority";

std::unique_ptr<VerifyPolicy>
convertConfigToVerifyPolicy(const RatsTlsCertValidatorConfig& validator_config) {
  auto verify_policy = std::make_unique<VerifyPolicy>();

  if (validator_config.has_coco_verifier()) {
    auto& coco_verifier = validator_config.coco_verifier();

    // Preparing verify_mode
    rats_rs_coco_verify_mode_t verify_mode;
    if (coco_verifier.has_evidence_mode()) {
      auto& evidence_mode = coco_verifier.evidence_mode();
      verify_mode =
          rats_rs_coco_verify_mode_t{RATS_RS_COCO_VERIFY_MODE_EVIDENCE,
                                     {evidence_mode.as_addr().c_str(), evidence_mode.as_is_grpc()}};
    } else if (coco_verifier.has_token_mode()) {
      verify_mode = rats_rs_coco_verify_mode_t{RATS_RS_COCO_VERIFY_MODE_TOKEN, {}};
    } else {
      throw EnvoyException("One of the field `evidence_mode` and `token_mode` must be set");
    }

    // Preparing policy_ids
    if (coco_verifier.policy_ids_size() < 1 ||
        coco_verifier.policy_ids_size() > kMaxNumsOfPolicyIds) {
      throw EnvoyException(
          fmt::format("The num of `policy_ids` should be greater equal than 1 and no more than {}",
                      kMaxNumsOfPolicyIds));
    }
    for (int i = 0; i < coco_verifier.policy_ids_size(); ++i) {
      verify_policy->tmp_policy_ids[i] = coco_verifier.policy_ids(i).c_str();
    }

    // Preparing trusted_certs_paths
    if (coco_verifier.trusted_certs_paths_size() > kMaxNumsOfTrustedCertsPaths) {
      throw EnvoyException(fmt::format("The num of `trusted_certs_paths` should be no more than {}",
                                       kMaxNumsOfTrustedCertsPaths));
    }
    for (int i = 0; i < coco_verifier.trusted_certs_paths_size(); ++i) {
      verify_policy->tmp_trusted_certs_paths[i] = coco_verifier.trusted_certs_paths(i).c_str();
    }

    // Preparing verify_policy
    verify_policy->rats_rs_verify_policy.tag = RATS_RS_VERIFY_POLICY_COCO;
    verify_policy->rats_rs_verify_policy.COCO.verify_mode = verify_mode;
    verify_policy->rats_rs_verify_policy.COCO.policy_ids = verify_policy->tmp_policy_ids;
    verify_policy->rats_rs_verify_policy.COCO.policy_ids_len = coco_verifier.policy_ids_size();
    verify_policy->rats_rs_verify_policy.COCO.trusted_certs_paths =
        verify_policy->tmp_trusted_certs_paths;
    verify_policy->rats_rs_verify_policy.COCO.trusted_certs_paths_len =
        coco_verifier.trusted_certs_paths_size();
    verify_policy->rats_rs_verify_policy.COCO.claims_check.tag = RATS_RS_CLAIMS_CHECK_CONTAINS;
    // Currently custom claims was not supported in TNG, so we set `CONTAINS` to empty value here.
    verify_policy->rats_rs_verify_policy.COCO.claims_check.CONTAINS.claims = nullptr;
    verify_policy->rats_rs_verify_policy.COCO.claims_check.CONTAINS.claims_len = 0;
  } else {
    throw EnvoyException("The field `coco_verifier` must be set");
  }

  return verify_policy;
}

void RatsTlsCertValidatorInner::logSslErrorChain() {
  while (uint64_t err = ERR_get_error()) {
    ENVOY_LOG(error, "Got SSL error: {}:{}:{}:{}:{}", err,
              absl::NullSafeStringView(ERR_lib_error_string(err)),
              absl::NullSafeStringView(ERR_func_error_string(err)), ERR_GET_REASON(err),
              absl::NullSafeStringView(ERR_reason_error_string(err)));
  }
}

// Convert an OpenSSL X509 object to pem cert string
bool RatsTlsCertValidatorInner::x509ToPem(X509* cert, std::string& pem_cert) {
  // Create a BIO object to hold the PEM certificate
  BIO* bio = BIO_new(BIO_s_mem());
  RELEASE_ASSERT(bio != nullptr, "");

  // Write the X509 certificate to the BIO object in PEM format
  if (PEM_write_bio_X509(bio, cert) != 1) {
    BIO_free(bio);
    logSslErrorChain();
    return false;
  }

  // Get the PEM certificate from the BIO object
  BUF_MEM* mem = nullptr;
  BIO_get_mem_ptr(bio, &mem);
  if (mem == nullptr) {
    BIO_free(bio);
    logSslErrorChain();
    return false;
  }

  pem_cert = std::string(mem->data, mem->length);
  BIO_free(bio);

  return true;
}

RatsTlsCertValidatorInner::RatsTlsCertValidatorInner(
    const Envoy::Ssl::CertificateValidationContextConfig* config, SslStats& stats,
    Server::Configuration::CommonFactoryContext& context)
    : DefaultCertValidator(config, stats, context), stats_(stats),
      rats_tls_worker_(Envoy::Common::RatsTls::allocateRatsTlsWorker(context.api())),
      rats_tls_worker_dispatcher_(rats_tls_worker_->dispatcher()) {

  this->validator_config_ = std::make_unique<RatsTlsCertValidatorConfig>();
  if (!config->customValidatorConfig().has_value()) {
    throw EnvoyException("The field `custom_validator_config` must be set");
  }
  Config::Utility::translateOpaqueConfig(config->customValidatorConfig().value().typed_config(),
                                         ProtobufMessage::getStrictValidationVisitor(),
                                         *this->validator_config_);

  this->verify_policy_ = convertConfigToVerifyPolicy(*this->validator_config_);
};

int RatsTlsCertValidatorInner::initializeSslContexts(std::vector<SSL_CTX*> /* contexts */,
                                                     bool /* provides_certificates */) {
  return SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
}

rats_rs_verify_policy_output_t custom_verifier_func_cpp_wrapper(const rats_rs_claim_t* claims,
                                                                size_t claims_len, void* args) {
  return (
      *static_cast<std::function<rats_rs_verify_policy_output_t(const rats_rs_claim_t*, size_t)>*>(
          args))(claims, claims_len);
};

std::pair<ValidationResults, std::string>
RatsTlsCertValidatorInner::verifyRatsTlsCertPem(std::string& certificate,
                                                absl::optional<std::string>& authority) noexcept {
  // Verify cert with rats-rs
  rats_rs_verify_policy_output_t verify_policy_output = RATS_RS_VERIFY_POLICY_OUTPUT_FAILED;
  rats_rs_error_obj_t* rats_rs_error_obj = nullptr;

  Buffer::OwnedImpl attestation_info_buffer;
  Json::Streamer streamer{attestation_info_buffer};
  Json::Streamer::MapPtr attestation_info = streamer.makeRootMap();
  attestation_info->addKey("target_url");
  attestation_info->addString(
      authority.value_or("null")); // TODO: better way to handle case when authority is null
  attestation_info->addKey("trustee_url");
  if (this->verify_policy_->rats_rs_verify_policy.COCO.verify_mode.tag ==
      RATS_RS_COCO_VERIFY_MODE_EVIDENCE) {
    attestation_info->addString(
        this->verify_policy_->rats_rs_verify_policy.COCO.verify_mode.EVIDENCE.as_addr);
  } else {
    attestation_info->addString("null");
  }

  attestation_info->addKey("policy_ids");
  Json::Streamer::ArrayPtr policy_ids = attestation_info->addArray();
  for (size_t i = 0; i < this->verify_policy_->rats_rs_verify_policy.COCO.policy_ids_len; ++i) {
    policy_ids->addString(this->verify_policy_->rats_rs_verify_policy.COCO.policy_ids[i]);
  }
  policy_ids.reset();

  auto callback = std::function<rats_rs_verify_policy_output_t(const rats_rs_claim_t*, size_t)>(
      [&](const rats_rs_claim_t* c_claims, size_t c_claims_len) -> rats_rs_verify_policy_output_t {
        attestation_info->addKey("claims");
        Json::Streamer::MapPtr claims = attestation_info->addMap();
        for (size_t i = 0; i < c_claims_len; i++) {
          claims->addKey(c_claims[i].name);
          // TODO: change rats-rs api claim value type to string
          absl::string_view maybe_string(reinterpret_cast<const char*>(c_claims[i].value),
                                         c_claims[i].value_len);
          if (maybe_string == MessageUtil::sanitizeUtf8String(maybe_string)) {
            claims->addString(maybe_string);
          } else {
            claims->addString(Hex::encode(c_claims[i].value, c_claims[i].value_len));
          }
        }
        claims.reset();
        return RATS_RS_VERIFY_POLICY_OUTPUT_PASSED;
      });

  // Copy verify_policy and modify locally
  rats_rs_verify_policy_t rats_rs_verify_policy = this->verify_policy_->rats_rs_verify_policy;
  rats_rs_verify_policy.COCO.claims_check.tag = RATS_RS_CLAIMS_CHECK_CUSTOM;
  rats_rs_verify_policy.COCO.claims_check.CUSTOM.func = custom_verifier_func_cpp_wrapper;
  rats_rs_verify_policy.COCO.claims_check.CUSTOM.args = &callback;

  rats_rs_error_obj =
      rats_rs_verify_cert(reinterpret_cast<const uint8_t*>(certificate.c_str()), certificate.size(),
                          rats_rs_verify_policy, &verify_policy_output);

  if (rats_rs_error_obj == nullptr) {
    if (verify_policy_output == RATS_RS_VERIFY_POLICY_OUTPUT_PASSED) {
      ENVOY_LOG(debug, "The evaluation result of rats-tls cert is PASSED");
      attestation_info->addKey("is_secure");
      attestation_info->addBoolean(true);
      attestation_info.reset();
      return std::make_pair(ValidationResults{ValidationResults::ValidationStatus::Successful,
                                              Envoy::Ssl::ClientValidationStatus::Validated,
                                              absl::nullopt, absl::nullopt},
                            attestation_info_buffer.toString());
    } else {
      auto error_msg = "The evaluation result of rats-tls cert is FAILED";
      ENVOY_LOG(error, error_msg);
      stats_.fail_verify_error_.inc();
      attestation_info->addKey("msg");
      attestation_info->addString(error_msg);
      attestation_info->addKey("is_secure");
      attestation_info->addBoolean(false);
      attestation_info.reset();
      return std::make_pair(ValidationResults{ValidationResults::ValidationStatus::Failed,
                                              Envoy::Ssl::ClientValidationStatus::Failed,
                                              SSL_AD_BAD_CERTIFICATE, error_msg},
                            attestation_info_buffer.toString());
    }
  } else {
    stats_.fail_verify_error_.inc();
    rats_rs_error_msg_t rats_rs_error_msg = rats_rs_err_get_msg_ref(rats_rs_error_obj);
    auto error_msg = fmt::format(
        "Failed to verify rats-tls cert with rats-rs: Error kind: {:#x}, msg: {:.{}s}",
        rats_rs_err_get_kind(rats_rs_error_obj), rats_rs_error_msg.msg, rats_rs_error_msg.msg_len);
    rats_rs_err_free(rats_rs_error_obj);
    rats_rs_error_obj = nullptr;
    ENVOY_LOG(error, error_msg);
    attestation_info->addKey("msg");
    attestation_info->addString(error_msg);
    attestation_info->addKey("is_secure");
    attestation_info->addBoolean(false);
    attestation_info.reset();
    return std::make_pair(ValidationResults{ValidationResults::ValidationStatus::Failed,
                                            Envoy::Ssl::ClientValidationStatus::Failed,
                                            SSL_AD_BAD_CERTIFICATE, error_msg},
                          attestation_info_buffer.toString());
  }
}

ValidationResults RatsTlsCertValidatorInner::doVerifyCertChain(
    STACK_OF(X509)& cert_chain, Ssl::ValidateResultCallbackPtr callback,
    const Network::TransportSocketOptionsConstSharedPtr& transport_socket_options,
    SSL_CTX& /* ssl_ctx */, const CertValidator::ExtraValidationContext& /* validation_context */,
    bool /* is_server */, absl::string_view /* host_name */) {

  ENVOY_LOG(info, "Verifing rats-tls cert");

  // Get certificate and convert to DER format
  if (sk_X509_num(&cert_chain) != 1) {
    stats_.fail_verify_error_.inc();
    auto error_msg = fmt::format("verify cert failed: depth of cert chain should be 1, but got {}",
                                 sk_X509_num(&cert_chain));
    ENVOY_LOG(error, error_msg);
    return ValidationResults{ValidationResults::ValidationStatus::Failed,
                             Envoy::Ssl::ClientValidationStatus::Failed, SSL_AD_BAD_CERTIFICATE,
                             error_msg};
  }
  X509* leaf_cert = sk_X509_value(&cert_chain, 0);
  ASSERT(leaf_cert);
  std::string certificate; // Cert in PEM format
  if (!x509ToPem(leaf_cert, certificate)) {
    stats_.fail_verify_error_.inc();
    auto error_msg =
        fmt::format("Verify cert failed: failed to encode OpenSSL X509 cert in PEM format");
    ENVOY_LOG(error, error_msg);
    return ValidationResults{ValidationResults::ValidationStatus::Failed,
                             Envoy::Ssl::ClientValidationStatus::Failed, SSL_AD_BAD_CERTIFICATE,
                             error_msg};
  }

  // Get authority from filter state object
  absl::optional<std::string> authority = absl::nullopt;
  for (const auto& object : transport_socket_options->downstreamSharedFilterStateObjects()) {
    if (object.name_ == kTngFilterStateObjectName) {
      authority = object.data_->serializeAsString();
      ENVOY_LOG(debug, "The authority of target to be evaluated: {}", *authority);
      break;
    }
  }

  auto weak_self = weak_from_this();
  this->rats_tls_worker_dispatcher_.post([weak_self, certificate = std::move(certificate),
                                          authority = std::move(authority),
                                          callback = std::move(callback)]() mutable -> void {
    if (auto self = weak_self.lock()) {
      auto [result, attestation_info_str] = self->verifyRatsTlsCertPem(certificate, authority);

      Event::Dispatcher& dispatcher = callback->dispatcher();
      dispatcher.post([result = std::move(result),
                       attestation_info_str = std::move(attestation_info_str),
                       authority = std::move(authority), callback = std::move(callback)]() -> void {
        if (authority != absl::nullopt) {
          ENVOY_LOG(debug, "Now store attestation info for authority: {}, attestation_info: {}",
                    *authority, attestation_info_str);
          Envoy::Common::RatsTls::RatsTlsAttestationInfo::local_storage[*authority] =
              attestation_info_str;
        } else {
          ENVOY_LOG(debug, "The authority of this request is null, skip to store attestation info");
        }

        callback->onCertValidationResult(
            result.status == ValidationResults::ValidationStatus::Successful,
            result.detailed_status,
            (result.error_details.has_value() ? result.error_details.value() : ""),
            (result.tls_alert.has_value() ? result.tls_alert.value() : SSL_AD_CERTIFICATE_UNKNOWN));
      });
    } else {
      ENVOY_LOG(error, "The std::weak_ptr<RatsTlsCertValidatorInner> is empty and maybe released");
    }
  });

  return {ValidationResults::ValidationStatus::Pending,
          Envoy::Ssl::ClientValidationStatus::NotValidated, absl::nullopt, absl::nullopt};
}

class RatsTlsCertValidatorFactory : public CertValidatorFactory {
public:
  CertValidatorPtr
  createCertValidator(const Envoy::Ssl::CertificateValidationContextConfig* config, SslStats& stats,
                      Server::Configuration::CommonFactoryContext& context) override {
    return std::make_unique<RatsTlsCertValidator>(config, stats, context);
  }

  std::string name() const override { return "envoy.tls.cert_validator.rats_tls"; }
};

REGISTER_FACTORY(RatsTlsCertValidatorFactory, CertValidatorFactory);

} // namespace Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
