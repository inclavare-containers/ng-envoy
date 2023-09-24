#include "source/common/secret/librats_secret_provider_impl.h"

#include <cstddef>
#include <cstdint>
#include <string>

#include "envoy/extensions/transport_sockets/tls/v3/cert.pb.h"

#include "source/common/common/assert.h"
#include "source/common/common/hex.h"
#include "source/common/ssl/certificate_validation_context_config_impl.h"
#include "source/common/ssl/tls_certificate_config_impl.h"

#include "openssl/x509.h"
#include "openssl/bio.h"
#include "openssl/pem.h"
#include "openssl/rsa.h"
#include "openssl/err.h"
#include "librats/api.h"

namespace Envoy {
namespace Secret {

LibratsTlsCertificateConfigProviderImpl::LibratsTlsCertificateConfigProviderImpl(
    const envoy::extensions::transport_sockets::tls::v3::LibratsCertificate&
        tls_certificates_librats_config)
    : tls_certificates_librats_config_(
          std::make_unique<envoy::extensions::transport_sockets::tls::v3::LibratsCertificate>(
              tls_certificates_librats_config)),
      tls_certificate_(
          std::make_unique<envoy::extensions::transport_sockets::tls::v3::TlsCertificate>()) {}

const envoy::extensions::transport_sockets::tls::v3::TlsCertificate*
LibratsTlsCertificateConfigProviderImpl::secret() const {
  ENVOY_LOG(info, "librats generating X509 cert");

  rats_conf_t conf = {};
  auto& log_level = tls_certificates_librats_config_->log_level();
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

  strncpy(conf.attester_type, tls_certificates_librats_config_->attester().c_str(),
          sizeof(conf.attester_type) - 1);
  ENVOY_LOG(debug, "librats: conf.attester_type: {}", conf.attester_type);

  bool provide_endorsements = tls_certificates_librats_config_->provide_endorsements();
  ENVOY_LOG(debug, "librats: provide_endorsements: {}", provide_endorsements);

  rats_cert_subject_t subject_name = {};
  subject_name.organization = "Inclavare Containers";
  subject_name.common_name = "LibRATS";

  std::vector<claim_t> claims;
  std::vector<std::vector<uint8_t>> claim_values; // used to temporarily hold all claim values
  for (const auto& custom_claim : tls_certificates_librats_config_->custom_claims()) {
    claim_t t = {};
    t.name = const_cast<char*>(custom_claim.first.c_str());
    // Convert claim value from hex ("0102030a0b0c") to bytes
    auto value = Envoy::Hex::decode(custom_claim.second);
    if (!custom_claim.second.empty() && value.empty()) {
      ENVOY_LOG(error, "failed to parsing value of claim with name '{}' as hex string",
                custom_claim.first);
      return nullptr;
    }
    t.value = reinterpret_cast<uint8_t*>(reinterpret_cast<char*>(value.data()));
    t.value_size = value.size();
    claims.emplace_back(t);

    claim_values.emplace_back(std::move(value));
  }

  uint8_t* p_private_key = nullptr;
  size_t private_key_size = 0;
  uint8_t* p_certificate = nullptr;
  size_t certificate_size = 0;
  rats_attester_err_t ret = RATS_ATTESTER_ERR_UNKNOWN;
  ENVOY_LOG(debug, "call librats_get_attestation_certificate() begin");
  ret = librats_get_attestation_certificate(conf, subject_name, &p_private_key, &private_key_size,
                                            &claims[0], claims.size(), provide_endorsements,
                                            &p_certificate, &certificate_size);
  ENVOY_LOG(debug, "call librats_get_attestation_certificate() returned with ret: {:#X}", ret);
  if (ret != RATS_ATTESTER_ERR_NONE) {
    ENVOY_LOG(error, "failed to generate certificate {:#X}", ret);
    return nullptr;
  }
  // Wrapping c allocated buffers with std::string so then can be released before function return
  std::string private_key;
  private_key.assign(reinterpret_cast<char*>(p_private_key), private_key_size);
  std::string certificate;
  certificate.assign(reinterpret_cast<char*>(p_certificate), certificate_size);

  std::string pem_cert;
  if (!this->certDerToPem(certificate, pem_cert)) {
    return nullptr;
  }
  ENVOY_LOG(debug, "got PEM cert, size: {}", pem_cert.size());

  envoy::config::core::v3::DataSource* ds_cert_chain = new envoy::config::core::v3::DataSource();
  envoy::config::core::v3::DataSource* ds_private_key = new envoy::config::core::v3::DataSource();
  ds_cert_chain->set_inline_bytes(std::move(pem_cert));
  ds_private_key->set_inline_bytes(std::move(private_key));
  tls_certificate_->set_allocated_certificate_chain(ds_cert_chain);
  tls_certificate_->set_allocated_private_key(ds_private_key);

  ENVOY_LOG(info, "X509 cert generated successfully");
  // TODO: ensure that old tls_certificate_ content will not be used after call sercet() second
  // time.
  return tls_certificate_.get();
}

void logSslErrorChain() {
  while (uint64_t err = ERR_get_error()) {
    ENVOY_LOG_MISC(debug, "SSL error: {}:{}:{}:{}:{}", err,
                   absl::NullSafeStringView(ERR_lib_error_string(err)),
                   absl::NullSafeStringView(ERR_func_error_string(err)), ERR_GET_REASON(err),
                   absl::NullSafeStringView(ERR_reason_error_string(err)));
  }
}

bool LibratsTlsCertificateConfigProviderImpl::certDerToPem(const std::string& der_cert,
                                                           std::string& pem_cert) const {
  X509* cert = nullptr;
  auto p = reinterpret_cast<const uint8_t*>(der_cert.c_str());
  cert = d2i_X509(nullptr, &p, static_cast<long>(der_cert.size()));
  if (cert == nullptr) {
    ENVOY_LOG(error, "failed to convert cert from DER format to PEM");
    logSslErrorChain();
    return false;
  }
  BIO* mem_bio = BIO_new(BIO_s_mem());
  RELEASE_ASSERT(mem_bio != nullptr, "");
  RELEASE_ASSERT(PEM_write_bio_X509(mem_bio, cert) == 1, "");
  char* pem_cert_buf;
  long pem_cert_len = BIO_get_mem_data(mem_bio, &pem_cert_buf);
  pem_cert = std::string(pem_cert_buf, pem_cert_len); // copy from BIO to here

  BIO_free(mem_bio);
  X509_free(cert);
  return true;
}

} // namespace Secret
} // namespace Envoy
