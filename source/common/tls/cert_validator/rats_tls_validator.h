#include "envoy/extensions/transport_sockets/tls/v3/rats_tls.pb.h"

#include "source/common/common/logger.h"
#include "source/common/tls/cert_validator/default_validator.h"
#include "source/common/rats_tls/worker.h"

#include "rats-rs/rats-rs.h"
#include <memory>

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {

constexpr int kMaxNumsOfPolicyIds = 16;
constexpr int kMaxNumsOfTrustedCertsPaths = 8;

using RatsTlsCertValidatorConfig =
    envoy::extensions::transport_sockets::tls::v3::RatsTlsCertValidatorConfig;

struct VerifyPolicy {
public:
  rats_rs_verify_policy_t rats_rs_verify_policy;
  const char* tmp_policy_ids[kMaxNumsOfPolicyIds];
  const char* tmp_trusted_certs_paths[kMaxNumsOfTrustedCertsPaths];
};

class RatsTlsCertValidatorInner : public DefaultCertValidator,
                                  public std::enable_shared_from_this<RatsTlsCertValidatorInner> {
public:
  RatsTlsCertValidatorInner(const Envoy::Ssl::CertificateValidationContextConfig* config,
                            SslStats& stats, Server::Configuration::CommonFactoryContext& context);

  ~RatsTlsCertValidatorInner() override = default;

  ValidationResults
  doVerifyCertChain(STACK_OF(X509)& cert_chain, Ssl::ValidateResultCallbackPtr callback,
                    const Network::TransportSocketOptionsConstSharedPtr& transport_socket_options,
                    SSL_CTX& ssl, const CertValidator::ExtraValidationContext& validation_context,
                    bool is_server, absl::string_view host_name) override;

  int initializeSslContexts(std::vector<SSL_CTX*> contexts, bool provides_certificates) override;

private:
  // Create this function since inheriting Logger::Loggable<Logger::Id::connection> directly leads
  // to ambiguity.
  static spdlog::logger& __log_do_not_use_read_comment() { // NOLINT(readability-identifier-naming)
    static spdlog::logger& instance = Envoy::Logger::Registry::getLog(Logger::Id::rats_tls);
    return instance;
  }

  static void logSslErrorChain();

  static bool x509ToPem(X509* cert, std::string& pem_cert);

  std::pair<ValidationResults, std::string>
  verifyRatsTlsCertPem(std::string& certificate, absl::optional<std::string>& authority) noexcept;

  std::unique_ptr<RatsTlsCertValidatorConfig> validator_config_;
  std::unique_ptr<VerifyPolicy> verify_policy_;
  SslStats& stats_;
  std::unique_ptr<Common::RatsTls::RatsTlsWorker> rats_tls_worker_;
  Event::Dispatcher& rats_tls_worker_dispatcher_;
};

class RatsTlsCertValidator : public DefaultCertValidator {
public:
  RatsTlsCertValidator(const Envoy::Ssl::CertificateValidationContextConfig* config,
                       SslStats& stats, Server::Configuration::CommonFactoryContext& context)
      : DefaultCertValidator(config, stats, context),
        inner_(std::make_shared<RatsTlsCertValidatorInner>(config, stats, context)){};

  ~RatsTlsCertValidator() override = default;

  ValidationResults
  doVerifyCertChain(STACK_OF(X509)& cert_chain, Ssl::ValidateResultCallbackPtr callback,
                    const Network::TransportSocketOptionsConstSharedPtr& transport_socket_options,
                    SSL_CTX& ssl, const CertValidator::ExtraValidationContext& validation_context,
                    bool is_server, absl::string_view host_name) override {
    return inner_->doVerifyCertChain(cert_chain, std::move(callback), transport_socket_options, ssl,
                                     validation_context, is_server, host_name);
  };

  int initializeSslContexts(std::vector<SSL_CTX*> contexts, bool provides_certificates) override {
    return inner_->initializeSslContexts(contexts, provides_certificates);
  };

private:
  std::shared_ptr<RatsTlsCertValidatorInner> inner_;
};

DECLARE_FACTORY(RatsTlsCertValidatorFactory);

} // namespace Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
