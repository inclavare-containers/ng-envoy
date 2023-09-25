#include "source/common/common/logger.h"
#include "source/extensions/transport_sockets/tls/cert_validator/default_validator.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {

class LibratsCertValidator : public DefaultCertValidator {
public:
  LibratsCertValidator(const Envoy::Ssl::CertificateValidationContextConfig* config,
                       SslStats& stats, TimeSource& time_source);

  ~LibratsCertValidator() override = default;

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
    static spdlog::logger& instance = Envoy::Logger::Registry::getLog(Logger::Id::connection);
    return instance;
  }

  const Envoy::Ssl::CertificateValidationContextConfig* config_;
  SslStats& stats_;
};

DECLARE_FACTORY(LibratsCertValidatorFactory);

} // namespace Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
