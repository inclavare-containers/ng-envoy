#include "source/extensions/transport_sockets/tls/cert_validator/default_validator.h"

#include <array>
#include <cstdint>
#include <deque>
#include <functional>
#include <string>
#include <utility>
#include <vector>

#include "envoy/common/pure.h"
#include "envoy/network/transport_socket.h"
#include "envoy/registry/registry.h"
#include "envoy/ssl/context.h"
#include "envoy/ssl/context_config.h"
#include "envoy/ssl/private_key/private_key.h"
#include "envoy/ssl/ssl_socket_extended_info.h"

#include "source/common/common/logger.h"
#include "source/common/common/matchers.h"
#include "source/common/stats/symbol_table.h"
#include "source/extensions/transport_sockets/tls/cert_validator/cert_validator.h"
#include "source/extensions/transport_sockets/tls/cert_validator/san_matcher.h"
#include "source/extensions/transport_sockets/tls/stats.h"

#include "absl/synchronization/mutex.h"
#include "openssl/ssl.h"
#include "openssl/x509v3.h"

#include "librats/api.h"
#include "librats/conf.h"

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
  const Envoy::Ssl::CertificateValidationContextConfig* config_;
  [[maybe_unused]] SslStats& stats_;
  [[maybe_unused]] TimeSource& time_source_;

  bool allow_untrusted_certificate_{false};
  bssl::UniquePtr<X509> ca_cert_;
  std::string ca_file_path_;
  std::vector<SanMatcherPtr> subject_alt_name_matchers_;
  std::vector<std::vector<uint8_t>> verify_certificate_hash_list_;
  std::vector<std::vector<uint8_t>> verify_certificate_spki_list_;
  [[maybe_unused]] bool verify_trusted_ca_{false};
};

DECLARE_FACTORY(LibratsCertValidatorFactory);

} // namespace Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
