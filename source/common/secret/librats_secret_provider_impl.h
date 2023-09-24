#include <functional>

#include "envoy/extensions/transport_sockets/tls/v3/cert.pb.h"
#include "envoy/secret/secret_provider.h"
#include "envoy/ssl/certificate_validation_context_config.h"
#include "envoy/ssl/tls_certificate_config.h"

#include "source/common/secret/secret_provider_impl.h"
#include "source/common/common/logger.h"

namespace Envoy {
namespace Secret {

class LibratsTlsCertificateConfigProviderImpl : public TlsCertificateConfigProvider,
                                                Logger::Loggable<Logger::Id::config> {
public:
  LibratsTlsCertificateConfigProviderImpl(
      const envoy::extensions::transport_sockets::tls::v3::LibratsCertificate&
          tls_certificates_librats_config);

  const envoy::extensions::transport_sockets::tls::v3::TlsCertificate* secret() const override;

  ABSL_MUST_USE_RESULT Common::CallbackHandlePtr addValidationCallback(
      std::function<void(const envoy::extensions::transport_sockets::tls::v3::TlsCertificate&)>)
      override {
    return nullptr;
  }

  ABSL_MUST_USE_RESULT Common::CallbackHandlePtr addUpdateCallback(std::function<void()>) override {
    return nullptr;
  }

private:
  bool certDerToPem(const std::string& der_cert, std::string& pem_cert) const;

  Secret::LibratsCertificatePtr tls_certificates_librats_config_;
  Secret::TlsCertificatePtr tls_certificate_;
};

} // namespace Secret
} // namespace Envoy
