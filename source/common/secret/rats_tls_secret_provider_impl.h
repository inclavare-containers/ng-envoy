#include <functional>

#include "envoy/extensions/transport_sockets/tls/v3/cert.pb.h"
#include "envoy/extensions/transport_sockets/tls/v3/rats_tls.pb.h"
#include "envoy/secret/secret_provider.h"
#include "envoy/ssl/certificate_validation_context_config.h"
#include "envoy/ssl/tls_certificate_config.h"

#include "source/common/rats_tls/worker.h"
#include "source/common/common/callback_impl.h"
#include "source/common/secret/secret_provider_impl.h"
#include "source/common/common/logger.h"
#include "envoy/api/api.h"

namespace Envoy {
namespace Secret {

class RatsTlsCertificateConfigProviderImpl;

class RatsTlsCertificateUpdater : Logger::Loggable<Logger::Id::rats_tls>,
                                  public std::enable_shared_from_this<RatsTlsCertificateUpdater> {
  friend class RatsTlsCertificateConfigProviderImpl;

public:
  RatsTlsCertificateUpdater(
      Api::Api& api, Event::Dispatcher& main_thread_dispatcher,
      const envoy::extensions::transport_sockets::tls::v3::RatsTlsCertGeneratorConfig&
          rats_tls_cert_generator_config);

private:
  void enableUpdater();
  std::unique_ptr<envoy::extensions::transport_sockets::tls::v3::TlsCertificate>
  generateCertOnceBlocking() const;

  Secret::RatsTlsCertGeneratorConfigPtr rats_tls_cert_generator_config_;
  Api::Api& api_;
  Event::Dispatcher& main_thread_dispatcher_;
  std::unique_ptr<Common::RatsTls::RatsTlsWorker> rats_tls_worker_;
  Event::Dispatcher& rats_tls_worker_dispatcher_;
  std::shared_ptr<Common::ThreadSafeCallbackManager> update_callback_manager_;
  Secret::TlsCertificatePtr tls_certificate_;
  Event::TimerPtr cert_update_timer_;
};

class RatsTlsCertificateConfigProviderImpl : public TlsCertificateConfigProvider,
                                             Logger::Loggable<Logger::Id::rats_tls> {
public:
  RatsTlsCertificateConfigProviderImpl(
      Api::Api& api, Event::Dispatcher& main_thread_dispatcher,
      const envoy::extensions::transport_sockets::tls::v3::RatsTlsCertGeneratorConfig&
          rats_tls_cert_generator_config);

  const envoy::extensions::transport_sockets::tls::v3::TlsCertificate* secret() const override;

  ABSL_MUST_USE_RESULT Common::CallbackHandlePtr addValidationCallback(
      std::function<void(const envoy::extensions::transport_sockets::tls::v3::TlsCertificate&)>)
      override {
    return nullptr;
  }

  ABSL_MUST_USE_RESULT Common::CallbackHandlePtr
  addUpdateCallback(std::function<void()> callback) override {
    if (secret()) {
      callback();
    }
    return this->cert_updater_->update_callback_manager_->add(
        this->cert_updater_->main_thread_dispatcher_,
        callback); // Currently we update secret in cert-updater thread
  }

private:
  std::shared_ptr<RatsTlsCertificateUpdater> cert_updater_;
};

} // namespace Secret
} // namespace Envoy
