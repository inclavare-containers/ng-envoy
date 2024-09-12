#pragma once

#include <functional>
#include <memory>

#include "source/common/common/logger.h"
#include "envoy/api/api.h"

namespace Envoy {
namespace Common {
namespace RatsTls {

class RatsTlsWorker : Logger::Loggable<Logger::Id::rats_tls> {

public:
  RatsTlsWorker(Api::Api& api);
  RatsTlsWorker(const RatsTlsWorker&) = delete;
  RatsTlsWorker& operator=(RatsTlsWorker&) = delete;
  ~RatsTlsWorker();
  Event::Dispatcher& dispatcher() { return *this->dispatcher_; }

private:
  Event::DispatcherPtr dispatcher_;
  Thread::ThreadPtr thread_;
};

std::unique_ptr<RatsTlsWorker> allocateRatsTlsWorker(Api::Api& api);

} // namespace RatsTls
} // namespace Common
} // namespace Envoy
