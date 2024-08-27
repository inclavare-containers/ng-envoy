#include "source/common/rats_tls/worker.h"

namespace Envoy {
namespace Common {
namespace RatsTls {

RatsTlsWorker& getRatsTlsWorker(Api::Api& api) {
  static RatsTlsWorker worker = RatsTlsWorker(api);
  return worker;
}

RatsTlsWorker::RatsTlsWorker(Api::Api& api) {
  this->dispatcher_ = api.allocateDispatcher("rats_tls_worker");
  this->thread_ = api.threadFactory().createThread(
      [&]() -> void { this->dispatcher_->run(Event::Dispatcher::RunType::RunUntilExit); },
      Thread::Options{"rats_tls_worker"});
}

RatsTlsWorker::~RatsTlsWorker() {
  ENVOY_LOG(info, "~RatsTlsWorker() called, shutdown now");
  this->dispatcher_->post([this]() -> void {
    this->dispatcher_->shutdown();
    this->dispatcher_->exit();
  });
  this->thread_->join();
}

} // namespace RatsTls
} // namespace Common
} // namespace Envoy
