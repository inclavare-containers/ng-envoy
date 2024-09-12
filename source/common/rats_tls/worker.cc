#include "source/common/rats_tls/worker.h"
#include <memory>

namespace Envoy {
namespace Common {
namespace RatsTls {

std::unique_ptr<RatsTlsWorker> allocateRatsTlsWorker(Api::Api& api) {
  return std::make_unique<RatsTlsWorker>(api);
}

static std::atomic<int> worker_index(0);

RatsTlsWorker::RatsTlsWorker(Api::Api& api) {
  auto thread_name = "rats_tls_w" + std::to_string(worker_index.fetch_add(1));
  ENVOY_LOG(info, "Initializing new RatsTlsWorker. thread_name: {}", thread_name);
  this->dispatcher_ = api.allocateDispatcher(thread_name);
  this->thread_ = api.threadFactory().createThread(
      [&]() -> void { this->dispatcher_->run(Event::Dispatcher::RunType::RunUntilExit); },
      Thread::Options{thread_name});
}

RatsTlsWorker::~RatsTlsWorker() {
  ENVOY_LOG(info, "Destroying RatsTlsWorker(). thread_name: {}", this->thread_->name());
  this->dispatcher_->post([this]() -> void {
    this->dispatcher_->shutdown();
    this->dispatcher_->exit();
  });
  this->thread_->join();
}

} // namespace RatsTls
} // namespace Common
} // namespace Envoy
