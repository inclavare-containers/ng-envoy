#pragma once

#include <functional>
#include <map>
#include <string>

#include "source/common/common/logger.h"
#include "envoy/api/api.h"

namespace Envoy {
namespace Common {
namespace RatsTls {

class RatsTlsAttestationInfo : Logger::Loggable<Logger::Id::rats_tls> {

public:
  static thread_local std::map<std::string, std::string> local_storage;
};

} // namespace RatsTls
} // namespace Common
} // namespace Envoy
