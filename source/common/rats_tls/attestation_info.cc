#include "source/common/rats_tls/attestation_info.h"

namespace Envoy {
namespace Common {
namespace RatsTls {

thread_local std::map<std::string, std::string> RatsTlsAttestationInfo::local_storage;

} // namespace RatsTls
} // namespace Common
} // namespace Envoy
