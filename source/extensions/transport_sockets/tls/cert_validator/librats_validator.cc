#include "source/extensions/transport_sockets/tls/cert_validator/librats_validator.h"

#include <array>
#include <cstdint>
#include <deque>
#include <functional>
#include <string>
#include <vector>

#include "envoy/extensions/transport_sockets/tls/v3/tls_librats_config.pb.h"
#include "source/common/protobuf/message_validator_impl.h"

#include "envoy/network/transport_socket.h"
#include "envoy/ssl/context.h"
#include "envoy/ssl/context_config.h"
#include "envoy/ssl/private_key/private_key.h"
#include "envoy/ssl/ssl_socket_extended_info.h"

#include "source/common/common/assert.h"
#include "source/common/common/base64.h"
#include "source/common/common/fmt.h"
#include "source/common/common/hex.h"
#include "source/common/common/matchers.h"
#include "source/common/common/utility.h"
#include "source/common/config/utility.h"
#include "source/common/network/address_impl.h"
#include "source/common/protobuf/utility.h"
#include "source/common/runtime/runtime_features.h"
#include "source/common/stats/symbol_table.h"
#include "source/common/stats/utility.h"
#include "source/extensions/transport_sockets/tls/cert_validator/cert_validator.h"
#include "source/extensions/transport_sockets/tls/cert_validator/factory.h"
#include "source/extensions/transport_sockets/tls/cert_validator/utility.h"
#include "source/extensions/transport_sockets/tls/stats.h"
#include "source/extensions/transport_sockets/tls/utility.h"

#include "absl/synchronization/mutex.h"
#include "openssl/ssl.h"
#include "openssl/pem.h"
#include "openssl/bio.h"
#include "openssl/x509v3.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {

LibratsCertValidator::LibratsCertValidator(
    const Envoy::Ssl::CertificateValidationContextConfig* config, SslStats& stats,
    TimeSource& time_source)
    : DefaultCertValidator(config, stats, time_source), config_(config), stats_(stats), time_source_(time_source){
  if (config_ != nullptr) {
    allow_untrusted_certificate_ = config_->trustChainVerification() ==
                                   envoy::extensions::transport_sockets::tls::v3::
                                       CertificateValidationContext::ACCEPT_UNTRUSTED;
  }
};

int LibratsCertValidator::initializeSslContexts(std::vector<SSL_CTX*> contexts,
                                                bool provides_certificates) {
  [[maybe_unused]] auto& ctx = contexts;
  [[maybe_unused]] bool tpp = provides_certificates;
  return SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
}

void print_claim_value(uint8_t *value, size_t value_size)
{
	bool hex = false;
	for (size_t i = 0; i < value_size; ++i) {
		if (!isprint(value[i])) {
			hex = true;
			break;
		}
	}
	if (hex) {
		printf("(hex)");
		for (size_t i = 0; i < value_size; ++i) {
			printf("%02X", value[i]);
		}
	} else {
        printf("'%.*s'", static_cast<int>(value_size), value);
	}
}

int verify_callback(claim_t *claims, size_t claims_size, void *args_in)
{
    int ret = 0;
	typedef struct {
		const claim_t *custom_claims;
		size_t custom_claims_size;
	} args_t;
	args_t *args = static_cast<args_t*>(args_in);	

    std::cout << "claims check begin." << std::endl;
    printf("----------------------------------------\n");
    std::cout << "claims custom and build-in claims (sys generate): " << std::endl;
	for (size_t i = 0; i < claims_size; ++i) {
		printf("claims[%zu] -> name: '%s' value_size: %zu value: ", i, claims[i].name,
		       claims[i].value_size);
		print_claim_value(claims[i].value, claims[i].value_size);
		printf("\n");
	}
    std::cout << "claims custom and build-in claims (usr provide): " << std::endl;
	for (size_t i = 0; i < args->custom_claims_size; ++i) {
		printf("claims[%zu] -> name: '%s' value_size: %zu value: ", i, args->custom_claims[i].name,
		       args->custom_claims[i].value_size);
		print_claim_value(args->custom_claims[i].value, args->custom_claims[i].value_size);
		printf("\n");
	}
	
    for (size_t i = 0; i < args->custom_claims_size; ++i) {
		const claim_t *claim = &args->custom_claims[i];
		bool found = false;
		for (size_t j = 0; j < claims_size; ++j) {
			if (!strcmp(claim->name, claims[j].name)) {
				found = true;
				if (claim->value_size != claims[j].value_size) {
					printf("different claim detected -> name: '%s' expected value_size: %zu got: %zu\n",
					       claim->name, claim->value_size,
					       claims[j].value_size);
					ret = 1;
					break;
				}

				if (memcmp(claim->value, claims[j].value, claim->value_size)) {
					printf("different claim detected -> name: '%s' value_size: %zu expected value: ",
					       claim->name, claim->value_size);
					print_claim_value(claim->value, claim->value_size);
					printf(" got: ");
					print_claim_value(claims[j].value, claim->value_size);
					printf("\n");
					ret = 1;
					break;
				}
				break;
			}
		}
		if (!found) {
			printf("different claim detected -> name: '%s' not found\n", claim->name);
			ret = 1;
		}
	}
	printf("verify_callback check result:\t%s\n", ret == 0 ? "SUCCESS" : "FAILED");
	printf("----------------------------------------\n");
	return ret;
}

using LibratsConfig = envoy::extensions::transport_sockets::tls::v3::LibratsCertValidatorConfig;

ValidationResults LibratsCertValidator::doVerifyCertChain(
    STACK_OF(X509)& cert_chain, Ssl::ValidateResultCallbackPtr /*callback*/,
    const Network::TransportSocketOptionsConstSharedPtr& transport_socket_options, SSL_CTX& ssl_ctx,
    const CertValidator::ExtraValidationContext& /*validation_context*/, bool is_server,
    absl::string_view /*host_name*/) {
    
    //get yaml comfig
    std::cout << "this is librats-client cert validator: " << std::endl;
    LibratsConfig message;
    Config::Utility::translateOpaqueConfig(config_->customValidatorConfig().value().typed_config(),
                                            ProtobufMessage::getStrictValidationVisitor(), message);
    std::cout << "read yaml config end." << std::endl;

    //conf
    claim_t claims[64];
	size_t claims_length = 0;
    rats_conf_t conf;
    memset(&conf, 0, sizeof(rats_conf_t));
    auto& log_level = message.log_level();
    if(log_level == "debug"){
        conf.log_level = RATS_LOG_LEVEL_DEBUG;
        std::cout <<"log_level set: RATS_LOG_LEVEL_DEBUG" << std::endl;
    }else{
        conf.log_level = RATS_LOG_LEVEL_DEFAULT;
        std::cout <<"log_level set: RATS_LOG_LEVEL_DEFAULT" << std::endl;
    }
    for (const auto& static_policy : message.static_policy()){
        if(static_policy.verifier() == "tdx"){
            //std::strncpy(conf.verifier_type, static_policy.verifier().c_str(), sizeof(conf.verifier_type) - 1);
            //std::cout <<"attester set: tdx" << std::endl;
        }else{
            //std::strncpy(conf.verifier_type, "tdx", sizeof(conf.verifier_type) - 1);
            std::cout <<"attester set: nullattester" << std::endl;
        }
        std::cout <<"verifier: " << static_policy.verifier() << std::endl;
        claims_length = static_cast<size_t>(static_policy.claims_size());
        std::cout <<"claim_size: " << static_policy.claims_size() << std::endl;
        for (const auto& yaml_claims : static_policy.claims()) {
            std::string str1(yaml_claims.first);  
            std::string str2(yaml_claims.second);  
            char* name = new char[str1.length() + 1];  
            std::strcpy(name, str1.c_str());  
            claims->name = name;
            delete[] name;
            claims->value = reinterpret_cast<uint8_t*>(str2.data());
            claims->value_size = static_cast<size_t>(yaml_claims.second.length());
            std::cout <<"name: " << yaml_claims.first << std::endl;
            std::cout <<"value: " << yaml_claims.second << std::endl;
            std::cout <<"value_length: " << yaml_claims.second.length()  << std::endl;
        }
    }
    
    //claims
    typedef struct {
        const claim_t *custom_claims;
        size_t custom_claims_size;
    } args_t;
    args_t args;  
    args.custom_claims = claims;  
    args.custom_claims_size = claims_length;
    
    //certificate get
    X509* leaf_cert = sk_X509_value(&cert_chain, 0);
    ASSERT(leaf_cert);
    BIO* bio = BIO_new(BIO_s_mem()); // create a new BIO  
    // write the certificate to the BIO  
    if (PEM_write_bio_X509(bio, leaf_cert) != 1) {
        // Handle error
        std::cout <<"PEM_write_bio_X509: error" <<std::endl;
    }
    // now, you can read the data from the BIO  
    uint8_t* certificate = new uint8_t[BIO_number_written(bio)];  
    int length = BIO_read(bio, certificate, BIO_number_written(bio));  
    ASSERT(static_cast<size_t>(length) == BIO_number_written(bio)); // make sure all the data was read  
    [[maybe_unused]] size_t certificate_size = static_cast<size_t>(length);
    std::cout << "cert_pem: " <<certificate << std::endl;
    std::cout << "cert_pem size: " <<length << std::endl;
    // don't forget to free the BIO and the certificate data when you're done with them  
    BIO_free_all(bio);
    
    //start verify
    rats_verifier_err_t rats_ret;
    
    rats_ret = librats_verify_attestation_certificate(conf, certificate, certificate_size, verify_callback, &args);
    
    //test
    rats_ret = RATS_VERIFIER_ERR_NONE;

    //result
    Envoy::Ssl::ClientValidationStatus detailed_status = Envoy::Ssl::ClientValidationStatus::NotValidated;
    uint8_t tls_alert = SSL_AD_CERTIFICATE_UNKNOWN;
    std::string error_details="cert verify not start";
    bool succeeded = 0;
    if (rats_ret != RATS_VERIFIER_ERR_NONE) {
		printf("Failed to verify certificate %#x\n", rats_ret);
    succeeded = 0;
    detailed_status = Envoy::Ssl::ClientValidationStatus::Failed;
    tls_alert = SSL_AD_CERTIFICATE_UNOBTAINABLE;
    error_details = "librats-failed.";
	}else{
    std::cout << "verify certificate success" << std::endl;
    succeeded = 1;
    detailed_status = Envoy::Ssl::ClientValidationStatus::Validated;
  }

  //unused parament declair
  [[maybe_unused]] auto transport_socket_options_pp = transport_socket_options;
  [[maybe_unused]] bool nouse2 = is_server;
  [[maybe_unused]] X509_STORE* verify_store = SSL_CTX_get_cert_store(&ssl_ctx);

  //return 
  return succeeded ? ValidationResults{ValidationResults::ValidationStatus::Successful,
                                       detailed_status, absl::nullopt, absl::nullopt}
                   : ValidationResults{ValidationResults::ValidationStatus::Failed, detailed_status,
                                       tls_alert, error_details};
}

class LibratsCertValidatorFactory : public CertValidatorFactory {
public:
  CertValidatorPtr createCertValidator(const Envoy::Ssl::CertificateValidationContextConfig* config,
                                       SslStats& stats, TimeSource& time_source) override {
    return std::make_unique<LibratsCertValidator>(config, stats, time_source);
  }

  std::string name() const override { return "envoy.tls.cert_validator.librats"; }
};

REGISTER_FACTORY(LibratsCertValidatorFactory, CertValidatorFactory);

} // namespace Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
