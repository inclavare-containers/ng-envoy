#include "source/common/secret/librats_secret_provider_impl.h"

#include "envoy/extensions/transport_sockets/tls/v3/cert.pb.h"

#include "source/common/common/assert.h"
#include "source/common/ssl/certificate_validation_context_config_impl.h"
#include "source/common/ssl/tls_certificate_config_impl.h"

#include "openssl/x509.h"
#include "openssl/bio.h"
#include "openssl/pem.h"
#include "openssl/rsa.h"
#include "openssl/err.h"

namespace Envoy {
namespace Secret {

LibratsTlsCertificateConfigProviderImpl::LibratsTlsCertificateConfigProviderImpl(
    const envoy::extensions::transport_sockets::tls::v3::LibratsCertificate&
        tls_certificates_librats_config)
    : tls_certificates_librats_config_(
          std::make_unique<envoy::extensions::transport_sockets::tls::v3::LibratsCertificate>(
              tls_certificates_librats_config)),
      tls_certificate_(
          std::make_unique<envoy::extensions::transport_sockets::tls::v3::TlsCertificate>()) {
  // envoy::extensions::transport_sockets::tls::v3::TlsCertificate* tls_certificate = new
  // envoy::extensions::transport_sockets::tls::v3::TlsCertificate(); tls_certificate_ =
  // std::make_unique<envoy::extensions::transport_sockets::tls::v3::TlsCertificate>(std::move(&tls_certificate));
}

void generate_certificate(uint8_t** private_key, size_t* private_key_size,
                          uint8_t** certificate_out, size_t* certificate_size_out) {
  EVP_PKEY* pkey = EVP_PKEY_new();
  RSA* rsa = RSA_new();
  BIGNUM* e = BN_new();
  BN_set_word(e, RSA_F4);
  RSA_generate_key_ex(rsa, 2048, e, NULL);
  EVP_PKEY_assign_RSA(pkey, rsa);
  X509* x509 = X509_new();
  X509_set_version(x509, 2);
  ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
  X509_gmtime_adj(X509_get_notBefore(x509), 0);
  X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);
  X509_set_pubkey(x509, pkey);
  X509_NAME* name = X509_get_subject_name(x509);
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                             reinterpret_cast<const unsigned char*>("example.com"), -1, -1, 0);
  X509_set_issuer_name(x509, name);
  X509_sign(x509, pkey, EVP_sha256());
  BIO* bio = BIO_new(BIO_s_mem());
  PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL);
  BUF_MEM* private_key_buf;
  BIO_get_mem_ptr(bio, &private_key_buf);
  *private_key_size = private_key_buf->length;
  *private_key = static_cast<uint8_t*>(malloc(*private_key_size + 1));
  memcpy(*private_key, private_key_buf->data, *private_key_size);
  (*private_key)[*private_key_size] = '\0';
  BIO_free_all(bio);
  bio = BIO_new(BIO_s_mem());
  PEM_write_bio_X509(bio, x509);
  BUF_MEM* certificate_buf;
  BIO_get_mem_ptr(bio, &certificate_buf);
  *certificate_size_out = certificate_buf->length;
  *certificate_out = static_cast<uint8_t*>(malloc(*certificate_size_out + 1));
  memcpy(*certificate_out, certificate_buf->data, *certificate_size_out);
  (*certificate_out)[*certificate_size_out] = '\0';
  BIO_free_all(bio);
  EVP_PKEY_free(pkey);
}

const envoy::extensions::transport_sockets::tls::v3::TlsCertificate*
LibratsTlsCertificateConfigProviderImpl::secret() const {
  // in
  std::cout << "this is librats-server cert generate: " << std::endl;
  rats_conf_t conf;
  memset(&conf, 0, sizeof(rats_conf_t));
  std::string tmp_log_level = tls_certificates_librats_config_->log_level();
  if (tmp_log_level == "debug") {
    conf.log_level = RATS_LOG_LEVEL_DEBUG;
    std::cout << "log_level set: RATS_LOG_LEVEL_DEBUG" << std::endl;
  } else {
    conf.log_level = RATS_LOG_LEVEL_DEFAULT;
    std::cout << "log_level set: RATS_LOG_LEVEL_DEFAULT" << std::endl;
  }

  if (tls_certificates_librats_config_->attester() == "tdx") {
    // std::strncpy(conf.attester_type, tls_certificates_librats_config_->attester().c_str(),
    // sizeof(conf.attester_type)); std::cout <<"attester set: tdx" << std::endl;
  } else {
    // std::strncpy(conf.attester_type, "tdx", sizeof(conf.attester_type));
    std::cout << "attester set: nullattester" << std::endl;
  }

  [[maybe_unused]] bool provide_endorsements = false;
  if (tls_certificates_librats_config_->provide_endorsements() == true) {
    provide_endorsements = tls_certificates_librats_config_->provide_endorsements();
    std::cout << "provide_endorsements set: true" << std::endl;
  } else {
    provide_endorsements = true;
    std::cout << "provide_endorsements set: true" << std::endl;
  }

  rats_cert_subject_t subject_name;
  subject_name.organization = "Inclavare Containers";
  subject_name.common_name = "LibRATS";
  subject_name.organization_unit = nullptr;

  claim_t claims[64];
  [[maybe_unused]] size_t claims_length = 0, i = 0;
  claims_length = static_cast<size_t>(tls_certificates_librats_config_->custom_claims_size());
  std::cout << "custom_claim_size: " << tls_certificates_librats_config_->custom_claims_size()
            << std::endl;
  for (const auto& yaml_claims : tls_certificates_librats_config_->custom_claims()) {
    std::string str1(yaml_claims.first);
    std::string str2(yaml_claims.second);
    char* name = new char[str1.length() + 1];
    std::strcpy(name, str1.c_str());
    claims[i].name = name;
    delete[] name;
    claims[i].value = reinterpret_cast<uint8_t*>(str2.data());
    claims[i].value_size = static_cast<size_t>(yaml_claims.second.length());
    std::cout << "name: " << yaml_claims.first << std::endl;
    std::cout << "value: " << yaml_claims.second << std::endl;
    std::cout << "value_length: " << yaml_claims.second.length() << std::endl;
    i++;
  }

  // out
  uint8_t* private_key = NULL;
  size_t private_key_size = 0;
  uint8_t* certificate_out = NULL;
  size_t certificate_size_out = 0;

  rats_attester_err_t ret = RATS_ATTESTER_ERR_UNKNOWN;
  std::cout << "call librats_get_attestation_certificate begin: " << std::endl;
  ret = librats_get_attestation_certificate(conf, subject_name, &private_key, &private_key_size,
                                            claims, claims_length, provide_endorsements,
                                            &certificate_out, &certificate_size_out);
  std::cout << "call librats_get_attestation_certificate end: " << std::endl;
  ret = RATS_ATTESTER_ERR_NONE;

  if (ret != RATS_ATTESTER_ERR_NONE) {
    printf("Failed to generate certificate %#x\n", ret);
  }

  std::cout << "self_generate private_key: " << std::endl;
  for (size_t i = 0; i < private_key_size; i++) {
    std::cout << private_key[i];
  }
  std::cout << "private_key_size: " << private_key_size << std::endl;

  // 将DER证书加载到X509对象中
  X509* cert = nullptr;
  // 如果certificate_out不是一个const对象，创建一个const对象并复制数据
  const uint8_t* certificate_out_const = certificate_out;
  cert = d2i_X509(nullptr, &certificate_out_const, certificate_size_out);
  if (cert == nullptr) {
    std::cerr << "Failed to load DER cert\n";
    return tls_certificate_.get();
  }
  // 转换为PEM
  BIO* mem_bio = BIO_new(BIO_s_mem());
  PEM_write_bio_X509(mem_bio, cert);
  char* pem_cert;
  long pem_cert_len = BIO_get_mem_data(mem_bio, &pem_cert);
  std::string pem_cert_str(pem_cert, pem_cert_len);
  // 输出PEM证书
  certificate_out = reinterpret_cast<uint8_t*>(pem_cert_str.data());
  certificate_size_out = reinterpret_cast<size_t>(pem_cert_str.length());
  std::cout << "pem_cert_str OUT: " << std::endl;
  std::cout << pem_cert_str << std::endl;
  // 清理
  // BIO_free(mem_bio);
  // X509_free(cert);

  //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  // generate_certificate(&private_key, &private_key_size, &certificate_out, &certificate_size_out);
  /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  std::cout << "self_generate certificate: " << std::endl;
  for (size_t i = 0; i < certificate_size_out; i++) {
    std::cout << certificate_out[i];
  }
  std::cout << "certificate_size: " << certificate_size_out << std::endl;

  ::envoy::config::core::v3::DataSource* cert_chain_ = new ::envoy::config::core::v3::DataSource();
  ::envoy::config::core::v3::DataSource* private_key_ = new ::envoy::config::core::v3::DataSource();
  cert_chain_->set_inline_bytes(certificate_out, certificate_size_out);
  /*
  std::cout <<"cert_chain_ has_inline_bytes: " << cert_chain_->has_inline_bytes() << std::endl;
  [[maybe_unused]] const uint8_t* const_certificate = reinterpret_cast<const
  uint8_t*>(cert_chain_->inline_bytes().data()); std::cout <<"RE certificate: " <<std::endl;
  for(size_t i = 0; i < certificate_size_out; i++) {
      std::cout << certificate_out[i];
  }
  std::cout <<"RE certificate_size: " << certificate_size_out  << std::endl;
  */
  private_key_->set_inline_bytes(private_key, private_key_size);
  // std::cout <<"private_key_ has_inline_bytes: " << cert_chain_->has_inline_bytes() << std::endl;
  //[[maybe_unused]] const uint8_t* const_private_key = reinterpret_cast<const
  //uint8_t*>(private_key_->inline_bytes().data());
  std::cout << "set_inline_bytes success." << std::endl;

  // envoy::extensions::transport_sockets::tls::v3::TlsCertificate tls_certificate;
  // tls_certificate.set_allocated_certificate_chain(&cert_chain_);
  // tls_certificate.set_allocated_private_key(&private_key_);
  // std::cout <<"tls_certificate_ pass success." << std::endl;
  // release

  if (tls_certificate_ == nullptr) {
    std::cout << "tls_certificate_ is nullptr" << std::endl;
  } else {
    std::cout << "tls_certificate_ is NOT nullptr" << std::endl;
  }

  tls_certificate_->set_allocated_certificate_chain(cert_chain_);
  /*
  std::cout <<"has_certificate_chain: " << tls_certificate_->has_certificate_chain() << std::endl;
  *cert_chain_ = tls_certificate_->certificate_chain();
  std::cout <<"cert_chain_ has_inline_bytes: " << cert_chain_->has_inline_bytes() << std::endl;
  const_certificate = reinterpret_cast<const uint8_t*>(cert_chain_->inline_bytes().data());
  std::cout <<"RERE certificate: " <<std::endl;
  for(size_t i = 0; i < certificate_size_out; i++) {
      std::cout << certificate_out[i];
  }
  std::cout <<"RERE certificate_size: " << certificate_size_out  << std::endl;
  */
  tls_certificate_->set_allocated_private_key(private_key_);
  // std::cout <<"has_certificate_chain: " << tls_certificate_->has_private_key() << std::endl;
  //*private_key_ = tls_certificate_->private_key();
  std::cout << "tls_certificate_ generete success" << std::endl;

  delete[] private_key;
  // delete[] certificate_out;
  return tls_certificate_.get();
}

} // namespace Secret
} // namespace Envoy
