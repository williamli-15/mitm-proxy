#ifndef SSL_UTILS_H
#define SSL_UTILS_H

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

int ssl_global_init(void);
int ca_init(const char* ca_crt_path, const char* ca_key_path);
void ca_free(void);

int generate_leaf_for_host(const char* hostname, X509** out_cert,
                           EVP_PKEY** out_pkey);

SSL_CTX* create_upstream_ctx(void);  // TLS client (proxy -> origin)
SSL_CTX* create_downstream_ctx(X509*,
                               EVP_PKEY*);  // TLS server (browser -> proxy)

extern X509* g_ca_cert;
extern EVP_PKEY* g_ca_key;

#endif
