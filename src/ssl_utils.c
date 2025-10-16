#include "ssl_utils.h"

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

X509* g_ca_cert = NULL;
EVP_PKEY* g_ca_key = NULL;

int ssl_global_init(void) {
  SSL_library_init();
  SSL_load_error_strings();
  OpenSSL_add_all_algorithms();
  return 1;
}

int ca_init(const char* ca_crt_path, const char* ca_key_path) {
  FILE* fp = fopen(ca_crt_path, "r");
  if (!fp) {
    perror("open ca crt");
    return 0;
  }
  g_ca_cert = PEM_read_X509(fp, NULL, NULL, NULL);
  fclose(fp);
  if (!g_ca_cert) {
    fprintf(stderr, "PEM_read_X509 failed\n");
    return 0;
  }

  fp = fopen(ca_key_path, "r");
  if (!fp) {
    perror("open ca key");
    return 0;
  }
  g_ca_key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
  fclose(fp);
  if (!g_ca_key) {
    fprintf(stderr, "PEM_read_PrivateKey failed\n");
    return 0;
  }

  return 1;
}

void ca_free(void) {
  if (g_ca_cert) {
    X509_free(g_ca_cert);
    g_ca_cert = NULL;
  }
  if (g_ca_key) {
    EVP_PKEY_free(g_ca_key);
    g_ca_key = NULL;
  }
}

static EVP_PKEY* gen_rsa_2048(void) {
  EVP_PKEY* pkey = NULL;
  EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
  if (!pctx) return NULL;
  if (EVP_PKEY_keygen_init(pctx) <= 0) {
    EVP_PKEY_CTX_free(pctx);
    return NULL;
  }
  if (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) <= 0) {
    EVP_PKEY_CTX_free(pctx);
    return NULL;
  }
  if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
    EVP_PKEY_CTX_free(pctx);
    return NULL;
  }
  EVP_PKEY_CTX_free(pctx);
  return pkey;
}

int generate_leaf_for_host(const char* hostname, X509** out_cert,
                           EVP_PKEY** out_pkey) {
  if (!g_ca_cert || !g_ca_key || !hostname || !out_cert || !out_pkey) return 0;

  *out_cert = NULL;
  *out_pkey = NULL;

  EVP_PKEY* leaf_key = gen_rsa_2048();
  if (!leaf_key) return 0;

  X509* leaf = X509_new();
  if (!leaf) {
    EVP_PKEY_free(leaf_key);
    return 0;
  }

  X509_set_version(leaf, 2);
  ASN1_INTEGER_set(X509_get_serialNumber(leaf), (long)time(NULL));
  X509_gmtime_adj(X509_get_notBefore(leaf), 0);
  X509_gmtime_adj(X509_get_notAfter(leaf), (long)60 * 60 * 24 * 365);  // 1 year
  X509_set_pubkey(leaf, leaf_key);

  // Subject name
  X509_NAME* subj = X509_get_subject_name(leaf);
  X509_NAME_add_entry_by_txt(subj, "C", MBSTRING_ASC, (unsigned char*)"US", -1,
                             -1, 0);
  X509_NAME_add_entry_by_txt(subj, "O", MBSTRING_ASC,
                             (unsigned char*)"MITM Proxy", -1, -1, 0);
  X509_NAME_add_entry_by_txt(subj, "CN", MBSTRING_ASC, (unsigned char*)hostname,
                             -1, -1, 0);

  // Issuer = CA subject
  X509_set_issuer_name(leaf, X509_get_subject_name(g_ca_cert));

  // X509v3 extensions
  X509V3_CTX ctx;
  X509V3_set_ctx(&ctx, g_ca_cert, leaf, NULL, NULL, 0);

  // basicConstraints: CA:FALSE
  X509_EXTENSION* ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_basic_constraints,
                                            "critical,CA:FALSE");
  X509_add_ext(leaf, ext, -1);
  X509_EXTENSION_free(ext);

  // keyUsage
  ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_key_usage,
                            "critical,digitalSignature,keyEncipherment");
  X509_add_ext(leaf, ext, -1);
  X509_EXTENSION_free(ext);

  // extKeyUsage
  ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_ext_key_usage,
                            "serverAuth,clientAuth");
  X509_add_ext(leaf, ext, -1);
  X509_EXTENSION_free(ext);

  // subjectAltName
  char san[512];
  snprintf(san, sizeof(san), "DNS:%s", hostname);
  ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_alt_name, san);
  X509_add_ext(leaf, ext, -1);
  X509_EXTENSION_free(ext);

  if (!X509_sign(leaf, g_ca_key, EVP_sha256())) {
    X509_free(leaf);
    EVP_PKEY_free(leaf_key);
    return 0;
  }

  *out_cert = leaf;
  *out_pkey = leaf_key;
  return 1;
}

SSL_CTX* create_upstream_ctx(void) {
  SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
  if (!ctx) return NULL;

  // Keep HTTP/1.1 to simplify parsing
#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
  const unsigned char alpn[] = {8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
  SSL_CTX_set_alpn_protos(ctx, alpn, sizeof(alpn));
#endif

  // We can enable verification if desired:
  SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
  SSL_CTX_set_options(
      ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION);

  return ctx;
}

SSL_CTX* create_downstream_ctx(X509* cert, EVP_PKEY* pkey) {
  SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
  if (!ctx) return NULL;

  if (SSL_CTX_use_certificate(ctx, cert) <= 0) {
    SSL_CTX_free(ctx);
    return NULL;
  }
  if (SSL_CTX_use_PrivateKey(ctx, pkey) <= 0) {
    SSL_CTX_free(ctx);
    return NULL;
  }
  if (!SSL_CTX_check_private_key(ctx)) {
    SSL_CTX_free(ctx);
    return NULL;
  }
  SSL_CTX_set_options(
      ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION);
  return ctx;
}
