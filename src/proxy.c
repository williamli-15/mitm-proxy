#include "proxy.h"

#include <brotli/decode.h>
#include <ctype.h>
#include <errno.h>
#include <event2/buffer.h>
#include <event2/bufferevent_ssl.h>
#include <inttypes.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <zlib.h>

#include "inject.h"
#include "ssl_utils.h"

#define MIN(a, b) ((a) < (b) ? (a) : (b))

/* ====================== Utilities ====================== */

static void loge(FILE* err, const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vfprintf(err ? err : stderr, fmt, ap);
  fprintf(err ? err : stderr, "\n");
  va_end(ap);
}

static void logs(FILE* out, const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vfprintf(out ? out : stdout, fmt, ap);
  fprintf(out ? out : stdout, "\n");
  va_end(ap);
}

static char* strcasestr_portable(const char* h, const char* n) {
  if (!h || !n) return NULL;

  size_t L = strlen(n);
  if (!L) return (char*)h;

  for (; *h; ++h) {
    if (strncasecmp(h, n, L) == 0) return (char*)h;
  }

  return NULL;
}

static void trim_crlf(char* s) {
  size_t n = strlen(s);
  while (n && (s[n - 1] == '\r' || s[n - 1] == '\n')) s[--n] = 0;
}

/* Lowercase ASCII in place */
static void strlower(char* s) {
  if (!s) return;

  for (; *s; ++s) *s = (char)tolower((unsigned char)*s);
}

/* ================= HTTP header parsing / rewriting ================ */

struct http_headers {
  char* status_line;  // or request line on request path
  char** keys;
  char** vals;
  size_t count;
  size_t cap;
  int is_response;
};

static void hh_init(struct http_headers* hh, int is_response) {
  memset(hh, 0, sizeof(*hh));
  hh->is_response = is_response;
}

static void hh_free(struct http_headers* hh) {
  if (hh->status_line) free(hh->status_line);

  for (size_t i = 0; i < hh->count; i++) {
    free(hh->keys[i]);
    free(hh->vals[i]);
  }

  free(hh->keys);
  free(hh->vals);
}

static int hh_add(struct http_headers* hh, const char* k, const char* v) {
  if (hh->count == hh->cap) {
    size_t ncap = hh->cap ? hh->cap * 2 : 16;

    char** nk = realloc(hh->keys, ncap * sizeof(char*));
    char** nv = realloc(hh->vals, ncap * sizeof(char*));
    if (!nk || !nv) {
      free(nk);
      free(nv);
      return 0;
    }

    hh->keys = nk;
    hh->vals = nv;
    hh->cap = ncap;
  }

  hh->keys[hh->count] = strdup(k ? k : "");
  hh->vals[hh->count] = strdup(v ? v : "");

  if (!hh->keys[hh->count] || !hh->vals[hh->count]) return 0;

  hh->count++;
  return 1;
}

static int hh_parse(const char* hdrs, size_t len, int is_response,
                    struct http_headers* out) {
  // hdrs is a single block including CRLFCRLF but we don't require trailing NUL
  struct http_headers hh;
  hh_init(&hh, is_response);

  char* buf = malloc(len + 1);
  if (!buf) return 0;

  memcpy(buf, hdrs, len);
  buf[len] = 0;

  char* saveptr = NULL;
  char* line = strtok_r(buf, "\r\n", &saveptr);
  if (!line) {
    free(buf);
    return 0;
  }

  hh.status_line = strdup(line);
  if (!hh.status_line) {
    free(buf);
    return 0;
  }

  while ((line = strtok_r(NULL, "\r\n", &saveptr))) {
    if (!*line) continue;

    char* colon = strchr(line, ':');
    if (!colon) continue;

    *colon = 0;
    char* k = line;
    char* v = colon + 1;
    while (*v == ' ' || *v == '\t') v++;

    if (!hh_add(&hh, k, v)) {
      hh_free(&hh);
      free(buf);
      return 0;
    }
  }

  *out = hh;
  free(buf);
  return 1;
}

static const char* hh_get_ci(struct http_headers* hh, const char* key) {
  for (size_t i = 0; i < hh->count; i++) {
    if (strcasecmp(hh->keys[i], key) == 0) return hh->vals[i];
  }
  return NULL;
}

static void hh_remove_all_ci(struct http_headers* hh, const char* key) {
  size_t w = 0;

  for (size_t i = 0; i < hh->count; i++) {
    if (strcasecmp(hh->keys[i], key) == 0) {
      free(hh->keys[i]);
      free(hh->vals[i]);
      continue;
    }
    if (w != i) {
      hh->keys[w] = hh->keys[i];
      hh->vals[w] = hh->vals[i];
    }
    w++;
  }

  hh->count = w;
}

static int hh_set(struct http_headers* hh, const char* key, const char* val) {
  for (size_t i = 0; i < hh->count; i++) {
    if (strcasecmp(hh->keys[i], key) == 0) {
      free(hh->vals[i]);
      hh->vals[i] = strdup(val ? val : "");
      return hh->vals[i] != NULL;
    }
  }

  return hh_add(hh, key, val);
}

static void hh_write(struct http_headers* hh, struct bufferevent* dst) {
  bufferevent_write(dst, hh->status_line, strlen(hh->status_line));
  bufferevent_write(dst, "\r\n", 2);

  for (size_t i = 0; i < hh->count; i++) {
    bufferevent_write(dst, hh->keys[i], strlen(hh->keys[i]));
    bufferevent_write(dst, ": ", 2);
    bufferevent_write(dst, hh->vals[i], strlen(hh->vals[i]));
    bufferevent_write(dst, "\r\n", 2);
  }

  bufferevent_write(dst, "\r\n", 2);
}

/* ============== Chunked encoder (downstream) ================= */

static void write_chunk(struct bufferevent* dst, const uint8_t* data,
                        size_t len) {
  char hdr[64];
  int n = snprintf(hdr, sizeof(hdr), "%zx\r\n", len);
  bufferevent_write(dst, hdr, (size_t)n);
  if (len) bufferevent_write(dst, data, len);
  bufferevent_write(dst, "\r\n", 2);
}
static void write_chunk_zero(struct bufferevent* dst) {
  bufferevent_write(dst, "0\r\n\r\n", 5);
}

/* ============== Origin chunked decoder (upstream) ============== */

enum chunk_state { CH_SIZE, CH_DATA, CH_CRLF, CH_TRAILERS, CH_DONE };

struct chunked_decoder {
  enum chunk_state st;
  size_t bytes_remaining;
  // for reading size line
  char linebuf[64];
  size_t lineused;
};

static void chdec_init(struct chunked_decoder* cd) {
  memset(cd, 0, sizeof(*cd));
  cd->st = CH_SIZE;
}

static long parse_hex(const char* s) {
  long v = 0;
  while (*s) {
    int d;
    if (*s >= '0' && *s <= '9')
      d = *s - '0';
    else if (*s >= 'a' && *s <= 'f')
      d = *s - 'a' + 10;
    else if (*s >= 'A' && *s <= 'F')
      d = *s - 'A' + 10;
    else
      break;
    v = (v << 4) + d;
    s++;
  }
  return v;
}

// Consume from src, produce plain body bytes into out (evbuffer).
// Returns 1 if made progress; 0 if need more input; -1 on error; sets
// cd->st=CH_DONE at end.
static int chdec_process(struct chunked_decoder* cd, struct evbuffer* src,
                         struct evbuffer* out) {
  for (;;) {
    size_t avail = evbuffer_get_length(src);
    if (cd->st == CH_DONE) return 0;
    if (cd->st == CH_SIZE) {
      // read a line up to CRLF
      while (cd->lineused < sizeof(cd->linebuf) - 1) {
        if (avail == 0) return (cd->lineused > 0) ? 1 : 0;
        unsigned char c;
        evbuffer_remove(src, &c, 1);
        avail--;
        cd->linebuf[cd->lineused++] = (char)c;
        if (cd->lineused >= 2 && cd->linebuf[cd->lineused - 2] == '\r' &&
            cd->linebuf[cd->lineused - 1] == '\n') {
          cd->linebuf[cd->lineused - 2] = 0;  // strip CRLF
          // handle possible chunk extensions: split at ';'
          char* semi = strchr(cd->linebuf, ';');
          if (semi) *semi = 0;
          long sz = parse_hex(cd->linebuf);
          cd->lineused = 0;
          if (sz < 0) return -1;
          cd->bytes_remaining = (size_t)sz;
          cd->st = (sz == 0) ? CH_TRAILERS : CH_DATA;
          break;
        }
      }
      if (cd->lineused >= sizeof(cd->linebuf) - 1) return -1;
    } else if (cd->st == CH_DATA) {
      size_t take = MIN(cd->bytes_remaining, avail);
      if (!take) return 0;
      evbuffer_remove_buffer(src, out, take);
      cd->bytes_remaining -= take;
      if (cd->bytes_remaining == 0) cd->st = CH_CRLF;
      return 1;
    } else if (cd->st == CH_CRLF) {
      if (avail < 2) return 0;
      unsigned char crlf[2];
      evbuffer_remove(src, crlf, 2);
      if (crlf[0] != '\r' || crlf[1] != '\n') return -1;
      cd->st = CH_SIZE;
      return 1;
    } else if (cd->st == CH_TRAILERS) {
      // consume trailer headers until empty line
      // simplest: search for CRLFCRLF
      struct evbuffer_ptr p = evbuffer_search(src, "\r\n\r\n", 4, NULL);
      if (p.pos == -1) {
        return (avail > 0) ? 1 : 0;
      }
      evbuffer_drain(src, (size_t)p.pos + 4);
      cd->st = CH_DONE;
      return 1;
    }
  }
}

/* ============== Decompressors: gzip/deflate + brotli ============== */

enum ce_kind { CE_IDENTITY = 0, CE_GZIP, CE_DEFLATE, CE_BR, CE_UNKNOWN };

struct zlib_dec {
  int inited;
  z_stream zs;
};

static void zdec_init(struct zlib_dec* zd) { memset(zd, 0, sizeof(*zd)); }
static void zdec_end(struct zlib_dec* zd) {
  if (zd->inited) inflateEnd(&zd->zs);
  memset(zd, 0, sizeof(*zd));
}

// kind: CE_GZIP -> windowBits=16+MAX_WBITS; CE_DEFLATE -> MAX_WBITS
static int zdec_ensure(struct zlib_dec* zd, enum ce_kind kind) {
  if (zd->inited) return 1;
  memset(&zd->zs, 0, sizeof(zd->zs));
  int wb = (kind == CE_GZIP) ? (16 + MAX_WBITS) : MAX_WBITS;
  if (inflateInit2(&zd->zs, wb) != Z_OK) return 0;
  zd->inited = 1;
  return 1;
}

// Feed data from src evbuffer into zlib, writing decompressed to out evbuffer
static int zdec_process(struct zlib_dec* zd, enum ce_kind kind,
                        struct evbuffer* src, struct evbuffer* out) {
  if (!zdec_ensure(zd, kind)) return -1;

  size_t avail = evbuffer_get_length(src);
  if (!avail) return 0;

  unsigned char* in = malloc(avail);
  if (!in) return -1;
  evbuffer_remove(src, in, avail);

  zd->zs.next_in = in;
  zd->zs.avail_in = (uInt)avail;

  unsigned char buf[16 * 1024];
  int made = 0;
  int ret = Z_OK;

  while (zd->zs.avail_in > 0 && ret != Z_STREAM_END) {
    zd->zs.next_out = buf;
    zd->zs.avail_out = (uInt)sizeof(buf);
    ret = inflate(&zd->zs, Z_NO_FLUSH);
    if (ret < 0) {
      free(in);
      return -1;
    }  // error
    size_t produced = sizeof(buf) - zd->zs.avail_out;
    if (produced > 0) {
      evbuffer_add(out, buf, produced);
      made = 1;
    }
    if (ret == Z_STREAM_END) break;
    if (zd->zs.avail_in == 0) break;
  }

  free(in);
  return made;
}

struct br_dec {
  BrotliDecoderState* st;
  int inited;
};
static void brdec_init(struct br_dec* bd) { memset(bd, 0, sizeof(*bd)); }
static void brdec_end(struct br_dec* bd) {
  if (bd->st) BrotliDecoderDestroyInstance(bd->st);
  memset(bd, 0, sizeof(*bd));
}

static int brdec_ensure(struct br_dec* bd) {
  if (bd->inited) return 1;
  bd->st = BrotliDecoderCreateInstance(NULL, NULL, NULL);
  if (!bd->st) return 0;
  bd->inited = 1;
  return 1;
}

static int brdec_process(struct br_dec* bd, struct evbuffer* src,
                         struct evbuffer* out) {
  if (!brdec_ensure(bd)) return -1;

  size_t avail = evbuffer_get_length(src);
  if (!avail) return 0;

  unsigned char* in = malloc(avail);
  if (!in) return -1;
  evbuffer_remove(src, in, avail);

  const uint8_t* next_in = in;
  size_t avail_in = avail;

  uint8_t outbuf[16 * 1024];
  uint8_t* next_out = outbuf;
  size_t avail_out = sizeof(outbuf);
  size_t total_out = 0;
  int made = 0;

  while (1) {
    BrotliDecoderResult r = BrotliDecoderDecompressStream(
        bd->st, &avail_in, &next_in, &avail_out, &next_out, &total_out);

    size_t produced = sizeof(outbuf) - avail_out;
    if (produced > 0) {
      evbuffer_add(out, outbuf, produced);
      next_out = outbuf;
      avail_out = sizeof(outbuf);
      made = 1;
    }

    if (r == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT && avail_in == 0) break;
    if (r == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT) continue;
    if (r == BROTLI_DECODER_RESULT_SUCCESS) break;
    if (r == BROTLI_DECODER_RESULT_ERROR) {
      free(in);
      return -1;
    }
  }

  free(in);
  return made;
}

/* ================== Injector state ================== */

struct inject_state {
  int enabled;  // we plan to inject (text/html etc.)
  int done;     // injection done already
  // For searching </body> case-insensitively across boundaries:
  char tail[8192];
  size_t tail_len;
};

static void inj_init(struct inject_state* is) { memset(is, 0, sizeof(*is)); }

static void write_injected_stream(struct bufferevent* dst, const uint8_t* data,
                                  size_t len, struct inject_state* is) {
  // Stream with look-behind window to find </body>.
  // Approach: Keep a tail window. On each call, concatenate tail+data in a
  // temp, search for "</body>". If found, emit prefix, then INJECT_HTML, then
  // suffix. Keep last up to 8KB in tail for future scans; otherwise stream out
  // as we go.
  const char* needle = "</body>";
  size_t needle_len = 7;  // includes slash; lowercase compare

  // Build a temporary buffer tail+data (bounded)
  size_t total = is->tail_len + len;
  uint8_t* tmp = malloc(total);
  if (!tmp) {
    // fallback: just output data as-is (chunked)
    write_chunk(dst, data, len);
    return;
  }
  memcpy(tmp, is->tail, is->tail_len);
  memcpy(tmp + is->tail_len, data, len);

  // Create lowercase copy for case-insensitive search
  uint8_t* low = malloc(total);
  if (!low) {
    free(tmp);
    write_chunk(dst, data, len);
    return;
  }
  for (size_t i = 0; i < total; i++) low[i] = (uint8_t)tolower(tmp[i]);

  // Search
  size_t pos = SIZE_MAX;
  for (size_t i = 0; i + needle_len <= total; i++) {
    if (memcmp(low + i, needle, needle_len) == 0) {
      pos = i;
      break;
    }
  }

  if (pos != SIZE_MAX && !is->done) {
    // split: [0..pos)  "</body>"  [pos..]
    // but pos is in tail+data coords. Emit prefix excluding the part that is
    // still in the tail.
    size_t prefix = (pos > 0 ? pos : 0);
    // Emit prefix
    if (prefix > 0) {
      if (prefix <= is->tail_len) {
        // prefix lies entirely in the previous tail -> nothing new to emit from
        // current data
        size_t emit_from_tail = prefix;  // but tail already sent previously; to
                                         // keep logic simple, emit now
        // Emit the tail prefix (rare case; safe)
        write_chunk(dst, tmp, emit_from_tail);
      } else {
        // Some in tail, some in new data
        size_t in_tail = is->tail_len;
        size_t from_new = prefix - in_tail;
        if (in_tail) write_chunk(dst, tmp, in_tail);
        if (from_new) write_chunk(dst, data, from_new);
      }
    }

    // Emit the rest of the current chunk up to the end of "</body>" from
    // new-data side
    size_t end_of_body = pos + needle_len;
    size_t remaining_before_suffix = 0;
    if (end_of_body > is->tail_len) {
      size_t from_new = end_of_body - is->tail_len;
      if (from_new > len) from_new = len;  // clamp
      // Emit the part up to and including </body>
      // We've already emitted prefix. Now emit the remainder up to end_of_body
      // if any in new data.
      if (from_new > prefix && prefix > is->tail_len) {
        // already emitted part of new; adjust
      }
      size_t start_in_new =
          (prefix > is->tail_len) ? (prefix - is->tail_len) : 0;
      size_t emit_len = from_new - start_in_new;
      if (emit_len > 0 && start_in_new < len &&
          (start_in_new + emit_len) <= len) {
        write_chunk(dst, data + start_in_new, emit_len);
      }
    }

    // Inject our HTML
    const char* inj = INJECT_HTML;
    write_chunk(dst, (const uint8_t*)inj, strlen(inj));
    is->done = 1;

    // Emit the suffix (after </body>)
    size_t suffix_off = end_of_body;
    if (suffix_off < total) {
      size_t suffix_len = total - suffix_off;
      // The suffix may be partly in tail and partly in new data.
      if (suffix_off < is->tail_len) {
        size_t in_tail = is->tail_len - suffix_off;
        write_chunk(dst, tmp + suffix_off, in_tail);
        size_t from_new = len;
        write_chunk(dst, data, from_new);
      } else {
        size_t start_in_new = suffix_off - is->tail_len;
        if (start_in_new < len) {
          size_t sl = len - start_in_new;
          write_chunk(dst, data + start_in_new, sl);
        }
      }
    }

    // Reset tail now that injection is done
    is->tail_len = 0;
  } else {
    // No match: stream most of it but keep last window
    size_t keep = MIN(sizeof(is->tail), total);
    size_t emit = (total > keep) ? (total - keep) : 0;

    if (emit > 0) {
      // emit from tmp[0..emit)
      write_chunk(dst, tmp, emit);
      // new tail = last 'keep' bytes
      if (keep > 0) {
        memcpy(is->tail, tmp + emit, keep);
        is->tail_len = keep;
      } else {
        is->tail_len = 0;
      }
    } else {
      // nothing to emit yet; just keep in tail
      memcpy(is->tail, tmp, total);
      is->tail_len = total;
    }
  }

  free(low);
  free(tmp);
}

/* At EOF: if we were injecting and not done, append injection now. Also flush
 * any tail. */
static void inj_finish(struct bufferevent* dst, struct inject_state* is) {
  if (is->tail_len) {
    write_chunk(dst, (const uint8_t*)is->tail, is->tail_len);
    is->tail_len = 0;
  }
  if (is->enabled && !is->done) {
    const char* inj = INJECT_HTML;
    write_chunk(dst, (const uint8_t*)inj, strlen(inj));
    is->done = 1;
  }
}

/* ================== Relay Context ================== */

struct relay_ctx {
  struct proxy_instance* prx;
  struct bufferevent* self_bev;
  struct bufferevent* peer_bev;

  int is_server_to_client;  // direction flag

  // Response-side state
  int headers_parsed;
  int origin_chunked;
  enum ce_kind ce;
  int is_html;
  int has_body;
  int downstream_chunked;  // we switch to chunked if modifying/decompressing
  int modifying;           // we plan to inject / remove CSP / strip encodings

  // request method (for HEAD detection)
  char req_method[16];

  // HTTP response code
  int status_code;

  // For chunked decode
  struct chunked_decoder chdec;

  // For decompress
  struct zlib_dec zdec;
  struct br_dec brdec;

  // Injector
  struct inject_state inj;

  // Buffers used during parsing
  struct evbuffer* scratch;  // general working buffer
};

static struct relay_ctx* ctx_new(struct proxy_instance* prx,
                                 struct bufferevent* self,
                                 struct bufferevent* peer, int is_s2c) {
  struct relay_ctx* c = calloc(1, sizeof(*c));
  if (!c) return NULL;
  c->prx = prx;
  c->self_bev = self;
  c->peer_bev = peer;
  c->is_server_to_client = is_s2c;
  c->scratch = evbuffer_new();
  chdec_init(&c->chdec);
  zdec_init(&c->zdec);
  brdec_init(&c->brdec);
  inj_init(&c->inj);
  return c;
}

static void ctx_free(struct relay_ctx* c) {
  if (!c) return;
  if (c->scratch) evbuffer_free(c->scratch);
  zdec_end(&c->zdec);
  brdec_end(&c->brdec);
  free(c);
}

/* ============= Client request path (C->P->S) ============= */

static char* remove_proxy_conn_and_accept_encoding(const char* req) {
  // Remove Proxy-Connection and Accept-Encoding headers; add Accept-Encoding:
  // identity
  char* dup = strdup(req);
  if (!dup) return NULL;
  // normalize line by line
  char* out = calloc(1, strlen(dup) + 128);
  if (!out) {
    free(dup);
    return NULL;
  }
  char* save = NULL;
  char* line = strtok_r(dup, "\r\n", &save);
  int first = 1, added_ae = 0;
  while (line) {
    char* next = strtok_r(NULL, "\r\n", &save);
    if (first) {
      strcat(out, line);
      strcat(out, "\r\n");
      first = 0;
    } else {
      char lower[512];
      snprintf(lower, sizeof(lower), "%s", line);
      strlower(lower);
      if (strstr(lower, "proxy-connection:") == lower) {
        // skip
      } else if (strstr(lower, "accept-encoding:") == lower) {
        // skip and add identity later
      } else {
        strcat(out, line);
        strcat(out, "\r\n");
      }
    }
    line = next;
  }
  strcat(out, "Accept-Encoding: identity\r\n\r\n");
  free(dup);
  return out;
}

/* ============= Server response path (S->P->C) parsing ============= */

static enum ce_kind parse_ce(const char* v) {
  if (!v) return CE_IDENTITY;
  char low[128];
  snprintf(low, sizeof(low), "%s", v);
  strlower(low);
  if (strstr(low, "gzip")) return CE_GZIP;
  if (strstr(low, "deflate")) return CE_DEFLATE;
  if (strstr(low, "br")) return CE_BR;
  return CE_UNKNOWN;
}

static int is_text_html(const char* v) {
  if (!v) return 0;
  char low[128];
  snprintf(low, sizeof(low), "%s", v);
  strlower(low);
  return (strstr(low, "text/html") != NULL);
}

static int response_has_body(int status_code, const char* method,
                             struct http_headers* hh) {
  // no body for HEAD, 1xx, 204, 304
  if (method && strcasecmp(method, "HEAD") == 0) return 0;
  if (status_code >= 100 && status_code < 200) return 0;
  if (status_code == 204 || status_code == 304) return 0;
  // Connection: upgrade? (websocket) -> treat as no-modify
  const char* conn = hh_get_ci(hh, "Connection");
  const char* up = hh_get_ci(hh, "Upgrade");
  if (conn && strcasestr_portable(conn, "upgrade")) return 0;
  if (up) return 0;
  // text/event-stream (SSE) -> leave alone
  const char* ct = hh_get_ci(hh, "Content-Type");
  if (ct) {
    char low[128];
    snprintf(low, sizeof(low), "%s", ct);
    strlower(low);
    if (strstr(low, "text/event-stream")) return 0;
  }
  return 1;
}

static void server_send_headers_rewritten(struct relay_ctx* rc,
                                          struct http_headers* hh) {
  // remove headers that conflict with our streaming modify
  hh_remove_all_ci(hh, "Content-Length");
  hh_remove_all_ci(hh, "Content-MD5");
  hh_remove_all_ci(hh, "ETag");

  if (rc->modifying) {
    // We'll output identity content, chunked
    hh_remove_all_ci(hh, "Content-Encoding");
    hh_remove_all_ci(hh, "Transfer-Encoding");
#if ALWAYS_REMOVE_CSP
    hh_remove_all_ci(hh, "Content-Security-Policy");
    hh_remove_all_ci(hh, "Content-Security-Policy-Report-Only");
#endif
    hh_set(hh, "Transfer-Encoding", "chunked");
    rc->downstream_chunked = 1;
  } else {
    // pass upstream TE/CL unchanged; no modification
    rc->downstream_chunked = 0;
  }

  // Send headers to client
  hh_write(hh, rc->peer_bev);
}

/* ============= Relay callbacks ============= */

static void relay_event_cb(struct bufferevent* bev, short what, void* arg);

static void relay_server_read_cb(struct bufferevent* bev, void* arg) {
  struct relay_ctx* rc = (struct relay_ctx*)arg;
  struct evbuffer* in = bufferevent_get_input(bev);

  // Step 1: parse response headers once
  if (!rc->headers_parsed) {
    struct evbuffer_ptr p = evbuffer_search(in, "\r\n\r\n", 4, NULL);
    if (p.pos == -1) return;  // need more
    size_t hdr_len = (size_t)p.pos + 4;

    // Copy and parse
    unsigned char* hdrs = malloc(hdr_len);
    if (!hdrs) {
      evbuffer_drain(in, hdr_len);
      return;
    }
    evbuffer_copyout(in, hdrs, hdr_len);

    struct http_headers hh;
    hh_init(&hh, 1);
    if (!hh_parse((const char*)hdrs, hdr_len, 1, &hh)) {
      free(hdrs);
      evbuffer_drain(in, hdr_len);
      // pass-through headers if parse failed
      bufferevent_write(rc->peer_bev, hdrs, hdr_len);
      rc->headers_parsed = 1;
      return;
    }
    free(hdrs);

    // Parse status code
    rc->status_code = 0;
    if (hh.status_line && strlen(hh.status_line) >= 12) {
      const char* sp = strchr(hh.status_line, ' ');
      if (sp) rc->status_code = atoi(sp + 1);
    }

    const char* ct = hh_get_ci(&hh, "Content-Type");
    const char* ce = hh_get_ci(&hh, "Content-Encoding");
    const char* te = hh_get_ci(&hh, "Transfer-Encoding");

    rc->ce = parse_ce(ce);
    rc->is_html = is_text_html(ct);
    rc->origin_chunked = (te && strcasestr_portable(te, "chunked") != NULL);
    rc->has_body = response_has_body(rc->status_code, rc->req_method, &hh);

    rc->modifying = (rc->has_body && rc->is_html);  // Only modify HTML bodies
    rc->inj.enabled = rc->modifying;

    // Send rewritten headers now (strip CSP/CE/CL, add chunked if needed)
    server_send_headers_rewritten(rc, &hh);
    hh_free(&hh);

    // Drain origin headers from input
    evbuffer_drain(in, hdr_len);

    rc->headers_parsed = 1;
    // Initialize chunked decoder if needed
    if (rc->origin_chunked) chdec_init(&rc->chdec);
  }

  // Step 2: stream body
  if (!rc->has_body) {
    // nothing to do; just wait EOF to close
    return;
  }

  // Pipeline: origin in -> (optional chunked decode) -> (optional decompress)
  // -> inject & chunk-encode (downstream) We'll use rc->scratch as the
  // intermediate buffer at each step.

  // 2a: from origin input to scratch_body (plain body bytes)
  struct evbuffer* scratch_body = rc->scratch;
  size_t made_progress = 0;

  for (;;) {
    int progress = 0;
    if (rc->origin_chunked) {
      progress = chdec_process(&rc->chdec, in, scratch_body);
    } else {
      // Not chunked: move all available to scratch_body
      size_t avail = evbuffer_get_length(in);
      if (avail == 0) break;
      evbuffer_remove_buffer(in, scratch_body, avail);
      progress = (int)(avail > 0);
    }
    if (progress < 0) {
      loge(rc->prx->log_err, "[ERR] chunked decode error");
      break;
    }
    if (!progress) break;
    made_progress = 1;

    // 2b: decompress if needed into scratch_dec
    struct evbuffer* scratch_dec = evbuffer_new();
    if (!scratch_dec) return;

    int dec_progress = 0;
    if (rc->modifying && (rc->ce == CE_GZIP || rc->ce == CE_DEFLATE)) {
      dec_progress = zdec_process(&rc->zdec, rc->ce, scratch_body, scratch_dec);
    } else if (rc->modifying && rc->ce == CE_BR) {
      dec_progress = brdec_process(&rc->brdec, scratch_body, scratch_dec);
    } else {
      // no decompression required: move straight across
      size_t avail = evbuffer_get_length(scratch_body);
      if (avail > 0) {
        evbuffer_remove_buffer(scratch_body, scratch_dec, avail);
        dec_progress = 1;
      }
    }

    // 2c: inject & chunk-encode downstream
    size_t avail = evbuffer_get_length(scratch_dec);
    if (avail > 0) {
      unsigned char* buf = malloc(avail);
      if (buf) {
        evbuffer_remove(scratch_dec, buf, avail);
        if (rc->modifying) {
          write_injected_stream(rc->peer_bev, buf, avail, &rc->inj);
        } else {
          // Pass-through unmodified (we didn't switch to downstream chunked)
          bufferevent_write(rc->peer_bev, buf, avail);
        }
        free(buf);
      } else {
        evbuffer_drain(scratch_dec, avail);
      }
    }
    evbuffer_free(scratch_dec);
  }

  (void)made_progress;
}

static void relay_client_read_cb(struct bufferevent* bev, void* arg) {
  // Client -> Server path: forward requests, strip Proxy-Connection and
  // Accept-Encoding
  struct relay_ctx* rc = (struct relay_ctx*)arg;
  struct evbuffer* in = bufferevent_get_input(bev);
  size_t len = evbuffer_get_length(in);
  if (!len) return;

  unsigned char* buf = malloc(len + 1);
  if (!buf) {
    evbuffer_drain(in, len);
    return;
  }
  evbuffer_copyout(in, buf, len);
  buf[len] = 0;

  // Only massage HTTP request lines/headers (before CONNECT tunnel)
  // Detect full headers:
  struct evbuffer_ptr p = evbuffer_search(in, "\r\n\r\n", 4, NULL);
  if (p.pos == -1) {
    free(buf);
    return;
  }  // need more
  size_t hdr_len = (size_t)p.pos + 4;
  char* hdr = malloc(hdr_len + 1);
  if (!hdr) {
    free(buf);
    return;
  }
  evbuffer_remove(in, hdr, hdr_len);
  hdr[hdr_len] = 0;

  // Extract method (for response no-body decisions)
  {
    // first token
    char* sp = strchr(hdr, ' ');
    size_t mlen = sp ? (size_t)(sp - hdr) : 0;
    memset(rc->req_method, 0, sizeof(rc->req_method));
    if (mlen > 0 && mlen < sizeof(rc->req_method))
      memcpy(rc->req_method, hdr, mlen);
  }

  if (strncmp(hdr, "CONNECT ", 8) == 0) {
    // Forward CONNECT to CONNECT handler (handled in accept_cb flow),
    // but this path shouldn't get here for CONNECT after we've switched
    // callbacks.
    bufferevent_write(rc->peer_bev, hdr, hdr_len);
    free(hdr);
    free(buf);
    return;
  }

  char* modified = remove_proxy_conn_and_accept_encoding(hdr);
  if (!modified) {
    bufferevent_write(rc->peer_bev, hdr, hdr_len);
  } else {
    bufferevent_write(rc->peer_bev, modified, strlen(modified));
    free(modified);
  }
  free(hdr);

  // Forward any extra already in evbuffer (normally none here, since we stopped
  // at headers)
  size_t rem = evbuffer_get_length(in);
  if (rem) {
    evbuffer_remove_buffer(in, bufferevent_get_output(rc->peer_bev), rem);
  }

  free(buf);
}

static void relay_event_cb(struct bufferevent* bev, short what, void* arg) {
  struct relay_ctx* rc = (struct relay_ctx*)arg;

  if (what & BEV_EVENT_ERROR) {
    unsigned long e;
    while ((e = bufferevent_get_openssl_error(bev))) {
      char buf[256];
      ERR_error_string_n(e, buf, sizeof(buf));
      loge(rc->prx->log_err, "[SSL] %s", buf);
    }
  }

  if (what & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
    if (rc->is_server_to_client) {
      // finalize downstream if we were chunking and injecting
      if (rc->modifying && rc->downstream_chunked) {
        inj_finish(rc->peer_bev, &rc->inj);
        write_chunk_zero(rc->peer_bev);
      }
    }
    // Free both directions
    if (rc->peer_bev) bufferevent_free(rc->peer_bev);
    bufferevent_free(rc->self_bev);
    ctx_free(rc);
  }
}

/* =============== CONNECT handling =============== */

static void connect_to_origin(struct proxy_instance* prx, const char* host,
                              int port, struct bufferevent** out_bev_upstream,
                              SSL** out_ssl, SSL_CTX** out_ctx) {
  *out_bev_upstream = NULL;
  *out_ssl = NULL;
  *out_ctx = NULL;

  SSL_CTX* sctx = create_upstream_ctx();
  if (!sctx) return;
  SSL* ssl = SSL_new(sctx);
  if (!ssl) {
    SSL_CTX_free(sctx);
    return;
  }

  // SNI
  if (host) SSL_set_tlsext_host_name(ssl, host);

  struct bufferevent* bev = bufferevent_openssl_socket_new(
      prx->base, -1, ssl, BUFFEREVENT_SSL_CONNECTING,
      BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
  if (!bev) {
    SSL_free(ssl);
    SSL_CTX_free(sctx);
    return;
  }

  // Resolve and connect
  char port_s[8];
  snprintf(port_s, sizeof(port_s), "%d", port);
  struct addrinfo hints, *res = NULL;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  int rc = getaddrinfo(host, port_s, &hints, &res);
  if (rc != 0 || !res) {
    bufferevent_free(bev);
    SSL_CTX_free(sctx);
    return;
  }

  if (bufferevent_socket_connect(bev, res->ai_addr, res->ai_addrlen) < 0) {
    bufferevent_free(bev);
    SSL_CTX_free(sctx);
    freeaddrinfo(res);
    return;
  }

  freeaddrinfo(res);
  *out_bev_upstream = bev;
  *out_ssl = ssl;
  *out_ctx = sctx;
}

static void handle_connect(struct proxy_instance* prx,
                           struct bufferevent* client_bev, const char* line) {
  // line ~ "CONNECT host:443 HTTP/1.1"
  char host[512];
  int port = 443;
  if (sscanf(line, "CONNECT %511[^:]:%d", host, &port) != 2) {
    // Some clients send CONNECT host:443 HTTP/1.1; handle with sscanf variant
    char tmp[512];
    if (sscanf(line, "CONNECT %511s", tmp) == 1) {
      // tmp could be host:port or just host
      char* colon = strchr(tmp, ':');
      if (colon) {
        *colon = 0;
        port = atoi(colon + 1);
      }
      snprintf(host, sizeof(host), "%s", tmp);
    } else {
      loge(prx->log_err, "Bad CONNECT line: %s", line);
      bufferevent_write(client_bev, "HTTP/1.1 400 Bad Request\r\n\r\n", 28);
      return;
    }
  }

  // Ack CONNECT
  bufferevent_write(client_bev, "HTTP/1.1 200 Connection Established\r\n\r\n",
                    40);

  // Create leaf cert for host and wrap client socket with TLS (server)
  X509* leaf = NULL;
  EVP_PKEY* leaf_key = NULL;
  if (!generate_leaf_for_host(host, &leaf, &leaf_key)) {
    loge(prx->log_err, "Leaf cert gen failed for %s", host);
    bufferevent_flush(client_bev, EV_WRITE, BEV_FLUSH);
    bufferevent_free(client_bev);
    return;
  }
  SSL_CTX* down_ctx = create_downstream_ctx(leaf, leaf_key);
  X509_free(leaf);
  EVP_PKEY_free(leaf_key);
  if (!down_ctx) {
    bufferevent_free(client_bev);
    return;
  }
  SSL* down_ssl = SSL_new(down_ctx);
  if (!down_ssl) {
    SSL_CTX_free(down_ctx);
    bufferevent_free(client_bev);
    return;
  }

  struct bufferevent* client_tls = bufferevent_openssl_filter_new(
      prx->base, client_bev, down_ssl, BUFFEREVENT_SSL_ACCEPTING,
      BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
  if (!client_tls) {
    SSL_CTX_free(down_ctx);
    bufferevent_free(client_bev);
    return;
  }

  // Upstream TLS
  struct bufferevent* up_bev = NULL;
  SSL* up_ssl = NULL;
  SSL_CTX* up_ctx = NULL;
  connect_to_origin(prx, host, port, &up_bev, &up_ssl, &up_ctx);
  if (!up_bev) {
    bufferevent_free(client_tls);
    SSL_CTX_free(down_ctx);
    return;
  }

  // Set up relay
  struct relay_ctx* srv_to_cli = ctx_new(prx, up_bev, client_tls, 1);
  struct relay_ctx* cli_to_srv = ctx_new(prx, client_tls, up_bev, 0);

  bufferevent_setcb(up_bev, relay_server_read_cb, NULL, relay_event_cb,
                    srv_to_cli);
  bufferevent_setcb(client_tls, relay_client_read_cb, NULL, relay_event_cb,
                    cli_to_srv);

  bufferevent_enable(up_bev, EV_READ | EV_WRITE);
  bufferevent_enable(client_tls, EV_READ | EV_WRITE);
}

/* =============== Accept / first-read (HTTP or CONNECT) =============== */

static void first_read_cb(struct bufferevent* bev, void* arg) {
  struct proxy_instance* prx = (struct proxy_instance*)arg;
  struct evbuffer* in = bufferevent_get_input(bev);
  size_t len = evbuffer_get_length(in);
  if (len < 4) return;

  struct evbuffer_ptr p = evbuffer_search(in, "\r\n\r\n", 4, NULL);
  if (p.pos == -1) return;

  size_t hdr_len = (size_t)p.pos + 4;
  char* hdr = malloc(hdr_len + 1);
  if (!hdr) {
    evbuffer_drain(in, hdr_len);
    return;
  }
  evbuffer_copyout(in, hdr, hdr_len);
  hdr[hdr_len] = 0;

  // Extract the request line
  char* line_end = strstr(hdr, "\r\n");
  if (!line_end) {
    free(hdr);
    evbuffer_drain(in, hdr_len);
    return;
  }
  *line_end = 0;

  if (strncmp(hdr, "CONNECT ", 8) == 0) {
    // Drain headers so CONNECT handler starts fresh
    evbuffer_drain(in, hdr_len);
    handle_connect(prx, bev, hdr);
    free(hdr);
    return;
  }

  // Plain HTTP (no TLS)
  // We'll build a server connection and then set up streaming relay (no SSL
  // filter).
  char method[16], url[2048], proto[16];
  if (sscanf(hdr, "%15s %2047s %15s", method, url, proto) != 3) {
    free(hdr);
    evbuffer_drain(in, hdr_len);
    bufferevent_write(bev, "HTTP/1.1 400 Bad Request\r\n\r\n", 28);
    bufferevent_free(bev);
    return;
  }

  // Parse host from absolute-form URL "http://host[:port]/path..."
  char host[512];
  int port = 80;
  memset(host, 0, sizeof(host));
  if (strncasecmp(url, "http://", 7) == 0) {
    const char* h = url + 7;
    const char* slash = strchr(h, '/');
    size_t hlen = slash ? (size_t)(slash - h) : strlen(h);
    char hostport[512];
    if (hlen >= sizeof(hostport)) hlen = sizeof(hostport) - 1;
    memcpy(hostport, h, hlen);
    hostport[hlen] = 0;
    char* colon = strchr(hostport, ':');
    if (colon) {
      *colon = 0;
      port = atoi(colon + 1);
    }
    snprintf(host, sizeof(host), "%s", hostport);
  } else {
    // relative-form; fallback to Host header
    // we’ll read from hdr block (which includes Host:)
    char* host_hdr = strcasestr_portable(hdr, "\r\nHost:");
    if (host_hdr) {
      host_hdr += 7;
      while (*host_hdr == ' ' || *host_hdr == '\t') host_hdr++;
      char* eol = strstr(host_hdr, "\r\n");
      size_t hlen = eol ? (size_t)(eol - host_hdr) : strlen(host_hdr);
      if (hlen >= sizeof(host)) hlen = sizeof(host) - 1;
      memcpy(host, host_hdr, hlen);
      host[hlen] = 0;
      char* colon = strchr(host, ':');
      if (colon) {
        *colon = 0;
        port = atoi(colon + 1);
      }
    } else {
      // No Host: header found; bad request
      free(hdr);
      evbuffer_drain(in, hdr_len);
      bufferevent_write(bev, "HTTP/1.1 400 Bad Request\r\n\r\n", 28);
      bufferevent_free(bev);
      return;
    }
  }

  // Connect to origin over TCP (no TLS)
  struct bufferevent* srv = bufferevent_socket_new(
      prx->base, -1, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
  if (!srv) {
    free(hdr);
    evbuffer_drain(in, hdr_len);
    bufferevent_free(bev);
    return;
  }

  char port_s[8];
  snprintf(port_s, sizeof(port_s), "%d", port);
  struct addrinfo hints, *res = NULL;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  if (getaddrinfo(host, port_s, &hints, &res) != 0 || !res) {
    bufferevent_free(srv);
    bufferevent_free(bev);
    free(hdr);
    return;
  }
  if (bufferevent_socket_connect(srv, res->ai_addr, res->ai_addrlen) < 0) {
    freeaddrinfo(res);
    bufferevent_free(srv);
    bufferevent_free(bev);
    free(hdr);
    return;
  }
  freeaddrinfo(res);

  // Switch callbacks to streaming relay: client<->server (plain)
  struct relay_ctx* c2s = ctx_new(prx, bev, srv, 0);
  struct relay_ctx* s2c = ctx_new(prx, srv, bev, 1);

  // initial method capture for HEAD handling on plain HTTP
  snprintf(c2s->req_method, sizeof(c2s->req_method), "%s", method);
  snprintf(s2c->req_method, sizeof(s2c->req_method), "%s", method);

  bufferevent_setcb(bev, relay_client_read_cb, NULL, relay_event_cb, c2s);
  bufferevent_setcb(srv, relay_server_read_cb, NULL, relay_event_cb, s2c);

  bufferevent_enable(bev, EV_READ | EV_WRITE);
  bufferevent_enable(srv, EV_READ | EV_WRITE);

  // Put back the request we already read (but with header rewriting)
  char* mod = remove_proxy_conn_and_accept_encoding(hdr);
  if (mod) {
    bufferevent_write(srv, mod, strlen(mod));
    free(mod);
  } else {
    bufferevent_write(srv, hdr, hdr_len);
  }

  free(hdr);

  // Drain any extra request bytes already in evbuffer (rare)
  size_t rem = evbuffer_get_length(in);
  if (rem) evbuffer_remove_buffer(in, bufferevent_get_output(srv), rem);
}

void accept_cb(struct evconnlistener* lev, evutil_socket_t fd,
               struct sockaddr* addr, int socklen, void* arg) {
  (void)addr;
  (void)socklen;
  struct proxy_instance* prx = (struct proxy_instance*)arg;
  struct bufferevent* bev = bufferevent_socket_new(
      prx->base, fd, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
  if (!bev) {
    evutil_closesocket(fd);
    return;
  }
  // Initial read to decide HTTP vs CONNECT; keep context = prx (instance)
  bufferevent_setcb(bev, first_read_cb, NULL, relay_event_cb, prx);
  bufferevent_enable(bev, EV_READ | EV_WRITE);
}

void accept_error_cb(struct evconnlistener* lev, void* arg) {
  struct proxy_instance* prx = (struct proxy_instance*)arg;
  int err = EVUTIL_SOCKET_ERROR();
  loge(prx->log_err, "Listener error %d (%s)", err,
       evutil_socket_error_to_string(err));
}
