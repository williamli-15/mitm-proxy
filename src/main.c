#include <signal.h>
#include <stdlib.h>
#include <string.h>

#include "proxy.h"
#include "ssl_utils.h"

static void on_sigint(evutil_socket_t sig, short events, void* arg) {
  struct proxy_instance* prx = (struct proxy_instance*)arg;
  (void)sig;
  (void)events;

  fprintf(stderr, "\nCaught SIGINT, shutting down...\n");
  event_base_loopexit(prx->base, NULL);
}

int main(int argc, char** argv) {
  (void)argc;
  (void)argv;

  // Init SSL and CA
  if (!ssl_global_init()) {
    fprintf(stderr, "SSL init failed\n");
    return 1;
  }

  if (!ca_init("ca/ca.crt", "ca/ca.key")) {
    fprintf(stderr,
            "Load CA failed. Run ./generate_ca.sh and import ca/ca.crt into "
            "browser.\n");
    return 1;
  }

  struct event_base* base = event_base_new();
  if (!base) {
    fprintf(stderr, "event_base_new failed\n");
    return 1;
  }

  struct proxy_instance prx = {0};
  prx.base = base;
  prx.log_out = stdout;
  prx.log_err = stderr;

  // Listen 0.0.0.0:8080
  struct sockaddr_in sin;
  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = htonl(INADDR_ANY);
  sin.sin_port = htons(PROXY_LISTEN_PORT);

  struct evconnlistener* lev = evconnlistener_new_bind(
      base, accept_cb, &prx, LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, -1,
      (struct sockaddr*)&sin, sizeof(sin));

  if (!lev) {
    perror("evconnlistener_new_bind");
    return 1;
  }

  evconnlistener_set_error_cb(lev, accept_error_cb);

  // SIGINT to exit
  struct event* sig_ev = evsignal_new(base, SIGINT, on_sigint, &prx);
  event_add(sig_ev, NULL);

  printf("MITM proxy listening on 0.0.0.0:%d\n", PROXY_LISTEN_PORT);
  printf("Import ./ca/ca.crt into your browser trust store.\n");
  printf(
      "Try: curl -v -x http://127.0.0.1:%d --cacert ca/ca.crt "
      "https://example.com/\n",
      PROXY_LISTEN_PORT);

  event_base_dispatch(base);

  event_free(sig_ev);
  evconnlistener_free(lev);
  event_base_free(base);
  ca_free();

  return 0;
}
