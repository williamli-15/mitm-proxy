#ifndef PROXY_H
#define PROXY_H

#include <event2/bufferevent.h>
#include <event2/event.h>
#include <event2/listener.h>
#include <openssl/ssl.h>
#include <stdio.h>

// Build-time switches
#define ALWAYS_REMOVE_CSP 1  // remove CSP when injecting to ensure badge shows

// Listening port
#define PROXY_LISTEN_PORT 8080

struct proxy_instance {
  struct event_base* base;
  FILE* log_out;
  FILE* log_err;
};

void accept_cb(struct evconnlistener* lev, evutil_socket_t fd,
               struct sockaddr* addr, int socklen, void* arg);

void accept_error_cb(struct evconnlistener* lev, void* arg);

#endif
