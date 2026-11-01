/**
 * Copyright (C) 2022 Carnegie Mellon University
 *
 * This file is part of the TCP in the Wild course project developed for the
 * Computer Networks course (15-441/641) taught at Carnegie Mellon University.
 *
 * No part of the project may be copied and/or distributed without the express
 * permission of the 15-441/641 course staff.
 *
 *
 * This file implements the high-level API for CMU-TCP sockets.
 */

#include "cmu_tcp.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "backend.h"

int cmu_socket(cmu_socket_t *sock, const cmu_socket_type_t socket_type,
               const int port, const char *server_ip) {
  int sockfd, optval;
  socklen_t len;
  struct sockaddr_in conn, my_addr;
  len = sizeof(my_addr);

  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    perror("ERROR opening socket");
    return EXIT_ERROR;
  }
  sock->socket = sockfd;
  sock->received_buf = NULL;
  sock->received_len = 0;
  sock->ooo_head = NULL;
  sock->ooo_bytes = 0;
  sock->adv_cache = (MAX_NETWORK_BUFFER > 65535) ? 65535 : MAX_NETWORK_BUFFER;
  pthread_mutex_init(&(sock->recv_lock), NULL);

  sock->sending_buf = NULL;
  sock->sending_len = 0;
  pthread_mutex_init(&(sock->send_lock), NULL);
  pthread_cond_init(&(sock->send_cond), NULL);

  sock->type = socket_type;
  sock->dying = 0;
  pthread_mutex_init(&(sock->death_lock), NULL);

  // Sequence numbers should be randomly initialized. The next expected
  // sequence number should be initialized according to the SYN packet from the
  // other side of the connection.
  srand(time(NULL) ^ getpid());
  sock->window.my_isn = rand();
  sock->window.last_ack_received = sock->window.my_isn;
  sock->window.next_seq_to_send = sock->window.my_isn;
  sock->window.highwater = sock->window.my_isn;
  sock->window.next_seq_expected = 0;
  sock->window.size = WINDOW_INITIAL_WINDOW_SIZE;
  sock->window.cwnd = WINDOW_INITIAL_WINDOW_SIZE;
  sock->window.ssthresh = WINDOW_INITIAL_SSTHRESH;
  sock->window.ca_carry = 0;
  sock->window.cc_state = (WINDOW_INITIAL_WINDOW_SIZE < WINDOW_INITIAL_SSTHRESH)
                              ? CC_SLOW_START
                              : CC_AVOIDANCE;
  sock->window.dup_ack_count = 0;
  sock->window.do_fast_retransmit = 0;
  sock->window.peer_adv_window = sock->adv_cache;
  sock->window.zero_advertised = 0;
  sock->window.last_wnd_update.tv_sec = 0;
  sock->window.last_wnd_update.tv_usec = 0;

  if (pthread_cond_init(&sock->wait_cond, NULL) != 0) {
    perror("ERROR condition variable not set\n");
    return EXIT_ERROR;
  }

  switch (socket_type) {
    case TCP_INITIATOR:
      if (server_ip == NULL) {
        perror("ERROR server_ip NULL");
        return EXIT_ERROR;
      }
      memset(&conn, 0, sizeof(conn));
      conn.sin_family = AF_INET;
      conn.sin_addr.s_addr = inet_addr(server_ip);
      conn.sin_port = htons(port);
      sock->conn = conn;

      my_addr.sin_family = AF_INET;
      my_addr.sin_addr.s_addr = htonl(INADDR_ANY);
      my_addr.sin_port = 0;
      if (bind(sockfd, (struct sockaddr *)&my_addr, sizeof(my_addr)) < 0) {
        perror("ERROR on binding");
        return EXIT_ERROR;
      }

      break;

    case TCP_LISTENER:
      memset(&conn, 0, sizeof(conn));
      conn.sin_family = AF_INET;
      conn.sin_addr.s_addr = htonl(INADDR_ANY);
      conn.sin_port = htons((uint16_t)port);

      optval = 1;
      setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval,
                 sizeof(int));
      if (bind(sockfd, (struct sockaddr *)&conn, sizeof(conn)) < 0) {
        perror("ERROR on binding");
        return EXIT_ERROR;
      }
      sock->conn = conn;
      break;

    default:
      perror("Unknown Flag");
      return EXIT_ERROR;
  }
  getsockname(sockfd, (struct sockaddr *)&my_addr, &len);
  sock->my_port = ntohs(my_addr.sin_port);

  pthread_create(&(sock->thread_id), NULL, begin_backend, (void *)sock);
  return EXIT_SUCCESS;
}

int cmu_close(cmu_socket_t *sock) {
  while (pthread_mutex_lock(&(sock->death_lock)) != 0) {
  }
  sock->dying = 1;
  pthread_mutex_unlock(&(sock->death_lock));

  pthread_join(sock->thread_id, NULL);

  if (sock != NULL) {
    if (sock->received_buf != NULL) {
      free(sock->received_buf);
    }
    if (sock->sending_buf != NULL) {
      free(sock->sending_buf);
    }
    while (sock->ooo_head != NULL) {
      recv_seg_t* seg = sock->ooo_head;
      sock->ooo_head = seg->next;
      free(seg->data);
      free(seg);
    }
  } else {
    perror("ERROR null socket\n");
    return EXIT_ERROR;
  }
  return close(sock->socket);
}

int cmu_read(cmu_socket_t *sock, void *buf, int length, cmu_read_mode_t flags) {
  uint8_t *new_buf;
  int read_len = 0;

  if (length < 0) {
    perror("ERROR negative length");
    return EXIT_ERROR;
  }

  while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {
  }

  switch (flags) {
    case NO_FLAG:
      while (sock->received_len == 0) {
        pthread_cond_wait(&(sock->wait_cond), &(sock->recv_lock));
      }
    // Fall through.
    case NO_WAIT:
      // Only do smth if there is data to read.
      if (sock->received_len > 0) {
        if (sock->received_len > length)
          read_len = length;
        else
          read_len = sock->received_len;

        // Copy received_buf data to buf 
        memcpy(buf, sock->received_buf, read_len);
        if (read_len < sock->received_len) {
          new_buf = malloc(sock->received_len - read_len);
          memcpy(new_buf, sock->received_buf + read_len,
                 sock->received_len - read_len);
          free(sock->received_buf);
          sock->received_len -= read_len;
          sock->received_buf = new_buf;
        } else {
          free(sock->received_buf);
          sock->received_buf = NULL;
          sock->received_len = 0;
        }
        // A full window stays shut until the application reads. Tell the
        // peer once, when this read is what opens it. Later reads piggyback
        // the new window on ordinary ACKs, so we don't emit extra dup ACKs.
        int was_closed = sock->adv_cache == 0;
        refresh_adv_cache(sock);
        if (was_closed && sock->adv_cache > 0) {
          send_window_update(sock);
        }
      }
      break;
    default:
      perror("ERROR Unknown flag.\n");
      read_len = EXIT_ERROR;
  }
  pthread_mutex_unlock(&(sock->recv_lock));
  return read_len;
}

int cmu_write(cmu_socket_t *sock, const void *buf, int length) {
  const uint8_t *src = buf;
  int off = 0;

  if (length < 0) {
    perror("ERROR negative length");
    return EXIT_ERROR;
  }

  // Queue at most MAX_NETWORK_BUFFER bytes that the backend has not taken
  // yet. A large write blocks here instead of growing the buffer without bound.
  while (off < length) {
    while (pthread_mutex_lock(&(sock->send_lock)) != 0) {
    }
    while (sock->sending_len >= MAX_NETWORK_BUFFER) {
      pthread_cond_wait(&(sock->send_cond), &(sock->send_lock));
    }
    int space = MAX_NETWORK_BUFFER - sock->sending_len;
    int n = length - off;
    if (n > space) n = space;

    if (sock->sending_buf == NULL)
      sock->sending_buf = malloc(n);
    else
      sock->sending_buf = realloc(sock->sending_buf, sock->sending_len + n);
    memcpy(sock->sending_buf + sock->sending_len, src + off, n);
    sock->sending_len += n;
    off += n;
    pthread_mutex_unlock(&(sock->send_lock));
  }
  return EXIT_SUCCESS;
}
