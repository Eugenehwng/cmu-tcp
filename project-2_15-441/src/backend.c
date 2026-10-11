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
 * This file implements the CMU-TCP backend. The backend runs in a different
 * thread and handles all the socket operations separately from the application.
 *
 * This is where most of your code should go. Feel free to modify any function
 * in this file.
 */

#include "backend.h"

#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "cmu_packet.h"
#include "cmu_tcp.h"

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))

/**
 * Connection states stored in window.state.
 */
enum {
  CLOSED = 0,
  SYN_SENT,
  SYN_RCVD,
  ESTABLISHED,
  FIN_WAIT_1,
  FIN_WAIT_2,
  TIME_WAIT,
  LAST_ACK
};

/**
 * Gives up on an unanswered FIN after this many transmissions, so a vanished
 * peer cannot keep cmu_close() from returning.
 */
#define MAX_FIN_TRANSMISSIONS 5

/* ───────────────────────────── Part 0: helpers ───────────────────────────── */

/**
 * Sends a packet with no payload (SYN, SYN-ACK, ACK, FIN).
 */
static void send_control_packet(cmu_socket_t *sock, uint32_t seq, uint32_t ack,
                                uint8_t flags) {
  uint16_t src = sock->my_port;
  uint16_t dst = ntohs(sock->conn.sin_port);
  uint16_t hlen = sizeof(cmu_tcp_header_t);
  uint16_t plen = hlen;
  uint16_t adv_window = 1;

  uint8_t *pkt = create_packet(src, dst, seq, ack, hlen, plen, flags,
                               adv_window, 0, NULL, NULL, 0);
  if (pkt == NULL) return;

  sendto(sock->socket, pkt, plen, 0, (struct sockaddr *)&(sock->conn),
         sizeof(sock->conn));
  free(pkt);
}

/**
 * Sends one data segment covering sequence numbers [seq, seq + len).
 *
 * @param data The buffer passed to single_send.
 * @param seq_base The sequence number of data[0].
 */
static void send_data_segment(cmu_socket_t *sock, uint8_t *data,
                              uint32_t seq_base, uint32_t seq, uint16_t len) {
  uint16_t src = sock->my_port;
  uint16_t dst = ntohs(sock->conn.sin_port);
  uint32_t ack = sock->window.next_seq_expected;
  uint16_t hlen = sizeof(cmu_tcp_header_t);
  uint16_t plen = hlen + len;
  uint16_t adv_window = 1;

  uint8_t *pkt =
      create_packet(src, dst, seq, ack, hlen, plen, ACK_FLAG_MASK, adv_window,
                    0, NULL, data + (seq - seq_base), len);
  if (pkt == NULL) return;

  sendto(sock->socket, pkt, plen, 0, (struct sockaddr *)&(sock->conn),
         sizeof(sock->conn));
  free(pkt);
}

/**
 * Waits up to timeout_ms for one packet (-1 blocks forever, 0 never blocks).
 *
 * The sender's address is written to `from`, not to sock->conn, so that
 * garbage packets cannot redirect the connection. Callers copy it into
 * sock->conn once they decide to accept the packet.
 *
 * @return malloc'd packet buffer (caller frees), or NULL on timeout/error.
 */
static uint8_t *recv_packet_timeout(cmu_socket_t *sock, int timeout_ms,
                                    struct sockaddr_in *from) {
  struct pollfd pfd;
  pfd.fd = sock->socket;
  pfd.events = POLLIN;

  if (poll(&pfd, 1, timeout_ms) <= 0) {
    return NULL;
  }

  cmu_tcp_header_t hdr;
  socklen_t from_len = sizeof(*from);
  ssize_t n = recvfrom(sock->socket, &hdr, sizeof(hdr), MSG_PEEK | MSG_DONTWAIT,
                       (struct sockaddr *)from, &from_len);
  if (n < 0) {
    return NULL;
  }

  if (n < (ssize_t)sizeof(cmu_tcp_header_t)) {
    from_len = sizeof(*from);
    recvfrom(sock->socket, &hdr, sizeof(hdr), MSG_DONTWAIT,
             (struct sockaddr *)from, &from_len);
    return NULL;
  }

  uint16_t plen = get_plen(&hdr);
  if (plen < sizeof(cmu_tcp_header_t) || plen > MAX_LEN) {
    from_len = sizeof(*from);
    recvfrom(sock->socket, &hdr, sizeof(hdr), MSG_DONTWAIT,
             (struct sockaddr *)from, &from_len);
    return NULL;
  }

  uint8_t *pkt = malloc(plen);
  if (pkt == NULL) {
    return NULL;
  }
  from_len = sizeof(*from);
  n = recvfrom(sock->socket, pkt, plen, MSG_DONTWAIT, (struct sockaddr *)from,
               &from_len);

  if (n != (ssize_t)plen) {
    free(pkt);
    return NULL;
  }
  return pkt;
}

static int is_valid_packet(uint8_t *pkt) {
  cmu_tcp_header_t *hdr = (cmu_tcp_header_t *)pkt;
  if (ntohl(hdr->identifier) != IDENTIFIER) return 0;
  if (get_hlen(hdr) < sizeof(cmu_tcp_header_t)) return 0;
  if (get_plen(hdr) < get_hlen(hdr)) return 0;
  if (get_plen(hdr) > MAX_LEN) return 0;
  return 1;
}

static void start_timer(cmu_socket_t *sock) {
  gettimeofday(&(sock->window.timer_start), NULL);
  sock->window.timer_running = 1;
}

static void stop_timer(cmu_socket_t *sock) { sock->window.timer_running = 0; }

/**
 * Milliseconds until the timer fires (0 if already expired). If the timer is
 * not running, returns a full DEFAULT_TIMEOUT.
 */
static int timer_remaining_ms(cmu_socket_t *sock) {
  if (!sock->window.timer_running) return DEFAULT_TIMEOUT;
  struct timeval now;
  gettimeofday(&now, NULL);
  long elapsed_ms = (now.tv_sec - sock->window.timer_start.tv_sec) * 1000 +
                    (now.tv_usec - sock->window.timer_start.tv_usec) / 1000;
  if (elapsed_ms >= DEFAULT_TIMEOUT) return 0;
  return (int)(DEFAULT_TIMEOUT - elapsed_ms);
}

static int timer_expired(cmu_socket_t *sock) {
  return sock->window.timer_running && timer_remaining_ms(sock) == 0;
}

/* ─────────────────────────── receive processing ─────────────────────────── */

/**
 * Updates the socket information to represent the newly received packet.
 *
 * A packet may carry an ACK and data at the same time, so both aspects are
 * processed independently. Must be called with recv_lock held.
 *
 * @param sock The socket used for handling packets received.
 * @param pkt The packet data received by the socket.
 */
void handle_message(cmu_socket_t *sock, uint8_t *pkt) {
  cmu_tcp_header_t *hdr = (cmu_tcp_header_t *)pkt;
  uint8_t flags = get_flags(hdr);
  int is_syn = flags & SYN_FLAG_MASK;
  int is_ack = flags & ACK_FLAG_MASK;
  int is_fin = flags & FIN_FLAG_MASK;
  uint16_t payload_len = get_payload_len(pkt);
  int need_ack = 0;

  if (is_syn) {
    // A retransmitted SYN-ACK after we are ESTABLISHED means our final
    // handshake ACK was lost; the listener is still waiting for it.
    if (is_ack && sock->type == TCP_INITIATOR &&
        get_seq(hdr) == sock->window.peer_isn) {
      send_control_packet(sock, sock->window.next_seq_to_send,
                          sock->window.next_seq_expected, ACK_FLAG_MASK);
    }
    return;
  }

  if (is_ack) {
    uint32_t ack = get_ack(hdr);
    if (after(ack, sock->window.last_ack_received) &&
        !after(ack, sock->window.next_seq_to_send)) {
      sock->window.last_ack_received = ack;
      if (sock->window.last_ack_received == sock->window.next_seq_to_send) {
        stop_timer(sock);
      } else {
        start_timer(sock);
      }
    }
  }

  if (payload_len > 0) {
    if (get_seq(hdr) == sock->window.next_seq_expected) {
      uint8_t *payload = get_payload(pkt);
      sock->received_buf =
          realloc(sock->received_buf, sock->received_len + payload_len);
      memcpy(sock->received_buf + sock->received_len, payload, payload_len);
      sock->received_len += payload_len;
      sock->window.next_seq_expected += payload_len;
      pthread_cond_signal(&(sock->wait_cond));
    }
    // Cumulative ACK, also sent for out-of-order or duplicate data so the
    // sender learns what we are still missing.
    need_ack = 1;
  }

  if (is_fin) {
    // The FIN occupies the sequence number right after the payload.
    if (get_seq(hdr) + payload_len == sock->window.next_seq_expected) {
      sock->window.next_seq_expected += 1;
      sock->window.fin_received = 1;
    }
    // ACK retransmitted FINs too: our previous ACK may have been lost.
    need_ack = 1;
  }

  if (need_ack) {
    send_control_packet(sock, sock->window.next_seq_to_send,
                        sock->window.next_seq_expected, ACK_FLAG_MASK);
  }
}

/**
 * Receives at most one packet (waiting up to timeout_ms) and, if it is a valid
 * CMU-TCP packet, hands it to handle_message().
 *
 * @return 1 if a packet was read from the socket, 0 otherwise.
 */
static int receive_and_handle(cmu_socket_t *sock, int timeout_ms) {
  struct sockaddr_in from;
  uint8_t *pkt = recv_packet_timeout(sock, timeout_ms, &from);
  if (pkt == NULL) return 0;

  if (is_valid_packet(pkt)) {
    while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {
    }
    sock->conn = from;
    handle_message(sock, pkt);
    pthread_mutex_unlock(&(sock->recv_lock));
  }
  free(pkt);
  return 1;
}

/**
 * Checks if the socket received any data.
 *
 * @param sock The socket used for receiving data on the connection.
 * @param flags Flags that determine how the socket should wait for data. Check
 *             `cmu_read_mode_t` for more information.
 */
void check_for_data(cmu_socket_t *sock, cmu_read_mode_t flags) {
  switch (flags) {
    case NO_FLAG:
      receive_and_handle(sock, -1);
      break;
    case TIMEOUT:
      receive_and_handle(sock, DEFAULT_TIMEOUT);
      break;
    case NO_WAIT:
      receive_and_handle(sock, 0);
      break;
    default:
      perror("ERROR unknown flag");
  }
}

/* ─────────────────────────── Part 3: sending ─────────────────────────── */

/**
 * Sends `data` using a fixed-size sliding window with Go-Back-N
 * retransmission. Returns once every byte has been acknowledged.
 *
 * @param sock The socket to use for sending data.
 * @param data The data to be sent.
 * @param buf_len The length of the data being sent.
 */
void single_send(cmu_socket_t *sock, uint8_t *data, int buf_len) {
  if (buf_len <= 0) return;

  uint32_t seq_base = sock->window.next_seq_to_send;
  uint32_t seq_end = seq_base + (uint32_t)buf_len;

  while (sock->window.last_ack_received != seq_end) {
    /* A. Fill the window. */
    while (before(sock->window.next_seq_to_send, seq_end)) {
      uint32_t in_flight =
          sock->window.next_seq_to_send - sock->window.last_ack_received;
      if (in_flight >= sock->window.size) break;
      uint32_t room = sock->window.size - in_flight;
      uint32_t remaining = seq_end - sock->window.next_seq_to_send;
      uint16_t payload_len =
          (uint16_t)MIN((uint32_t)MSS, MIN(remaining, room));

      send_data_segment(sock, data, seq_base, sock->window.next_seq_to_send,
                        payload_len);
      if (!sock->window.timer_running) start_timer(sock);
      sock->window.next_seq_to_send += payload_len;
    }

    /* B. Wait for an ACK, but no longer than the retransmission timer allows,
     * then drain anything else already queued. */
    if (receive_and_handle(sock, timer_remaining_ms(sock))) {
      while (receive_and_handle(sock, 0)) {
      }
    }

    /* C. Go-Back-N: resend everything in [last_ack_received, next_seq). */
    if (timer_expired(sock)) {
      uint32_t s = sock->window.last_ack_received;
      while (before(s, sock->window.next_seq_to_send)) {
        uint16_t len = (uint16_t)MIN((uint32_t)MSS,
                                     sock->window.next_seq_to_send - s);
        send_data_segment(sock, data, seq_base, s, len);
        s += len;
      }
      start_timer(sock);
    }
  }
}

/* ─────────────────────────── Parts 1–2: handshake ─────────────────────────── */

static void initiator_handshake(cmu_socket_t *sock) {
  uint32_t my_isn = sock->window.my_isn;
  struct sockaddr_in from;

  sock->window.state = SYN_SENT;

  while (1) {
    send_control_packet(sock, my_isn, 0, SYN_FLAG_MASK);
    start_timer(sock);

    // Wait out the full timeout before resending, even if junk arrives.
    while (!timer_expired(sock)) {
      uint8_t *pkt = recv_packet_timeout(sock, timer_remaining_ms(sock), &from);
      if (pkt == NULL) continue;

      cmu_tcp_header_t *hdr = (cmu_tcp_header_t *)pkt;
      uint8_t flags = get_flags(hdr);
      if (!is_valid_packet(pkt) || !(flags & SYN_FLAG_MASK) ||
          !(flags & ACK_FLAG_MASK) || (flags & FIN_FLAG_MASK) ||
          get_ack(hdr) != my_isn + 1) {
        free(pkt);
        continue;
      }

      sock->conn = from;
      sock->window.peer_isn = get_seq(hdr);
      sock->window.next_seq_expected = sock->window.peer_isn + 1;

      send_control_packet(sock, my_isn + 1, sock->window.next_seq_expected,
                          ACK_FLAG_MASK);

      sock->window.last_ack_received = my_isn + 1;
      sock->window.next_seq_to_send = my_isn + 1;
      sock->window.state = ESTABLISHED;
      stop_timer(sock);
      free(pkt);
      return;
    }
  }
}

static void listener_handshake(cmu_socket_t *sock) {
  uint32_t my_isn = sock->window.my_isn;
  uint32_t peer_isn = 0;
  struct sockaddr_in from;

  /* Phase A: wait for a valid SYN. Invalid packets get no response. */
  while (1) {
    uint8_t *pkt = recv_packet_timeout(sock, -1, &from);
    if (pkt == NULL) continue;

    cmu_tcp_header_t *hdr = (cmu_tcp_header_t *)pkt;
    uint8_t flags = get_flags(hdr);
    if (!is_valid_packet(pkt) || !(flags & SYN_FLAG_MASK) ||
        (flags & ACK_FLAG_MASK) || (flags & FIN_FLAG_MASK)) {
      free(pkt);
      continue;
    }

    sock->conn = from;
    peer_isn = get_seq(hdr);
    sock->window.peer_isn = peer_isn;
    sock->window.next_seq_expected = peer_isn + 1;
    free(pkt);
    break;
  }

  sock->window.state = SYN_RCVD;
  sock->window.last_ack_received = my_isn + 1;
  sock->window.next_seq_to_send = my_isn + 1;

  /* Phase B: send SYN-ACK, wait for the final ACK (or in-order data). */
  while (1) {
    send_control_packet(sock, my_isn, peer_isn + 1,
                        SYN_FLAG_MASK | ACK_FLAG_MASK);
    start_timer(sock);

    while (!timer_expired(sock)) {
      uint8_t *pkt = recv_packet_timeout(sock, timer_remaining_ms(sock), &from);
      if (pkt == NULL) continue;

      if (!is_valid_packet(pkt)) {
        free(pkt);
        continue;
      }

      cmu_tcp_header_t *hdr = (cmu_tcp_header_t *)pkt;
      uint8_t flags = get_flags(hdr);
      int is_syn = flags & SYN_FLAG_MASK;
      int is_ack = flags & ACK_FLAG_MASK;
      int has_payload = get_payload_len(pkt) > 0;

      // (a) Retransmitted SYN: our SYN-ACK was lost. Answer right away.
      if (is_syn && !is_ack && get_seq(hdr) == peer_isn) {
        sock->conn = from;
        send_control_packet(sock, my_isn, peer_isn + 1,
                            SYN_FLAG_MASK | ACK_FLAG_MASK);
        start_timer(sock);
        free(pkt);
        continue;
      }

      // (b) The final ACK. (d) In-order data: the final ACK was lost but the
      // initiator already considers the connection open.
      int good_ack = !is_syn && is_ack && get_ack(hdr) == my_isn + 1;
      int in_order_data = !is_syn && has_payload &&
                          get_seq(hdr) == sock->window.next_seq_expected;

      if (good_ack || in_order_data) {
        sock->conn = from;
        sock->window.state = ESTABLISHED;
        stop_timer(sock);
        if (has_payload) {
          while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {
          }
          handle_message(sock, pkt);
          pthread_mutex_unlock(&(sock->recv_lock));
        }
        free(pkt);
        return;
      }

      // (c) Wrong ACK number or anything else: ignore, keep waiting.
      free(pkt);
    }
  }
}

/* ─────────────────────────── teardown ─────────────────────────── */

/**
 * Closes the connection once all of our data has been acknowledged.
 *
 * Active close (we send FIN first): FIN_WAIT_1 -> FIN_WAIT_2 -> TIME_WAIT.
 * Passive close (peer's FIN already arrived): LAST_ACK.
 * Data and FINs from the peer keep being handled (and ACKed) throughout.
 */
static void teardown(cmu_socket_t *sock) {
  int active_close = !sock->window.fin_received;
  uint32_t fin_seq = sock->window.next_seq_to_send;

  // The FIN consumes one sequence number; it is ACKed with fin_seq + 1.
  sock->window.next_seq_to_send = fin_seq + 1;
  sock->window.state = active_close ? FIN_WAIT_1 : LAST_ACK;

  for (int tries = 0; tries < MAX_FIN_TRANSMISSIONS &&
                      before(sock->window.last_ack_received,
                             sock->window.next_seq_to_send);
       tries++) {
    send_control_packet(sock, fin_seq, sock->window.next_seq_expected,
                        FIN_FLAG_MASK);
    start_timer(sock);
    while (!timer_expired(sock) && before(sock->window.last_ack_received,
                                          sock->window.next_seq_to_send)) {
      receive_and_handle(sock, timer_remaining_ms(sock));
    }
  }
  stop_timer(sock);

  if (!active_close) return;

  // FIN_WAIT_2: we may still receive data until the peer sends its FIN. Give
  // up if the peer goes silent for 2 * DEFAULT_TIMEOUT.
  sock->window.state = FIN_WAIT_2;
  while (!sock->window.fin_received) {
    if (!receive_and_handle(sock, 2 * DEFAULT_TIMEOUT)) break;
  }

  // TIME_WAIT: stay around for 2 * DEFAULT_TIMEOUT to re-ACK the peer's FIN
  // in case our ACK was lost.
  if (sock->window.fin_received) {
    sock->window.state = TIME_WAIT;
    for (int i = 0; i < 2; i++) {
      start_timer(sock);
      while (!timer_expired(sock)) {
        receive_and_handle(sock, timer_remaining_ms(sock));
      }
    }
    stop_timer(sock);
  }
  sock->window.state = CLOSED;
}

void *begin_backend(void *in) {
  cmu_socket_t *sock = (cmu_socket_t *)in;
  int death, buf_len, send_signal;
  uint8_t *data;

  sock->window.state = CLOSED;
  sock->window.timer_running = 0;
  sock->window.peer_isn = 0;
  sock->window.fin_received = 0;

  if (sock->type == TCP_INITIATOR) {
    initiator_handshake(sock);
  } else {
    listener_handshake(sock);
  }

  while (1) {
    while (pthread_mutex_lock(&(sock->death_lock)) != 0) {
    }
    death = sock->dying;
    pthread_mutex_unlock(&(sock->death_lock));

    while (pthread_mutex_lock(&(sock->send_lock)) != 0) {
    }
    buf_len = sock->sending_len;

    if (death && buf_len == 0) {
      pthread_mutex_unlock(&(sock->send_lock));
      break;
    }

    if (buf_len > 0) {
      data = malloc(buf_len);
      memcpy(data, sock->sending_buf, buf_len);
      sock->sending_len = 0;
      free(sock->sending_buf);
      sock->sending_buf = NULL;
      pthread_mutex_unlock(&(sock->send_lock));
      single_send(sock, data, buf_len);
      free(data);
    } else {
      pthread_mutex_unlock(&(sock->send_lock));
    }

    check_for_data(sock, NO_WAIT);

    while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {
    }

    send_signal = sock->received_len > 0;

    pthread_mutex_unlock(&(sock->recv_lock));

    if (send_signal) {
      pthread_cond_signal(&(sock->wait_cond));
    }
  }

  teardown(sock);

  pthread_exit(NULL);
  return NULL;
}
