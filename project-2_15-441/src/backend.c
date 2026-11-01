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
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

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
  uint16_t adv_window = sock->adv_cache;

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
  uint16_t adv_window = sock->adv_cache;

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

/* ─────────────────────── congestion control (Reno) ─────────────────────── */

static const char *cc_name(cc_state_t state) {
  switch (state) {
    case CC_SLOW_START:
      return "slow_start";
    case CC_AVOIDANCE:
      return "congestion_avoidance";
    case CC_FAST_RECOVERY:
      return "fast_recovery";
    default:
      return "unknown";
  }
}

/**
 * Append one row whenever cwnd, ssthresh, or the congestion-control stage
 * changes. Used to plot the sawtooth for the checkpoint report.
 */
static void log_cc(cmu_socket_t *sock, const char *event) {
  static FILE *fp = NULL;
  static int tried = 0;
  if (!tried) {
    tried = 1;
    fp = fopen("cwnd_log.csv", "a");
    if (fp != NULL) {
      int fd = fileno(fp);
      flock(fd, LOCK_EX);
      fseek(fp, 0, SEEK_END);
      if (ftell(fp) == 0) {
        fprintf(fp, "time,pid,port,cwnd,ssthresh,peer_adv,state,event\n");
        fflush(fp);
      }
      flock(fd, LOCK_UN);
    }
  }
  if (fp == NULL) return;

  struct timeval now;
  gettimeofday(&now, NULL);
  double t = (double)now.tv_sec + (double)now.tv_usec / 1000000.0;
  fprintf(fp, "%.6f,%d,%u,%u,%u,%u,%s,%s\n", t, (int)getpid(),
          (unsigned)sock->my_port, sock->window.cwnd, sock->window.ssthresh,
          (unsigned)sock->window.peer_adv_window, cc_name(sock->window.cc_state),
          event);
  fflush(fp);
}

static void note_peer_window(cmu_socket_t *sock, uint16_t adv) {
  if (adv == sock->window.peer_adv_window) return;
  sock->window.peer_adv_window = adv;
  log_cc(sock, "peer_window");
}

/** Bytes the sender may have in flight: min(cwnd, peer advertised window). */
static uint32_t send_window(cmu_socket_t *sock) {
  uint32_t adv = sock->window.peer_adv_window;
  uint32_t cwnd = sock->window.cwnd;
  return adv < cwnd ? adv : cwnd;
}

/**
 * Multiplicative decrease. RFC 5681 keeps ssthresh at least two segments so
 * slow start still has room to run after a loss.
 */
static uint32_t half_window(uint32_t cwnd) {
  uint32_t half = cwnd / 2;
  uint32_t floor = 2 * (uint32_t)MSS;
  return half < floor ? floor : half;
}

static void on_timeout(cmu_socket_t *sock) {
  sock->window.ssthresh = half_window(sock->window.cwnd);
  // The published Reno diagram restarts slow start at one segment. The
  // connection's initial window (WINDOW_INITIAL_WINDOW_SIZE) is separate.
  sock->window.cwnd = MSS;
  sock->window.dup_ack_count = 0;
  sock->window.ca_carry = 0;
  sock->window.cc_state = CC_SLOW_START;
  sock->window.do_fast_retransmit = 0;
  log_cc(sock, "timeout");
}

/**
 * Bytes newly acknowledged by one cumulative ACK.
 *
 * Slow start adds those bytes, so acknowledging a full flight doubles cwnd
 * whether the peer ACKs every segment or the whole flight at once.
 * Congestion avoidance adds about one MSS per cwnd bytes acknowledged, so a
 * flight ACK grows the window by one segment instead of doubling it.
 */
static void on_new_ack(cmu_socket_t *sock, uint32_t acked) {
  sock->window.dup_ack_count = 0;
  sock->window.do_fast_retransmit = 0;
  if (acked == 0) return;

  if (sock->window.cc_state == CC_FAST_RECOVERY) {
    // Reno leaves fast recovery on the first ACK of new data and deflates.
    sock->window.cwnd = sock->window.ssthresh;
    sock->window.ca_carry = 0;
    sock->window.cc_state = CC_AVOIDANCE;
    log_cc(sock, "fast_recovery_exit");
    return;
  }

  if (sock->window.cwnd < sock->window.ssthresh) {
    uint32_t room = sock->window.ssthresh - sock->window.cwnd;
    uint32_t add = acked < room ? acked : room;
    sock->window.cwnd += add;
    acked -= add;
    if (sock->window.cwnd < sock->window.ssthresh) {
      sock->window.cc_state = CC_SLOW_START;
      log_cc(sock, "slow_start_ack");
      return;
    }
    sock->window.cc_state = CC_AVOIDANCE;
    sock->window.ca_carry = 0;
    if (acked == 0) {
      log_cc(sock, "slow_start_ack");
      return;
    }
  }

  sock->window.cc_state = CC_AVOIDANCE;
  if (sock->window.cwnd == 0) return;
  uint64_t credit =
      (uint64_t)MSS * (uint64_t)acked + sock->window.ca_carry;
  uint32_t inc = (uint32_t)(credit / sock->window.cwnd);
  sock->window.ca_carry = (uint32_t)(credit % sock->window.cwnd);
  sock->window.cwnd += inc;
  if (inc > 0) log_cc(sock, "congestion_avoidance_ack");
}

/**
 * Duplicate ACK: same cumulative number, and we still have data outstanding.
 * The third one (fourth ACK of that number) is fast retransmit.
 */
static void on_dup_ack(cmu_socket_t *sock) {
  if (sock->window.cc_state == CC_FAST_RECOVERY) {
    sock->window.cwnd += MSS;
    log_cc(sock, "fast_recovery_dup");
    return;
  }

  sock->window.dup_ack_count += 1;
  if (sock->window.dup_ack_count < 3) return;

  sock->window.ssthresh = half_window(sock->window.cwnd);
  sock->window.cwnd = sock->window.ssthresh + 3 * (uint32_t)MSS;
  sock->window.ca_carry = 0;
  sock->window.cc_state = CC_FAST_RECOVERY;
  sock->window.do_fast_retransmit = 1;
  log_cc(sock, "triple_dup_ack");
}

/* ─────────────────────────── receive buffer ─────────────────────────── */

void refresh_adv_cache(cmu_socket_t *sock) {
  uint32_t used = (uint32_t)sock->received_len + sock->ooo_bytes;
  if (used >= MAX_NETWORK_BUFFER) {
    sock->adv_cache = 0;
    sock->window.zero_advertised = 1;
    return;
  }
  uint32_t free_bytes = MAX_NETWORK_BUFFER - used;
  if (free_bytes > 65535) free_bytes = 65535;
  sock->adv_cache = (uint16_t)free_bytes;
}

void send_window_update(cmu_socket_t *sock) {
  if (sock->window.state < ESTABLISHED) return;
  send_control_packet(sock, sock->window.next_seq_to_send,
                      sock->window.next_seq_expected, ACK_FLAG_MASK);
  gettimeofday(&(sock->window.last_wnd_update), NULL);
}

/**
 * If the application opened a window we had advertised as zero, repeat the
 * update until the peer sends data. One lost update would stall the sender.
 */
static void maybe_retransmit_window_update(cmu_socket_t *sock) {
  if (!sock->window.zero_advertised) return;
  if (sock->window.state < ESTABLISHED) return;
  if (sock->adv_cache == 0) return;

  struct timeval now;
  gettimeofday(&now, NULL);
  long elapsed_ms = (now.tv_sec - sock->window.last_wnd_update.tv_sec) * 1000 +
                    (now.tv_usec - sock->window.last_wnd_update.tv_usec) / 1000;
  if (sock->window.last_wnd_update.tv_sec != 0 && elapsed_ms < DEFAULT_TIMEOUT) {
    return;
  }
  send_window_update(sock);
}

static uint32_t buffer_free(cmu_socket_t *sock) {
  uint32_t used = (uint32_t)sock->received_len + sock->ooo_bytes;
  if (used >= MAX_NETWORK_BUFFER) return 0;
  return MAX_NETWORK_BUFFER - used;
}

/** Bytes of [start, end) that are already stored out of order. */
static uint32_t ooo_overlap_bytes(cmu_socket_t *sock, uint32_t start,
                                  uint32_t end) {
  uint32_t n = 0;
  for (recv_seg_t *s = sock->ooo_head; s != NULL; s = s->next) {
    uint32_t s_end = s->seq + s->len;
    uint32_t lo = before(s->seq, start) ? start : s->seq;
    uint32_t hi = before(s_end, end) ? s_end : end;
    if (before(lo, hi)) n += hi - lo;
  }
  return n;
}

/** Drop or trim out-of-order bytes that fall inside [start, end). */
static void discard_ooo_range(cmu_socket_t *sock, uint32_t start, uint32_t end) {
  recv_seg_t **pp = &(sock->ooo_head);
  while (*pp != NULL) {
    recv_seg_t *s = *pp;
    uint32_t s_end = s->seq + s->len;
    if (!before(s->seq, end) || !after(s_end, start)) {
      pp = &(s->next);
      continue;
    }
    if (!after(s_end, end)) {
      sock->ooo_bytes -= s->len;
      *pp = s->next;
      free(s->data);
      free(s);
      continue;
    }
    uint32_t skip = end - s->seq;
    memmove(s->data, s->data + skip, s->len - skip);
    sock->ooo_bytes -= skip;
    s->len = (uint16_t)(s->len - skip);
    s->seq += skip;
    pp = &(s->next);
  }
}

static void append_recv(cmu_socket_t *sock, uint8_t *data, uint16_t len) {
  sock->received_buf = realloc(sock->received_buf, sock->received_len + len);
  memcpy(sock->received_buf + sock->received_len, data, len);
  sock->received_len += len;
  sock->window.next_seq_expected += len;
}

/** Move contiguous out-of-order bytes into the application buffer. */
static void drain_ooo(cmu_socket_t *sock) {
  int progressed = 1;
  while (progressed) {
    progressed = 0;
    while (sock->ooo_head != NULL &&
           !after(sock->ooo_head->seq + sock->ooo_head->len,
                  sock->window.next_seq_expected)) {
      recv_seg_t *s = sock->ooo_head;
      sock->ooo_head = s->next;
      sock->ooo_bytes -= s->len;
      free(s->data);
      free(s);
      progressed = 1;
    }
    if (sock->ooo_head != NULL &&
        before(sock->ooo_head->seq, sock->window.next_seq_expected) &&
        after(sock->ooo_head->seq + sock->ooo_head->len,
              sock->window.next_seq_expected)) {
      recv_seg_t *s = sock->ooo_head;
      uint32_t skip = sock->window.next_seq_expected - s->seq;
      memmove(s->data, s->data + skip, s->len - skip);
      sock->ooo_bytes -= skip;
      s->len = (uint16_t)(s->len - skip);
      s->seq += skip;
      progressed = 1;
    }
    if (sock->ooo_head != NULL &&
        sock->ooo_head->seq == sock->window.next_seq_expected) {
      recv_seg_t *s = sock->ooo_head;
      sock->ooo_head = s->next;
      sock->ooo_bytes -= s->len;
      append_recv(sock, s->data, s->len);
      free(s->data);
      free(s);
      progressed = 1;
    }
  }
}

/**
 * Copy the new bytes of an in-order (or left-overlapping) segment into the
 * application buffer. Returns 1 if any new byte was delivered.
 */
static int take_in_order(cmu_socket_t *sock, uint8_t *payload, uint32_t seq,
                         uint16_t payload_len) {
  uint32_t expect = sock->window.next_seq_expected;
  uint32_t skip = expect - seq;
  if (skip >= payload_len) return 0;
  uint16_t new_len = (uint16_t)(payload_len - skip);
  uint32_t end = expect + new_len;
  uint32_t freed = ooo_overlap_bytes(sock, expect, end);
  uint32_t used = (uint32_t)sock->received_len + sock->ooo_bytes;
  if (freed > used || used - freed + new_len > MAX_NETWORK_BUFFER) return 0;

  discard_ooo_range(sock, expect, end);
  append_recv(sock, payload + skip, new_len);
  drain_ooo(sock);
  return 1;
}

static void insert_ooo_chunk(cmu_socket_t *sock, uint32_t seq, uint8_t *data,
                             uint16_t len) {
  recv_seg_t *node = malloc(sizeof(*node));
  if (node == NULL) return;
  node->data = malloc(len);
  if (node->data == NULL) {
    free(node);
    return;
  }
  memcpy(node->data, data, len);
  node->seq = seq;
  node->len = len;
  node->next = NULL;

  recv_seg_t **pp = &(sock->ooo_head);
  while (*pp != NULL && !after((*pp)->seq, seq)) {
    pp = &((*pp)->next);
  }
  node->next = *pp;
  *pp = node;
  sock->ooo_bytes += len;
}

/** Remember the parts of an out-of-order segment we do not already hold. */
static int insert_ooo(cmu_socket_t *sock, uint32_t seq, uint8_t *data,
                      uint16_t len) {
  uint32_t limit = sock->window.next_seq_expected + MAX_NETWORK_BUFFER;
  if (!before(seq, limit)) return 0;

  int stored = 0;
  uint32_t pos = seq;
  uint32_t end = seq + len;
  while (before(pos, end)) {
    int inside = 0;
    recv_seg_t *next_seg = NULL;
    for (recv_seg_t *s = sock->ooo_head; s != NULL; s = s->next) {
      uint32_t s_end = s->seq + s->len;
      if (!after(s->seq, pos) && before(pos, s_end)) {
        pos = s_end;
        inside = 1;
        break;
      }
      if (after(s->seq, pos)) {
        next_seg = s;
        break;
      }
    }
    if (inside) continue;
    if (!before(pos, end)) break;

    uint32_t chunk_end = end;
    if (next_seg != NULL && before(next_seg->seq, chunk_end)) {
      chunk_end = next_seg->seq;
    }
    uint32_t chunk_len = chunk_end - pos;
    if (chunk_len == 0 || chunk_len > buffer_free(sock)) break;
    insert_ooo_chunk(sock, pos, data + (pos - seq), (uint16_t)chunk_len);
    stored = 1;
    pos = chunk_end;
  }
  return stored;
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
  int delivered = 0;

  // Every packet carries the peer's current receive window. A pure window
  // update repeats the ACK number; that is not a signal of loss.
  uint16_t prev_adv = sock->window.peer_adv_window;
  uint16_t new_adv = get_advertised_window(hdr);
  note_peer_window(sock, new_adv);
  int window_update = new_adv != prev_adv;

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
        !after(ack, sock->window.highwater)) {
      uint32_t acked = ack - sock->window.last_ack_received;
      sock->window.last_ack_received = ack;
      // A timeout rewinds next_seq. An ACK can then cover bytes the peer
      // already buffered, past the rewound cursor. Catch the cursor up.
      if (before(sock->window.next_seq_to_send, ack)) {
        sock->window.next_seq_to_send = ack;
      }
      on_new_ack(sock, acked);
      if (sock->window.last_ack_received == sock->window.highwater) {
        stop_timer(sock);
      } else {
        start_timer(sock);
      }
    } else if (!window_update && ack == sock->window.last_ack_received &&
               after(sock->window.highwater, sock->window.last_ack_received)) {
      // Four ACKs of the same number: the original plus three duplicates.
      on_dup_ack(sock);
    }
  }

  if (payload_len > 0) {
    uint32_t seq = get_seq(hdr);
    uint32_t expect = sock->window.next_seq_expected;
    uint8_t *payload = get_payload(pkt);
    if (!after(seq, expect) && after(seq + payload_len, expect)) {
      delivered = take_in_order(sock, payload, seq, payload_len);
    } else if (after(seq, expect)) {
      insert_ooo(sock, seq, payload, payload_len);
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

  refresh_adv_cache(sock);
  // The peer is moving again, so a zero-window update is no longer owed
  // unless accepting this segment just filled the buffer.
  if (delivered && sock->adv_cache > 0) {
    sock->window.zero_advertised = 0;
  }
  if (delivered) pthread_cond_signal(&(sock->wait_cond));

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
 * Resend the oldest unacknowledged segment. Fast retransmit does this once;
 * it does not rewind the send pointer, so later segments stay outstanding.
 */
static void retransmit_oldest(cmu_socket_t *sock, uint8_t *data,
                              uint32_t seq_base) {
  uint32_t seq = sock->window.last_ack_received;
  // Prefer the high-water mark: next_seq may have been rewound by a timeout.
  uint32_t sent_end = sock->window.highwater;
  if (before(sent_end, sock->window.next_seq_to_send)) {
    sent_end = sock->window.next_seq_to_send;
  }
  if (!before(seq, sent_end)) return;
  uint32_t have = sent_end - seq;
  uint16_t len = (uint16_t)MIN((uint32_t)MSS, have);
  send_data_segment(sock, data, seq_base, seq, len);
  // The retransmitted segment is now the oldest outstanding byte. Give it a
  // full RTO instead of inheriting a timer that is about to fire.
  start_timer(sock);
}

/**
 * Send `data` under TCP Reno. The usable window is min(cwnd, advertised
 * window). A timeout rewinds to the left edge and re-enters slow start. Three
 * duplicate ACKs retransmit only the missing segment and enter fast recovery.
 *
 * @param sock The socket to use for sending data.
 * @param data The data to be sent.
 * @param buf_len The length of the data being sent.
 */
void single_send(cmu_socket_t *sock, uint8_t *data, int buf_len) {
  if (buf_len <= 0) return;

  uint32_t seq_base = sock->window.next_seq_to_send;
  uint32_t seq_end = seq_base + (uint32_t)buf_len;

  while (before(sock->window.last_ack_received, seq_end)) {
    // ACKs already queued must be applied before a timeout, or a packet that
    // arrived on time gets treated as loss.
    while (receive_and_handle(sock, 0)) {
    }
    if (!before(sock->window.last_ack_received, seq_end)) break;

    int timed_out = 0;
    if (timer_expired(sock) &&
        after(sock->window.highwater, sock->window.last_ack_received)) {
      on_timeout(sock);
      // Rewind the send cursor and arm a fresh RTO. Leaving the old timer
      // running would make every following iteration look like another timeout.
      sock->window.next_seq_to_send = sock->window.last_ack_received;
      start_timer(sock);
      timed_out = 1;
    } else if (sock->window.do_fast_retransmit) {
      retransmit_oldest(sock, data, seq_base);
      sock->window.do_fast_retransmit = 0;
    }

    int force_one = timed_out;
    while (before(sock->window.next_seq_to_send, seq_end)) {
      uint32_t flight =
          sock->window.next_seq_to_send - sock->window.last_ack_received;
      uint32_t win = send_window(sock);
      sock->window.size = win;
      if (flight >= win) {
        // A shut window still needs one retransmission after a timeout, or
        // the peer never regenerates the ACK that opens it.
        if (force_one && flight == 0) {
          // Zero-window probe: one byte, so a lost ACK can be regenerated
          // without ignoring the peer's advertised window.
          win = 1;
        } else {
          break;
        }
      }
      force_one = 0;
      uint32_t room = win - flight;
      uint32_t remaining = seq_end - sock->window.next_seq_to_send;
      uint16_t payload_len =
          (uint16_t)MIN((uint32_t)MSS, MIN(remaining, room));
      if (payload_len == 0) break;

      send_data_segment(sock, data, seq_base, sock->window.next_seq_to_send,
                        payload_len);
      if (!sock->window.timer_running) start_timer(sock);
      sock->window.next_seq_to_send += payload_len;
      if (!before(sock->window.next_seq_to_send, sock->window.highwater)) {
        sock->window.highwater = sock->window.next_seq_to_send;
      }
    }
    if (timed_out && !sock->window.timer_running) start_timer(sock);

    maybe_retransmit_window_update(sock);
    if (receive_and_handle(sock, timer_remaining_ms(sock))) {
      while (receive_and_handle(sock, 0)) {
      }
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
      note_peer_window(sock, get_advertised_window(hdr));
      sock->window.next_seq_expected = sock->window.peer_isn + 1;

      send_control_packet(sock, my_isn + 1, sock->window.next_seq_expected,
                          ACK_FLAG_MASK);

      sock->window.last_ack_received = my_isn + 1;
      sock->window.next_seq_to_send = my_isn + 1;
      sock->window.highwater = my_isn + 1;
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
    note_peer_window(sock, get_advertised_window(hdr));
    sock->window.next_seq_expected = peer_isn + 1;
    free(pkt);
    break;
  }

  sock->window.state = SYN_RCVD;
  sock->window.last_ack_received = my_isn + 1;
  sock->window.next_seq_to_send = my_isn + 1;
  sock->window.highwater = my_isn + 1;

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
        note_peer_window(sock, get_advertised_window(hdr));
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
  sock->window.highwater = fin_seq + 1;
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
  log_cc(sock, "init");

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
      pthread_cond_signal(&(sock->send_cond));
      pthread_mutex_unlock(&(sock->send_lock));
      single_send(sock, data, buf_len);
      free(data);
    } else {
      pthread_mutex_unlock(&(sock->send_lock));
    }

    maybe_retransmit_window_update(sock);
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
