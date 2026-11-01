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
 * This file defines the API for the CMU TCP implementation.
 */

#ifndef PROJECT_2_15_441_INC_CMU_TCP_H_
#define PROJECT_2_15_441_INC_CMU_TCP_H_

#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>

#include "cmu_packet.h"
#include "grading.h"

#define EXIT_SUCCESS 0
#define EXIT_ERROR -1
#define EXIT_FAILURE 1

/**
 * CMU-TCP socket types. (DO NOT CHANGE.)
 */
typedef enum {
  TCP_INITIATOR = 0,
  TCP_LISTENER = 1,
} cmu_socket_type_t;

/**
 * TCP Reno congestion-control states. See the state diagram in the handout.
 */
typedef enum {
  CC_SLOW_START = 0,
  CC_AVOIDANCE = 1,
  CC_FAST_RECOVERY = 2,
} cc_state_t;

typedef struct {
  // Sender-side
  uint32_t last_ack_received; // window left edge
  uint32_t next_seq_to_send;  // next byte to transmit (rewinds after a timeout)
  uint32_t highwater;         // furthest sequence ever transmitted
  uint32_t size;              // last effective send window (min of cwnd, adv)

  // retransmission timer
  struct timeval timer_start;
  int timer_running;

  // receiver
  uint32_t next_seq_expected;

  // connection
  int state;
  uint32_t my_isn;
  uint32_t peer_isn;
  int fin_received;  // peer's FIN has been received in order

  // Congestion control (TCP Reno). All sizes are in bytes.
  uint32_t cwnd;
  uint32_t ssthresh;
  uint32_t ca_carry;  // leftover bytes for the congestion-avoidance increment
  cc_state_t cc_state;
  int dup_ack_count;
  int do_fast_retransmit;  // single_send should resend the oldest unacked seg

  // Flow control. peer_adv_window is the latest window the peer advertised.
  uint16_t peer_adv_window;
  // Set when we advertise 0, so a later read can open the window again.
  int zero_advertised;
  struct timeval last_wnd_update;

} window_t;

/**
 * One out-of-order segment held until the gap in front of it is filled.
 * These bytes count against MAX_NETWORK_BUFFER, same as ordered data.
 */
typedef struct recv_seg {
  uint32_t seq;
  uint16_t len;
  uint8_t* data;
  struct recv_seg* next;
} recv_seg_t;

typedef struct {
  int socket;
  pthread_t thread_id;
  uint16_t my_port;
  struct sockaddr_in conn;

  uint8_t* received_buf;
  uint8_t* sending_buf;
  int received_len;
  int sending_len;
  pthread_mutex_t recv_lock;
  pthread_mutex_t send_lock;
  pthread_mutex_t death_lock;
  pthread_cond_t wait_cond;
  pthread_cond_t send_cond;

  // Bytes of receive buffer still free, mirrored for the send path.
  // Updated only while recv_lock is held. The backend thread is the only
  // thread that shrinks it (by accepting data); the app thread only grows it.
  uint16_t adv_cache;

  recv_seg_t* ooo_head;
  uint32_t ooo_bytes;

  cmu_socket_type_t type;
  int dying;

  window_t window;
} cmu_socket_t;

/*
 * DO NOT CHANGE THE DECLARATIONS BELOW
 */

/**
 * Read mode flags supported by a CMU-TCP socket.
 */
typedef enum {
  NO_FLAG = 0,  // Default behavior: block indefinitely until data is available.
  NO_WAIT,      // Return immediately if no data is available.
  TIMEOUT,      // Block until data is available or the timeout is reached.
} cmu_read_mode_t;

/**
 * Constructs a CMU-TCP socket.
 *
 * An Initiator socket is used to connect to a Listener socket.
 *
 * @param sock The structure with the socket state. It will be initialized by
 *             this function.
 * @param socket_type Indicates the type of socket: Listener or Initiator.
 * @param port Port to either connect to, or bind to. (Based on socket_type.)
 * @param server_ip IP address of the server to connect to. (Only used if the
 *                 socket is an initiator.)
 *
 * @return 0 on success, -1 on error.
 */
int cmu_socket(cmu_socket_t* sock, const cmu_socket_type_t socket_type,
               const int port, const char* server_ip);

/**
 * Closes a CMU-TCP socket.
 *
 * @param sock The socket to close.
 *
 * @return 0 on success, -1 on error.
 */
int cmu_close(cmu_socket_t* sock);

/**
 * Reads data from a CMU-TCP socket.
 *
 * If there is data available in the socket buffer, it is placed in the
 * destination buffer.
 *
 * @param sock The socket to read from.
 * @param buf The buffer to read into.
 * @param length The maximum number of bytes to read.
 * @param flags Flags that determine how the socket should wait for data. Check
 *             `cmu_read_mode_t` for more information. `TIMEOUT` is not
 *             implemented for CMU-TCP.
 *
 * @return The number of bytes read on success, -1 on error.
 */
int cmu_read(cmu_socket_t* sock, void* buf, const int length,
             cmu_read_mode_t flags);

/**
 * Writes data to a CMU-TCP socket.
 *
 * @param sock The socket to write to.
 * @param buf The data to write.
 * @param length The number of bytes to write.
 *
 * @return 0 on success, -1 on error.
 */
int cmu_write(cmu_socket_t* sock, const void* buf, int length);

/*
 * You can declare more functions after this point if you need to.
 */

#endif  // PROJECT_2_15_441_INC_CMU_TCP_H_
