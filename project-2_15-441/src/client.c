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
 * This file implements a simple CMU-TCP client. Its purpose is to provide
 * simple test cases and demonstrate how the sockets will be used.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "cmu_tcp.h"

#include <sys/time.h>
void functionality(cmu_socket_t *sock) {
  const char *path = getenv("payload");
  if (!path) path = "/tmp/payload.bin";
  FILE *fp = fopen(path, "rb");
  if (!fp) exit(EXIT_FAILURE);
  uint8_t buf[2000];
  int total = 0;
  struct timeval t0, t1;
  gettimeofday(&t0, NULL);
  int n;
  while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
    if (cmu_write(sock, buf, n) < 0) exit(EXIT_FAILURE);
    total += n;
  }
  gettimeofday(&t1, NULL);
  fclose(fp);
  double seconds = (t1.tv_sec - t0.tv_sec) + (t1.tv_usec - t0.tv_usec) / 1e6;
  printf("%d %.6f\n", total, seconds);
  fflush(stdout);
}

int main() {
  int portno;
  char *serverip;
  char *serverport;
  cmu_socket_t socket;

  serverip = getenv("server15441");
  if (!serverip) {
    serverip = "10.0.1.1";
  }

  serverport = getenv("serverport15441");
  if (!serverport) {
    serverport = "15441";
  }
  portno = (uint16_t)atoi(serverport);

  if (cmu_socket(&socket, TCP_INITIATOR, portno, serverip) < 0) {
    exit(EXIT_FAILURE);
  }

  functionality(&socket);

  if (cmu_close(&socket) < 0) {
    exit(EXIT_FAILURE);
  }

  return EXIT_SUCCESS;
}
