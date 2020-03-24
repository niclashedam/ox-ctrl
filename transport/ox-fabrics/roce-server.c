/* OX: Open-Channel NVM Express SSD Controller
 *
 *  - OX NVMe over RoCE (server side)
 *
 * Copyright 2018 IT University of Copenhagen
 *
 * Written by Ivan Luiz Picoli <ivpi@itu.dk>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <sched.h>
#include <errno.h>
#include <ox-fabrics.h>
#include <tcp.h>
#include <libox.h>
#include <roce-rdma.h>

#include <rdma/rsocket.h>

static int is_running;
struct oxf_rdma_state state;
pthread_t handler;

struct oxf_server_con *oxf_roce_server_bind (struct oxf_server *server,
                                uint16_t cid, const char *addr, uint16_t port)
{
    int sock_fd = 0;
    struct sockaddr_in inet_addr;
    unsigned int len = sizeof (struct sockaddr);

    if(state.sock_fd > 0) return oxf_tcp_server_bind(server, cid, addr, port);

    if ( (sock_fd = rsocket(AF_INET, SOCK_STREAM, 0)) < 0 ) {
        log_err ("[ox-fabrics (RDMA): Socket creation failure. %d]", sock_fd);
        return NULL;
    }

    inet_addr.sin_family = AF_INET;
    inet_addr.sin_port = htons(RDMA_PORT);
    inet_aton(RDMA_ADDR, &inet_addr.sin_addr);

    int RIOs = 64;
    rsetsockopt(sock_fd, SOL_RDMA, RDMA_IOMAPSIZE, (void *) &RIOs, sizeof RIOs);

    if ( rbind(sock_fd, (const struct sockaddr *) &inet_addr,
                                    sizeof(inet_addr)) < 0 )
    {
        log_err ("[ox-fabrics (RDMA): Socket bind failure.]");
        goto ERR;
    }

    /* Put the socket in listen mode to accepting connections */
    if (rlisten (sock_fd, 16)) {
        log_err ("[ox-fabrics (RDMA): Socket listen failure.]");
        goto ERR;
    }

    state.inet_addr = inet_addr;
    state.len = len;
    state.sock_fd = sock_fd;
    state.con_fd = -1;
    state.is_running = &is_running;
    state.listen = 1;

    pthread_create(&handler, NULL, &oxf_roce_rdma_handler, &state);
    return oxf_tcp_server_bind(server, cid, addr, port);

ERR:
    rshutdown (sock_fd, 2);
    rclose (sock_fd);
    return NULL;

}

void oxf_roce_server_unbind (struct oxf_server_con *con)
{
  is_running = 0;

  usleep(25000); // Wait for RDMA handler to exit

  if (state.con_fd) rshutdown(state.con_fd, 2);
  rshutdown (state.sock_fd, 2);
  rclose (state.sock_fd);
  oxf_tcp_server_unbind(con);
}

int oxf_roce_server_con_start (struct oxf_server_con *con, oxf_rcv_fn *fn)
{
  return oxf_tcp_server_con_start(con, fn);
}

void oxf_roce_server_con_stop (struct oxf_server_con *con)
{
  oxf_tcp_server_con_stop(con);
}

int oxf_roce_server_reply (struct oxf_server_con *con, const void *buf,
                                                 uint32_t size, void *recv_cli)
{
  return oxf_tcp_server_reply(con, buf, size, recv_cli);
}

void oxf_roce_server_map (void *buffer, uint32_t size){
  printf("Mapping %p\n", buffer);
  riomap(state.con_fd, buffer, size, PROT_WRITE, 0, -1);
}

void oxf_roce_server_unmap (void *buffer, uint32_t size){
  riounmap(state.con_fd, buffer, size);
}

int oxf_roce_server_rdma_req (void *buf, uint32_t size, uint64_t prp, uint8_t dir) {
  printf("RDMA REQ\n");
  return oxf_roce_rdma(state.con_fd, buf, size, prp, dir);
}

struct oxf_server_ops oxf_roce_srv_ops = {
    .bind    = oxf_roce_server_bind,
    .unbind  = oxf_roce_server_unbind,
    .start   = oxf_roce_server_con_start,
    .stop    = oxf_roce_server_con_stop,
    .reply   = oxf_roce_server_reply,

    .map     = oxf_roce_server_map,
    .unmap     = oxf_roce_server_unmap,
    .rdma    = oxf_roce_server_rdma_req
};

struct oxf_server *oxf_roce_server_init (void)
{
  log_info ("[ox-fabrics: Data protocol -> RoCE\n");
  struct oxf_server *server = oxf_tcp_server_init();
  server->ops = &oxf_roce_srv_ops;
  return server;
}

void oxf_roce_server_exit (struct oxf_server *server)
{
  return oxf_tcp_server_exit(server);
}
