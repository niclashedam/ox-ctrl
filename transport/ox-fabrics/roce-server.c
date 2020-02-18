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
#include <sched.h>
#include <errno.h>
#include <ox-fabrics.h>
#include <tcp.h>
#include <libox.h>
#include <roce-rdma.h>

#include <rdma/rsocket.h>

static int is_running;
static int sock_fd = 0, con_fd = 0;
struct oxf_rdma_state state;
pthread_t handler;

struct oxf_server_con *oxf_roce_server_bind (struct oxf_server *server,
                                uint16_t cid, const char *addr, uint16_t port)
{
    struct sockaddr_in inet_addr;
    unsigned int len = sizeof (struct sockaddr);

    if(sock_fd > 0) return oxf_tcp_server_bind(server, cid, addr, port);

    if ( (sock_fd = rsocket(AF_INET, SOCK_STREAM, 0)) < 0 ) {
        log_err ("[ox-fabrics (RDMA): Socket creation failure. %d]", sock_fd);
        return NULL;
    }

    inet_addr.sin_family = AF_INET;
    inet_addr.sin_port = htons(RDMA_PORT);
    inet_aton(RDMA_ADDR, &inet_addr.sin_addr);

    int RIOs = OXF_QUEUE_SIZE * OXF_SERVER_MAX_CON;
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

    con_fd = raccept(sock_fd, (struct sockaddr *) &inet_addr, &len);
    if (con_fd == -1) {
        log_err ("[ox-fabrics (RDMA): Socket accept failure.]");
        goto ERR;
    }

    is_running = 1;

    state.con_fd = con_fd;
    state.is_running = &is_running;

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
  void *result;
  pthread_join(handler, &result);

  if (con_fd) rshutdown(con_fd, 0);
  rshutdown (sock_fd, 0);
  rclose (sock_fd);
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

off_t oxf_roce_server_map (struct oxf_server *server, uint16_t cid, void *buffer, uint32_t size){
    if (con_fd < 1) {
        log_err ("[ox-fabrics (RDMA): Cannot map buffer to unconnected client.]");
        return 0;
    }
    return riomap(con_fd, buffer, size, PROT_WRITE, 0, -1);
}

int oxf_roce_server_unmap (struct oxf_server *server, uint16_t cid, void *buffer, uint32_t size){
    if (con_fd < 1) {
        log_err ("[ox-fabrics (RDMA): Cannot unmap buffer to unconnected client.]");
        return -1;
    }
    return riounmap(con_fd, buffer, size);
}

int oxf_roce_server_rdma_req (void *buf, uint32_t size, uint64_t prp, uint8_t dir) {
  return oxf_roce_rdma(con_fd, buf, size, prp, dir);
}

struct oxf_server_ops oxf_roce_srv_ops = {
    .bind    = oxf_roce_server_bind,
    .unbind  = oxf_roce_server_unbind,
    .start   = oxf_roce_server_con_start,
    .stop    = oxf_roce_server_con_stop,
    .reply   = oxf_roce_server_reply,

    .map     = oxf_roce_server_map,
    .unmap   = oxf_roce_server_unmap,
    .rdma    = oxf_roce_server_rdma_req
};

struct oxf_server *oxf_roce_server_init (void)
{
  struct oxf_server *server = oxf_tcp_server_init();
  server->ops = &oxf_roce_srv_ops;
  return server;
}

void oxf_roce_server_exit (struct oxf_server *server)
{
  return oxf_tcp_server_exit(server);
}
