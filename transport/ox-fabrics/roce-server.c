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
#include <signal.h>

#include <rdma/rsocket.h>

static int is_running;
struct oxf_rdma_state state;
pthread_t handler;

void *oxf_roce_rdma_handler(){
LISTEN:
    printf("Listening ..\n");
    state.con_fd = raccept(state.sock_fd, (struct sockaddr *) &state.inet_addr, &state.len);

    printf ("[ox-fabrics (RDMA): Client connected, socket ID %d]\n", state.con_fd);

    for(int i = 0; i < OXF_RDMA_COUNT; i++){
        state.buffers[i].buf = malloc(OXF_RDMA_SIZE);
        state.buffers[i].size = OXF_RDMA_SIZE;
        state.buffers[i].status = OXF_RDMA_BUFFER_OPEN;

        if(state.buffers[i].buf == NULL){
            log_info("Unable to register RDMA buffer %i/%i. Probably out of memory.\n", i, OXF_RDMA_COUNT);
            return;
        }

        riomap(
            state.con_fd,
            state.buffers[i].buf,
            state.buffers[i].size,
            PROT_WRITE, 0, -1
        );
    }

    log_info ("[ox-fabrics (RDMA): Sending memory pool to %d]\n", state.con_fd);

    rsend(state.con_fd, state.buffers, sizeof(state.buffers), 0);

    is_running = 1;

    char empty = 0;
    while(is_running){
        usleep(5000);

        int bytes = rrecv(state.con_fd, &empty , sizeof(empty), MSG_DONTWAIT);

        if(bytes == 0) goto LISTEN;
    }

    return NULL;
}

struct oxf_server_con *oxf_roce_server_bind (struct oxf_server *server,
                                uint16_t cid, const char *addr, uint16_t port)
{
    struct sockaddr_in inet_addr;
    unsigned int len = sizeof (struct sockaddr);

    if(state.sock_fd > 0) return oxf_tcp_server_bind(server, cid, addr, port);

    if ( (state.sock_fd = rsocket(AF_INET, SOCK_STREAM, 0)) < 0 ) {
        log_err ("[ox-fabrics (RDMA): Socket creation failure. %d]", state.sock_fd);
        return NULL;
    }

    inet_addr.sin_family = AF_INET;
    inet_addr.sin_port = htons(OXF_RDMA_PORT);
    inet_aton(OXF_RDMA_ADDR, &inet_addr.sin_addr);

    int RIOs = OXF_RDMA_COUNT;
    rsetsockopt(state.sock_fd, SOL_RDMA, RDMA_IOMAPSIZE, (void *) &RIOs, sizeof RIOs);

    if ( rbind(state.sock_fd, (const struct sockaddr *) &inet_addr,
                                    sizeof(inet_addr)) < 0 )
    {
        log_err ("[ox-fabrics (RDMA): Socket bind failure.]");
        goto ERR;
    }

    /* Put the socket in listen mode to accepting connections */
    if (rlisten (state.sock_fd, 16)) {
        log_err ("[ox-fabrics (RDMA): Socket listen failure.]");
        goto ERR;
    }

    state.inet_addr = inet_addr;
    state.len = len;
    state.con_fd = -1;

    pthread_create(&handler, NULL, &oxf_roce_rdma_handler, NULL);

    usleep(25000);

    return oxf_tcp_server_bind(server, cid, addr, port);

ERR:
    rshutdown (state.sock_fd, 2);
    rclose (state.sock_fd);
    return NULL;

}

void oxf_roce_server_unbind (struct oxf_server_con *con)
{
  is_running = 0;

  usleep(25000);

  if (state.con_fd) rshutdown(state.con_fd, 2);
  rshutdown (state.sock_fd, 2);
  rclose (state.sock_fd);

  usleep(25000);

  // pthread_kill(handler, 9); // the thread may be listening in a blocking state

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

off_t oxf_roce_server_rdma (void *buf, uint32_t size, uint64_t prp) {
    if(prp <= 0){
        log_err("[ox-fabrics (RDMA): The server must pass a valid PRP.]\n");
        printf("[ox-fabrics (RDMA): The server must pass a valid PRP.]\n");
        return -1;
    }

    size_t bytes = riowrite(state.con_fd, buf, size, (off_t) prp, 0);
    if(bytes != size){
        printf ("[ox-fabrics (RDMA): Incorrect number of bytes transferred. Unrecoverable. %hu/%hu to socket %d]", bytes, size, state.con_fd);
        log_err ("[ox-fabrics (RDMA): Incorrect number of bytes transferred. Unrecoverable. %hu/%hu to socket %d]", bytes, size, state.con_fd);
    }
    return (off_t) prp;
}

struct oxf_server_ops oxf_roce_srv_ops = {
    .bind    = oxf_roce_server_bind,
    .unbind  = oxf_roce_server_unbind,
    .start   = oxf_roce_server_con_start,
    .stop    = oxf_roce_server_con_stop,
    .reply   = oxf_roce_server_reply,

    .rdma    = oxf_roce_server_rdma
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
