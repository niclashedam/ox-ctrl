/* OX: Open-Channel NVM Express SSD Controller
 *
 *  - OX NVMe over roce (client side)
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
#include <tcp.h>
#include <ox-fabrics.h>
#include <roce-rdma.h>

#include <rdma/rsocket.h>

static int is_running;
struct oxf_rdma_state state;
pthread_t handler;

// TODO: How many max queues?
struct oxf_rdma_buffer buffers[OXF_QUEUE_SIZE * OXF_CLIENT_MAX_CON * 32];

static struct oxf_client_con *oxf_roce_client_connect (struct oxf_client *client,
       uint16_t cid, const char *addr, uint16_t port, oxf_rcv_reply_fn *recv_fn)
{
    int sock_fd = -1;
    struct sockaddr_in inet_addr;
    unsigned int len = sizeof (struct sockaddr);

    if(state.con_fd > 0) return oxf_tcp_client_connect(client, cid, addr, port, recv_fn);

    if ( (sock_fd = rsocket(AF_INET, SOCK_STREAM, 0)) < 0 ) {
        log_err ("[ox-fabrics (RDMA): Socket creation failure. %d]", sock_fd);
        return NULL;
    }

    inet_addr.sin_family = AF_INET;
    inet_addr.sin_port = htons(RDMA_PORT);
    inet_aton(RDMA_ADDR, &inet_addr.sin_addr);

    int RIOs = OXF_QUEUE_SIZE * OXF_CLIENT_MAX_CON;
    rsetsockopt(sock_fd, SOL_RDMA, RDMA_IOMAPSIZE, (void *) &RIOs, sizeof RIOs);

    if ( rconnect(sock_fd, (const struct sockaddr *) &inet_addr, len) < 0){
        printf ("[ox-fabrics (RDMA): Socket connection failure.]\n");
        rshutdown(sock_fd, 0);
        rclose(sock_fd);
        return NULL;
    }

    is_running = 1;

    state.inet_addr = inet_addr;
    state.len = len;
    state.con_fd = sock_fd; // bottom up because we are a client
    state.listen = 0;
    state.is_running = &is_running;
    state.buffers = buffers;
    state.registered_buffers = 0;

    pthread_create(&handler, NULL, &oxf_roce_rdma_handler, &state);

    return oxf_tcp_client_connect(client, cid, addr, port, recv_fn);
}


static int oxf_roce_client_send (struct oxf_client_con *con, uint32_t size,
                                                                const void *buf)
{
    return oxf_tcp_client_send(con, size, buf);
}

void oxf_roce_client_disconnect (struct oxf_client_con *con)
{
    is_running = 0;
    pthread_kill(handler, 0);

    rshutdown (state.sock_fd, 0);
    rclose (state.sock_fd);

    oxf_tcp_client_disconnect(con);
}

void oxf_roce_client_exit (struct oxf_client *client)
{
    pthread_kill(handler, 0);
    oxf_tcp_client_exit(client);
}

void oxf_roce_client_map (void *buffer, uint32_t size){
    struct oxf_rdma_buffer buf;
    buf.buffer = buffer;
    buf.size = size;
    printf("Registering %p\n", buffer);
    buffers[state.buffer_count++] = buf;
}

int oxf_roce_client_rdma_req (void *buf, uint32_t size, uint64_t prp, uint8_t dir) {
  uint8_t normalised_dir = (dir != NVM_DMA_TO_HOST) ? OXF_RDMA_PUSH : OXF_RDMA_PULL;
  return oxf_roce_rdma(state.con_fd, buf, size, prp, normalised_dir);
}

struct oxf_client_ops oxf_roce_cli_ops = {
    .connect    = oxf_roce_client_connect,
    .disconnect = oxf_roce_client_disconnect,
    .send       = oxf_roce_client_send,

    .map     = oxf_roce_client_map,
    .rdma = oxf_roce_client_rdma_req
};

struct oxf_client *oxf_roce_client_init (void)
{
  struct oxf_client *client = oxf_tcp_client_init();
  client->ops = &oxf_roce_cli_ops;
  return client;
}
