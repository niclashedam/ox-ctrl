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
#include <tcp.h>
#include <ox-fabrics.h>
#include <roce-rdma.h>

#include <rdma/rsocket.h>

static int is_running;
static int sock_fd = 0;
struct oxf_rdma_state state;
pthread_t handler;

static struct oxf_client_con *oxf_roce_client_connect (struct oxf_client *client,
       uint16_t cid, const char *addr, uint16_t port, oxf_rcv_reply_fn *recv_fn)
{
    struct sockaddr_in inet_addr;
    unsigned int len = sizeof (struct sockaddr);

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

    state.con_fd = sock_fd;
    state.is_running = &is_running;

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
    void *result;
    pthread_join(handler, &result);

    rshutdown (sock_fd, 0);
    rclose (sock_fd);

    oxf_tcp_client_disconnect(con);
}

void oxf_roce_client_exit (struct oxf_client *client)
{
    oxf_tcp_client_exit(client);
}

off_t oxf_roce_client_map (struct oxf_server *server, uint16_t cid, void *buffer, uint32_t size){
    if (sock_fd < 1) {
        log_err ("[ox-fabrics (RDMA): Cannot map buffer to unconnected client.]");
        return 0;
    }
    return riomap(sock_fd, buffer, size, PROT_WRITE, 0, -1);
}

int oxf_roce_client_unmap (struct oxf_server *server, uint16_t cid, void *buffer, uint32_t size){
    if (sock_fd < 1) {
        log_err ("[ox-fabrics (RDMA): Cannot unmap buffer to unconnected client.]");
        return -1;
    }
    return riounmap(sock_fd, buffer, size);
}

int oxf_roce_client_rdma_req (void *buf, uint32_t size, uint64_t prp, uint8_t dir) {
  return oxf_roce_rdma(sock_fd, buf, size, prp, dir);
}

struct oxf_client_ops oxf_roce_cli_ops = {
    .connect    = oxf_roce_client_connect,
    .disconnect = oxf_roce_client_disconnect,
    .send       = oxf_roce_client_send,

    .map     = oxf_roce_client_map,
    .unmap   = oxf_roce_client_unmap,
    .rdma = oxf_roce_client_rdma_req
};

struct oxf_client *oxf_roce_client_init (void)
{
  struct oxf_client *client = oxf_tcp_client_init();
  client->ops = &oxf_roce_cli_ops;
  return client;
}
