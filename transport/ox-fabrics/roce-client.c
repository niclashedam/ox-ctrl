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
    inet_addr.sin_port = htons(OXF_RDMA_PORT);
    inet_aton(OXF_RDMA_ADDR, &inet_addr.sin_addr);

    int RIOs = OXF_RDMA_COUNT;
    rsetsockopt(sock_fd, SOL_RDMA, RDMA_IOMAPSIZE, (void *) &RIOs, sizeof RIOs);

    if ( rconnect(sock_fd, (const struct sockaddr *) &inet_addr, len) < 0){
        printf ("[ox-fabrics (RDMA): Socket connection failure.]\n");
        rshutdown(sock_fd, 2);
        rclose(sock_fd);
        return NULL;
    }

    state.inet_addr = inet_addr;
    state.len = len;
    state.con_fd = sock_fd; // bottom up because we are a client
    state.listen = 0;
    state.is_running = &is_running;

    pthread_create(&handler, NULL, &oxf_roce_rdma_handler, &state);

    while(!state.is_running) usleep(1000);

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

    usleep(25000); // Wait for RDMA handler to exit

    rshutdown (state.con_fd, 2);
    rclose (state.con_fd);

    oxf_tcp_client_disconnect(con);
}

void oxf_roce_client_exit (struct oxf_client *client)
{
    oxf_tcp_client_exit(client);
}

void oxf_roce_client_map (void *buffer, uint32_t size){
  riomap(state.con_fd, buffer, size, PROT_WRITE, 0, -1);
}

void oxf_roce_client_unmap (void *buffer, uint32_t size){
  riounmap(state.con_fd, buffer, size);
}

off_t oxf_roce_client_rdma (void *buf, uint32_t size, uint64_t prp, uint8_t dir) {
RETRY:
  if(dir != NVM_DMA_FROM_HOST){
      printf("[ox-fabrics (RDMA): The host can only transfer from the host.]\n");
      return -1;
  }

  if(prp > 0){
      printf("[ox-fabrics (RDMA): The host does not accept a remote PRP.]\n");
      return -1;
  }

  struct oxf_rdma_buffer *buffer = NULL;
  for(int i = 0; i < OXF_RDMA_COUNT; i++){
      if(state.buffers[i].status != OXF_RDMA_BUFFER_OPEN) continue;
      buffer = &state.buffers[i];
  }

  if(buffer == NULL) goto RETRY;

  buffer->status = OXF_RDMA_BUFFER_RESERVED;
  off_t offset = (off_t) buffer->buf;
  riowrite(state.con_fd, buf, size, offset, 0);
  rsend(state.con_fd, &offset, sizeof(offset), 0);

  return offset;
}

struct oxf_client_ops oxf_roce_cli_ops = {
    .connect    = oxf_roce_client_connect,
    .disconnect = oxf_roce_client_disconnect,
    .send       = oxf_roce_client_send,

    .map     = oxf_roce_client_map,
    .unmap     = oxf_roce_client_unmap,
    .rdma = oxf_roce_client_rdma
};

struct oxf_client *oxf_roce_client_init (void)
{
  struct oxf_client *client = oxf_tcp_client_init();
  client->ops = &oxf_roce_cli_ops;
  return client;
}
