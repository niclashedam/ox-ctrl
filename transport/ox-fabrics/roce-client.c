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
#include <assert.h>

#include <rdma/rsocket.h>

struct oxf_rdma_state state;
pthread_mutex_t mutex;

static struct oxf_client_con *oxf_roce_client_connect (struct oxf_client *client,
       uint16_t cid, const char *addr, uint16_t port, oxf_rcv_reply_fn *recv_fn)
{
    struct sockaddr_in inet_addr;
    unsigned int len = sizeof (struct sockaddr);

    if(state.con_fd > 0) return oxf_tcp_client_connect(client, cid, addr, port, recv_fn);

    if ( (state.con_fd = rsocket(AF_INET, SOCK_STREAM, 0)) < 0 ) {
        log_err ("[ox-fabrics (RDMA): Socket creation failure. %d]", state.con_fd);
        return NULL;
    }

    inet_addr.sin_family = AF_INET;
    inet_addr.sin_port = htons(OXF_RDMA_PORT);
    inet_aton(OXF_RDMA_ADDR, &inet_addr.sin_addr);

    int RIOs = OXF_RDMA_COUNT;
    rsetsockopt(state.con_fd, SOL_RDMA, RDMA_IOMAPSIZE, (void *) &RIOs, sizeof RIOs);

    pthread_mutex_lock(&mutex);

    if (rconnect(state.con_fd, (const struct sockaddr *) &inet_addr, len) < 0){
        printf ("[ox-fabrics (RDMA): Socket connection failure.]\n");
        rshutdown (state.con_fd, 2);
        rclose (state.con_fd);
        return NULL;
    }

    log_info ("[ox-fabrics (RDMA): Connected to server, socket ID %d]\n", state.con_fd);

    state.inet_addr = inet_addr;
    state.len = len;

    rrecv(state.con_fd, state.buffers, sizeof(state.buffers), 0);

    log_info ("[ox-fabrics (RDMA): Received memory pool from %d]\n", state.con_fd);

    pthread_mutex_unlock(&mutex);

    return oxf_tcp_client_connect(client, cid, addr, port, recv_fn);
}


static int oxf_roce_client_send (struct oxf_client_con *con, uint32_t size,
                                                                const void *buf)
{
    return oxf_tcp_client_send(con, size, buf);
}

void oxf_roce_client_disconnect (struct oxf_client_con *con)
{
    usleep(25000);

    rshutdown (state.con_fd, 2);
    rclose (state.con_fd);

    oxf_tcp_client_disconnect(con);
}

void oxf_roce_client_exit (struct oxf_client *client)
{
    oxf_tcp_client_exit(client);
}

void oxf_roce_client_map (void *buffer, uint32_t size){
  pthread_mutex_lock(&mutex);
  riomap(state.con_fd, buffer, size, PROT_WRITE, 0, -1);
  pthread_mutex_unlock(&mutex);
}

void oxf_roce_client_unmap (void *buffer, uint32_t size){
  pthread_mutex_lock(&mutex);
  riounmap(state.con_fd, buffer, size);
  pthread_mutex_unlock(&mutex);
}

void oxf_roce_client_free (void *buffer){
    pthread_mutex_lock(&mutex);
    for(int i = 0; i < OXF_RDMA_COUNT; i++){
        if(state.buffers[i].buf != buffer) continue;
        state.buffers[i].status = OXF_RDMA_BUFFER_OPEN;
    }
    pthread_mutex_unlock(&mutex);
}


off_t oxf_roce_client_rdma (void *buf, uint32_t size) {
  struct oxf_rdma_buffer *buffer = NULL;

  RETRY:
  pthread_mutex_lock(&mutex);
  for(int i = 0; i < OXF_RDMA_COUNT; i++){
      if(state.buffers[i].status != OXF_RDMA_BUFFER_OPEN) continue;

      buffer = &state.buffers[i];
      break;
  }

  if(buffer == NULL){
      pthread_mutex_unlock(&mutex);
      usleep(5000);
      goto RETRY;
  }

  buffer->status = OXF_RDMA_BUFFER_RESERVED;
  pthread_mutex_unlock(&mutex);

  off_t offset = (off_t) buffer->buf;

  size_t bytes = riowrite(state.con_fd, buf, size, offset, 0);
  if(bytes != size){
      printf ("[ox-fabrics (RDMA): Incorrect number of bytes transferred. Unrecoverable. %hu/%hu to socket %d]", bytes, size, state.con_fd);
      log_err ("[ox-fabrics (RDMA): Incorrect number of bytes transferred. Unrecoverable. %hu/%hu to socket %d]", bytes, size, state.con_fd);
   }


  return offset;
}

struct oxf_client_ops oxf_roce_cli_ops = {
    .connect    = oxf_roce_client_connect,
    .disconnect = oxf_roce_client_disconnect,
    .send       = oxf_roce_client_send,

    .map     = oxf_roce_client_map,
    .unmap     = oxf_roce_client_unmap,
    .rdma = oxf_roce_client_rdma,
    .free = oxf_roce_client_free
};

struct oxf_client *oxf_roce_client_init (void)
{
  struct oxf_client *client = oxf_tcp_client_init();
  client->ops = &oxf_roce_cli_ops;
  return client;
}
