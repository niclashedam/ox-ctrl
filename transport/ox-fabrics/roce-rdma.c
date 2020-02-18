/* OX: Open-Channel NVM Express SSD Controller
 *
 *  - OX NVMe over RoCE (RDMA)
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

#include <rdma/rsocket.h>

void *oxf_roce_rdma_handler(void *p){
    struct oxf_rdma_state *state = (struct oxf_rdma_state *) p;
    struct oxf_rdma_request request;

    while(*state->is_running){
        int bytes = rrecv(state->con_fd, &request , sizeof(request), MSG_WAITALL);

        printf("Received REQ");

        if(bytes == 0) break;

        if(request.direction == OXF_RDMA_CONFIRM){
          printf("Was confirm");
          int *fulfilled = (int *) request.fulfilment_bit;
          *fulfilled = 1;
          continue;
        }

        printf("Was pull request");
        riowrite(state->con_fd, (void *) request.remote_addr, request.size, request.local_addr, 0);
        request.direction = OXF_RDMA_CONFIRM;

        rsend(state->con_fd, &request, sizeof(request), 0);

        usleep(1000);
    }

    return state;
}

int oxf_roce_rdma (int con_fd, void *buf, uint32_t size, uint64_t prp, uint8_t dir) {
    struct oxf_rdma_request request;
    request.direction = dir == NVM_DMA_TO_HOST ? OXF_RDMA_PUSH : OXF_RDMA_PULL;
    request.local_addr = (off_t) buf;
    request.remote_addr = (off_t) prp;
    request.size = size;

    printf("Hej\n");

    if (con_fd < 1) return -1;
    if (request.direction == OXF_RDMA_PUSH){
      riowrite(con_fd, (void *) request.local_addr, request.size, request.remote_addr, 0);
      return 1;
    }

    int fulfilled = 0;
    request.fulfilment_bit = (off_t) &fulfilled;

    rsend(con_fd, &request, sizeof(request), 0);

    while (!fulfilled){ usleep(1000); }

    return 1;
}
