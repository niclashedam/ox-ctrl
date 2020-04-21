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

#include <roce-rdma.h>
#include <rdma/rsocket.h>

void *oxf_roce_rdma_handler(void *p){
    struct oxf_rdma_state *state = (struct oxf_rdma_state *) p;

LISTEN:
    if(state->listen){
        log_info("[ox-fabrics (RDMA): Waiting for RDMA client to connect.]");
        state->con_fd = raccept(state->sock_fd, (struct sockaddr *) &state->inet_addr, &state->len);

        for(int i = 0; i < OXF_RDMA_COUNT; i++){
            state->buffers[i].buf = malloc(OXF_RDMA_SIZE);
            state->buffers[i].size = OXF_RDMA_SIZE;
            state->buffers[i].status = OXF_RDMA_BUFFER_OPEN;
            riomap(
                state->con_fd,
                state->buffers[i].buf,
                state->buffers[i].size,
                PROT_WRITE, 0, -1
            );
        }
    }

    if (state->con_fd == -1) {
        log_err ("[ox-fabrics (RDMA): Socket accept failure. Data path will be unavailable.]");
        return state;
    }

    log_info("[ox-fabrics (RDMA): RDMA connection established.]");

    printf("Handler started!\n");

    if(state->listen){
        rsend(state->con_fd, state->buffers, sizeof(state->buffers), 0);
    } else {
        rrecv(state->con_fd, state->buffers, sizeof(state->buffers), 0);
    }

    *state->is_running = 1;

    while(*state->is_running){
        // int bytes = rrecv(state->con_fd, &request , sizeof(request), MSG_DONTWAIT);

        /* Timeout */
        // if (bytes < 0) continue;


        /* Client disconnected */
        // if(bytes == 0){
        //     printf("Remote disconnected\n");
        //     log_info("[ox-fabrics (RDMA): RDMA client disconnected.]");
        //     if(state->listen)   goto LISTEN;
        //                         goto EXIT;
        // }


        usleep(1000);
    }

EXIT:
    log_info("[ox-fabrics (RDMA): Handler exited.]");

    return state;
}
