/* OX: Open-Channel NVM Express SSD Controller
 *
 *  - OX NVMe over RoCE (server side)
 *
 * Copyright 2019 IT University of Copenhagen
 *
 * Written by Niclas Hedam <nhed@itu.dk>
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
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sched.h>
#include <errno.h>
#include <rdma/rdma_cma.h>
#include <rdma/rdma_verbs.h>
#include <ox-fabrics.h>
#include <libox.h>


/* Last connection ID that has received a 'connect' command */
uint16_t pending_conn;

static struct oxf_server_con *oxf_roce_server_bind (struct oxf_server *server,
                                uint16_t cid, const char *addr, uint16_t port)
{
    //
}

static void oxf_roce_server_unbind (struct oxf_server_con *con)
{
    //
}

static uint16_t oxf_roce_server_process_msg (struct oxf_server_con *con,
                uint8_t *buffer, uint8_t *broken, uint16_t *brkb,
                uint16_t conn_id, int msg_bytes)
{
    //
}

static void *oxf_roce_server_con_th (void *arg)
{
    //
}

static void *oxf_roce_server_accept_th (void *arg)
{
    //
}

static int oxf_roce_server_reply(struct oxf_server_con *con, const void *buf,
                                                 uint32_t size, void *recv_cli)
{
    //
}

static int oxf_roce_server_con_start (struct oxf_server_con *con, oxf_rcv_fn *fn)
{
    //
}

static void oxf_roce_server_con_stop (struct oxf_server_con *con)
{
    //
}

void oxf_roce_server_exit (struct oxf_server *server)
{
    uint32_t con_i;

    for (con_i = 0; con_i < OXF_SERVER_MAX_CON; con_i++)
        oxf_roce_server_con_stop (server->connections[con_i]);

    ox_free (server, OX_MEM_ROCE_SERVER);
}


struct oxf_server_ops oxf_roce_srv_ops = {
    .bind    = oxf_roce_server_bind,
    .unbind  = oxf_roce_server_unbind,
    .start   = oxf_roce_server_con_start,
    .stop    = oxf_roce_server_con_stop,
    .reply   = oxf_roce_server_reply
};

struct oxf_server *oxf_roce_server_init (void){
    struct oxf_server *server;

    if (!ox_mem_create_type ("ROCE_SERVER", OX_MEM_ROCE_SERVER))
        return NULL;

    server = ox_calloc (1, sizeof (struct oxf_server), OX_MEM_ROCE_SERVER);
    if (!server) return NULL;

    server->ops = &oxf_roce_srv_ops;

    log_info ("[ox-fabrics: Protocol -> RoCE\n");

    return server;
}
