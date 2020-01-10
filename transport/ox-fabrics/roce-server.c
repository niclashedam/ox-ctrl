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

#define OXF_ROCE_DEBUG   0

/* Last connection ID that has received a 'connect' command */
uint16_t pending_conn;

static struct oxf_server_con *oxf_roce_server_bind (struct oxf_server *server,
                                uint16_t cid, const char *addr, uint16_t port)
{
    struct oxf_server_con *con;
    int ret;
    struct rdma_addrinfo hints, *res;
    struct ibv_qp_init_attr init_attr;

    if (cid > OXF_SERVER_MAX_CON) {
        log_err ("[ox-fabrics (bind): Invalid connection ID: %d]", cid);
        return NULL;
    }

    if (server->connections[cid]) {
        log_err ("[ox-fabrics (bind): Connection already established: %d]", cid);
        return NULL;
    }

    con = ox_malloc (sizeof (struct oxf_server_con), OX_MEM_ROCE_SERVER);
    if (!con)
	return NULL;

    con->cid = cid;
    con->server = server;
    con->running = 0;
    memset (con->active_cli, 0x0, OXF_SERVER_MAX_CON * sizeof (int));

    char cport[16];
    snprintf(cport, sizeof(cport), "%d", port);

	memset(&hints, 0, sizeof hints);
    hints.ai_flags = RAI_PASSIVE;
    hints.ai_port_space = RDMA_PS_TCP;

    ret = rdma_getaddrinfo(addr, cport, &hints, &res);
    if (ret) {
        log_err ("[ox-fabrics (bind): Socket creation failure. %d. %s]", con->sock_fd, gai_strerror(ret));
        ox_free (con, OX_MEM_ROCE_SERVER);
        return NULL;
	}

    ret = rdma_create_ep(&con->listen_id, res, NULL, &init_attr);
	if (ret) {
        log_err ("[ox-fabrics (bind): RoCE create EP failure.]");
        ox_free (con, OX_MEM_ROCE_SERVER);
        return NULL;
    }

    ret = rdma_listen(con->listen_id, 0);
    if (ret) {
        rdma_destroy_ep(con->listen_id);
        log_err ("[ox-fabrics (bind): RoCE listen failure.]");
        goto ERR;
    }

    server->connections[cid] = con;
    server->n_con++;

    memcpy (con->haddr.addr, addr, 15);
    con->haddr.addr[15] = '\0';
    con->haddr.port = port;

    return con;

ERR:
    shutdown (con->sock_fd, 2);
    close (con->sock_fd);
    ox_free (con, OX_MEM_ROCE_SERVER);
    return NULL;
}

static void oxf_roce_server_unbind (struct oxf_server_con *con)
{
    if (con) {
        rdma_destroy_ep(con->id);
        rdma_destroy_ep(con->listen_id);
        con->server->connections[con->cid] = NULL;
        con->server->n_con--;
        ox_free (con, OX_MEM_ROCE_SERVER);
    }
}
static uint16_t oxf_roce_server_process_msg (struct oxf_server_con *con,
                uint8_t *buffer, uint8_t *broken, uint16_t *brkb,
                uint16_t conn_id, int msg_bytes)
{
    uint16_t offset = 0, fix = 0, msg_sz, brk_bytes = *brkb;

    if (brk_bytes) {

        if (brk_bytes < 3) {

            if (msg_bytes + brk_bytes < 3) {
                memcpy (&broken[brk_bytes], buffer, msg_bytes);
                brk_bytes += msg_bytes;
                return brk_bytes;
            }

            memcpy (&broken[brk_bytes], buffer, 3 - brk_bytes);
            offset = fix = 3 - brk_bytes;
            msg_bytes -= 3 - brk_bytes;
            brk_bytes = 3;
            if (!msg_bytes)
                return brk_bytes;
        }

        msg_sz = ((struct oxf_capsule_sq *) broken)->size;

        if (brk_bytes + msg_bytes < msg_sz) {
            memcpy (&broken[brk_bytes], &buffer[offset], msg_bytes);
            brk_bytes += msg_bytes;
            return brk_bytes;
        }

        memcpy (&broken[brk_bytes], &buffer[offset], msg_sz - brk_bytes);
        con->rcv_fn (msg_sz, (void *) broken,
                                            (void *) &con->active_cli[conn_id]);
        offset += msg_sz - brk_bytes;
        brk_bytes = 0;
    }

    msg_bytes += fix;
    while (offset < msg_bytes) {
        if ( (msg_bytes - offset < 3) ||
            (msg_bytes - offset <
                         ((struct oxf_capsule_sq *) &buffer[offset])->size) ) {
            memcpy (broken, &buffer[offset], msg_bytes - offset);
            brk_bytes = msg_bytes - offset;
            offset += msg_bytes - offset;
            continue;
        }

        msg_sz = ((struct oxf_capsule_sq *) &buffer[offset])->size;
        con->rcv_fn (msg_sz, (void *) &buffer[offset],
                                           (void *) &con->active_cli[conn_id]);
        offset += msg_sz;
    }

    return brk_bytes;
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
    if (con->running)
        return 0;

    con->running = 1;
    con->rcv_fn = fn;

    if (pthread_create (&con->tid, NULL, oxf_roce_server_accept_th, con)) {
	log_err ("[ox-fabrics: Connection not started.]");
	con->running = 0;
	return -1;
    }

    return 0;
}

static void oxf_roce_server_con_stop (struct oxf_server_con *con)
{
    uint32_t cli_id;

    if (con && con->running)
	con->running = 0;
    else
        return;

    for (cli_id = 0; cli_id < OXF_SERVER_MAX_CON; cli_id++) {
        if (con->active_cli[cli_id]) {
            con->active_cli[cli_id] = 0;
            pthread_join (con->cli_tid[cli_id], NULL);
        }
    }
    pthread_join (con->tid, NULL);
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

    log_info ("[ox-fabrics: Protocol -> RoCE]\n");

    return server;
}
