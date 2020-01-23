/* OX: Open-Channel NVM Express SSD Controller
 *
 *  - OX NVMe over RoCE (server side)
 *
 * Copyright 2020 IT University of Copenhagen
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

#include "roce-helper.h"

/* Last connection ID that has received a 'connect' command */
uint16_t pending_conn;

static void oxf_roce_server_unbind (struct oxf_server_con *con)
{
    if (con) {
        if(con->listen_id) rdma_destroy_ep(con->listen_id);
        con->server->connections[con->cid] = NULL;
        con->server->n_con--;
        free (con);
    }
}

static struct oxf_server_con *oxf_roce_server_bind (struct oxf_server *server,
                                uint16_t cid, const char *addr, uint16_t port)
{
    struct oxf_server_con *con = malloc (sizeof (struct oxf_server_con));;
    if(!con) return NULL;

    int ret;
    struct rdma_addrinfo *res;

    if (cid > OXF_SERVER_MAX_CON) {
        log_err ("[ox-fabrics: Invalid connection ID: %d]", cid);
        return NULL;
    }

    if (server->connections[cid]) {
        log_err ("[ox-fabrics: Connection already established: %d]", cid);
        return NULL;
    }

    /* Change port for different connections */
    port = port + cid;

    con->cid = cid;
    con->server = server;
    con->running = 0;
    con->addr.sin_family = AF_INET;
    inet_aton (addr, (struct in_addr *) &con->addr.sin_addr.s_addr);
    con->addr.sin_port = htons(port);

    char cport[16];
    snprintf(cport, sizeof(cport), "%d", port);

    ret = rdma_getaddrinfo(addr, cport, hints(1), &res);
    ret = rdma_create_ep(&con->listen_id, res, NULL, attr());
    if (ret) {
        log_err ("[ox-fabrics: RoCE create EP failure.]");
        perror("RoCE EP creation failture");
	goto ERR;
    }

    printf("ID\n");

    ret = rdma_listen(con->listen_id, 0);
    if (ret) {
        log_err ("[ox-fabrics: RoCE listen failure.]");
        goto ERR;
    }

    printf("Listen\n");

    server->connections[cid] = con;
    server->n_con++;

    memcpy (con->haddr.addr, addr, 15);
    con->haddr.addr[15] = '\0';
    con->haddr.port = port;

    return con;

ERR:
    oxf_roce_server_unbind(con);
    return NULL;
}

static void *oxf_roce_server_con_th (void *arg)
{
    struct oxf_server_con *con = (struct oxf_server_con *) arg;
    uint8_t buffer[OXF_MAX_DGRAM + 1];
    uint8_t ack[2];
    int n, ret;

    struct rdma_cm_id *id;
    struct ibv_wc wc;

    ack[0] = OXF_ACK_BYTE;
    while (con->running) {
        printf("Waiting ..\n");
        ret = rdma_get_request(con->listen_id, &id);
        if(ret){
            log_err ("[ox-fabrics: error in rdma_get_request]");
            perror("Received connection, but something broke");
            continue;
        }

        printf("Receiving\n");

        struct ibv_mr *mr = rdma_reg_msgs(id, buffer, OXF_MAX_DGRAM + 1);
        ret = rdma_post_recv(id, NULL, buffer, OXF_MAX_DGRAM, mr);
        if(ret){
            log_err ("[ox-fabrics: error in rdma_post_recv]");
            continue;
        }

        printf("Accepting\n");

        ret = rdma_accept(id, NULL);
        if (ret) {
            log_err ("[ox-fabrics: error in rdma_accept]");
            continue;
        }

        printf("Will receive\n");

        while ((ret = rdma_get_recv_comp(id, &wc)) == 0);
        if (ret < 0) {
            perror("rdma_get_recv_comp");
            rdma_disconnect(id);
            rdma_destroy_ep(id);
            return NULL;
        }

        printf("Received\n");

        n = wc.byte_len;
        buffer[n] = '\0';

        printf("n = %d, b0 = %d, con_byte = %d\n", n, buffer[0], OXF_CON_BYTE);

        if (n < 0)
            continue;

        if (n == 1 && (buffer[0] == OXF_CON_BYTE) )
            goto ACK;

        con->rcv_fn (n, (void *) buffer, (void *) &id);
        continue;

ACK:

        printf("Before ACK\n");

        ret = rdma_post_send(id, NULL, ack, 1, NULL, send_flags(1));
        if (ret) {
            perror("rdma_post_send");
            log_err ("[ox-fabrics: error in rdma_post_send]");
            rdma_disconnect(id);
            rdma_destroy_ep(id);
            return NULL;
        }

        printf("During ACK\n");

        while ((ret = rdma_get_send_comp(id, &wc)) == 0);
        if (ret < 0){
            perror("rdma_get_send_comp");
            log_err ("[ox-fabrics: Connect ACK hasn't been sent.]");
            rdma_disconnect(id);
            rdma_destroy_ep(id);
            return NULL;
        }

         printf("After ack\n");
    }

    log_err ("[ox-fabrics: Connection %d is closed.]", con->cid);

    return NULL;
}

static int oxf_roce_server_reply(struct oxf_server_con *con, const void *buf,
                                                 uint32_t size, void *recv_cli)
{
    struct ibv_wc wc;
    struct rdma_cm_id *id = (struct rdma_cm_id *) recv_cli;

    int ret = rdma_post_send(id, NULL, &buf, size, NULL, send_flags(size));
    if (ret) goto SEND_ERROR;

    while ((ret = rdma_get_send_comp(id, &wc)) == 0);
    if (ret < 0) goto SEND_ERROR;
    else ret = 0;

SEND_ERROR:
    if (ret) {
        log_err ("[ox-fabrics: Completion reply hasn't been sent. %d]", ret);
        return -1;
    }

    return 0;
}

static int oxf_roce_server_con_start (struct oxf_server_con *con, oxf_rcv_fn *fn)
{
    con->running = 1;
    con->rcv_fn = fn;

    if (pthread_create (&con->tid, NULL, oxf_roce_server_con_th, con)) {
	log_err ("[ox-fabrics: Connection not started.]");
	con->running = 0;
	return -1;
    }

    return 0;
}

static void oxf_roce_server_con_stop (struct oxf_server_con *con)
{
    if (con && con->running)
	con->running = 0;
    else
        return;

    pthread_join (con->tid, NULL);
}
void oxf_roce_server_exit (struct oxf_server *server)
{
    free (server);
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

    server = calloc (1, sizeof (struct oxf_server));
    if (!server)
	return NULL;

    server->ops = &oxf_roce_srv_ops;

    log_info ("[ox-fabrics: Protocol -> RoCE\n");

    return server;
}
