/* OX: Open-Channel NVM Express SSD Controller
 *
 *  - OX NVMe over RoCE (client side)
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
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <netdb.h>
#include <rdma/rdma_cma.h>
#include <rdma/rdma_verbs.h>
#include <ox-fabrics.h>
#include <libox.h>

#include "roce-helper.h"

static void *oxf_roce_client_recv (void *arg)
{
    int ret;
    uint8_t buf[OXF_MAX_DGRAM + 1];
    struct oxf_client_con *con = (struct oxf_client_con *) arg;
    struct ibv_mr *mr = rdma_reg_msgs(con->id, buf, OXF_MAX_DGRAM + 1);
    struct ibv_wc wc;

    while (con->running) {
        ret = rdma_post_recv(con->id, NULL, buf, OXF_MAX_DGRAM, mr);

        if(ret){
            log_err ("[ox-fabrics: error in rdma_post_recv]");
            return NULL;
        }


        while ((ret = rdma_get_recv_comp(con->id, &wc)) == 0);

        if (wc.byte_len > 0)
            con->recv_fn (wc.byte_len, (void *) buf);
    }

    return NULL;
}

static struct oxf_client_con *oxf_roce_client_connect (struct oxf_client *client,
       uint16_t cid, const char *addr, uint16_t port, oxf_rcv_reply_fn *recv_fn)
{
    struct oxf_client_con *con = calloc (1, sizeof (struct oxf_client_con));
    if (!con) return NULL;

    int ret;
    struct rdma_addrinfo *res = NULL;
    struct rdma_cm_id *id = NULL;
    uint8_t connect[2], ack[2];

    if (cid >= OXF_SERVER_MAX_CON) {
        printf ("[ox-fabrics: Invalid connection ID: %d]", cid);
        return NULL;
    }

    if (client->connections[cid]) {
        printf ("[ox-fabrics: Connection already established: %d]", cid);
        return NULL;
    }

    /* Change port for different connections */
    port = port + cid;

    con->cid = cid;
    con->client = client;
    con->recv_fn = recv_fn;

    char cport[16];
    snprintf(cport, sizeof(cport), "%d", port);

    ret = rdma_getaddrinfo(addr, cport, hints(0), &res);
    if (ret) {
        log_err ("[ox-fabrics: Socket creation failure. %d. %s]", con->sock_fd, gai_strerror(ret));
        perror("Failed ID");
        goto NOT_CONNECTED;
    }

    printf("Got addr\n");

    ret = rdma_create_ep(&id, res, NULL, attr());
    if (ret) {
        log_err ("[ox-fabrics: RoCE create EP failure.]");
        goto NOT_CONNECTED;
    }

    struct ibv_wc wc;

    ret = rdma_connect(id, NULL);
    if (ret) {
        log_err ("[ox-fabrics: Could not connect. Is the server running?]");
        perror("Could not connect");
        goto NOT_CONNECTED;
    }

    printf("Connected\n");
    connect[0] = OXF_CON_BYTE;

    ret = rdma_post_send(id, NULL, connect, 1, NULL, send_flags(1));
    if (ret) goto NOT_CONNECTED;

    printf("Handshake 1\n");

    while ((ret = rdma_get_send_comp(id, &wc)) == 0);

    if (ret < 0) goto NOT_CONNECTED;
    else ret = 0;


    printf("Handshake 2\n");

    struct ibv_mr *mr = rdma_reg_msgs(id, ack, 2);
    ret = rdma_post_recv(id, NULL, ack, 2, mr);

    if(ret){
        log_err ("[ox-fabrics: error in rdma_post_recv]");
        goto NOT_CONNECTED;
    }

    printf("Handshake 3\n");

    while ((ret = rdma_get_recv_comp(id, &wc)) == 0);

    printf("Handshake 4\n");

    if (ack[0] != OXF_ACK_BYTE) {
        printf ("[ox-fabrics: Server responded, but byte is incorrect: %x]\n",
                                                                        ack[0]);
        goto NOT_CONNECTED;
    }

    con->running = 1;
    client->connections[cid] = con;
    client->connections[cid]->id = id;
    printf("Setting ID for connection %d\n", cid);
    client->n_con++;

    sleep(1);

    if (pthread_create(&con->recv_th, NULL, oxf_roce_client_recv, (void *) con)){
        printf ("[ox-fabrics: Receive reply thread not started.]");
        goto NOT_CONNECTED;
    }

    return con;

NOT_CONNECTED:
    if(id) rdma_disconnect(id);
    if(id) rdma_destroy_ep(id);
    if(con && con->listen_id) rdma_destroy_ep(con->listen_id);
    free (con);
    return NULL;
}

static int oxf_roce_client_send (struct oxf_client_con *con, uint32_t size,
                                                                const void *buf)
{
    struct ibv_wc wc;

    printf("Sending from connection %d\n", con->cid);
    int ret = rdma_post_send(con->id, NULL, buf, size, NULL, send_flags(size));
    if (ret) goto SEND_ERROR;
    while ((ret = rdma_get_send_comp(con->id, &wc)) == 0);
    if (ret < 0) goto SEND_ERROR;
    else ret = 0;

    printf("Sent\n");

SEND_ERROR:
    if (ret) {
        perror("Could not send");
        log_err ("[ox-fabrics: Send failed]");
        return -1;
    }

    return 0;
}

static void oxf_roce_client_disconnect (struct oxf_client_con *con)
{
    if (con) {
        con->running = 0;
        pthread_join (con->recv_th, NULL);
        if(con->listen_id) rdma_destroy_ep(con->listen_id);
        con->client->connections[con->cid] = NULL;
        con->client->n_con--;
        free (con);
    }
}

void oxf_roce_client_exit (struct oxf_client *client)
{
    free (client);
}

struct oxf_client_ops oxf_roce_cli_ops = {
    .connect    = oxf_roce_client_connect,
    .disconnect = oxf_roce_client_disconnect,
    .send       = oxf_roce_client_send
};

struct oxf_client *oxf_roce_client_init (void)
{
    struct oxf_client *client;

    client = calloc (1, sizeof (struct oxf_client));
    if (!client)
	return NULL;

    client->ops = &oxf_roce_cli_ops;

    return client;
}
