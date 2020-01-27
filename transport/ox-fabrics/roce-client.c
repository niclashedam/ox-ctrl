/* OX: Open-Channel NVM Express SSD Controller
 *
 *  - OX NVMe over RoCE (client side)
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
#include <ox-fabrics.h>

#include <rdma/rdma_cma.h>
#include <rdma/rsocket.h>

static void *oxf_roce_client_recv (void *arg)
{
    uint32_t *msg_bytes = calloc(1, sizeof(uint32_t));
    struct oxf_client_con *con = (struct oxf_client_con *) arg;

    while (con->running) {
        rrecv(con->sock_fd, msg_bytes, sizeof(msg_bytes), MSG_DONTWAIT);

        if (msg_bytes <= 0)
            continue;

        con->recv_fn (*msg_bytes, (void *) con->buffer);
    }

    return NULL;
}

static struct oxf_client_con *oxf_roce_client_connect (struct oxf_client *client,
       uint16_t cid, const char *addr, uint16_t port, oxf_rcv_reply_fn *recv_fn)
{
    struct oxf_client_con *con;
    unsigned int len;

    if (cid >= OXF_SERVER_MAX_CON) {
        printf ("[ox-fabrics: Invalid connection ID: %d]\n", cid);
        return NULL;
    }

    if (client->connections[cid]) {
        printf ("[ox-fabrics: Connection already established: %d]\n", cid);
        return NULL;
    }

    con = calloc (1, sizeof (struct oxf_client_con));
    if (!con)
	return NULL;

    con->cid = cid;
    con->client = client;
    con->recv_fn = recv_fn;

    if ( (con->sock_fd = rsocket(AF_INET, SOCK_STREAM, 0)) < 0 ) {
        printf ("[ox-fabrics: Socket creation failure]\n");
        free (con);
        return NULL;
    }

    len = sizeof (struct sockaddr);
    con->addr.sin_family = AF_INET;
    inet_aton (addr, (struct in_addr *) &con->addr.sin_addr.s_addr);
    con->addr.sin_port = htons(port);

    if ( rconnect(con->sock_fd, (const struct sockaddr *) &con->addr , len) < 0){
        printf ("[ox-fabrics: Socket connection failure.]\n");
        goto NOT_CONNECTED;
    }

    con->local_offset = riomap(con->sock_fd, con->buffer, OXF_MAX_DGRAM + 1, PROT_WRITE, 0,  -1);
    int ret = rsend(con->sock_fd, &con->local_offset, sizeof(con->local_offset), 0);
    if (ret != sizeof(con->local_offset)){
        printf ("[ox-fabrics: Failed to send RIO memory region.]\n");
        perror("RIO send error");
        goto NOT_CONNECTED;
    }

    ret = rrecv(con->sock_fd, &con->remote_offset , sizeof(con->remote_offset), MSG_WAITALL);
    if (ret != sizeof(con->remote_offset)){
        printf ("[ox-fabrics: Failed to receive RIO memory region.]\n");
        perror("RIO receive error");
        goto NOT_CONNECTED;
    }

    log_info("[ox-fabrics: Local RIO offset is %ld]", con->local_offset);
    log_info("[ox-fabrics: Remote RIO offset is %ld]", con->remote_offset);

    printf("[ox-fabrics: Local RIO offset is %ld]\n", con->local_offset);
    printf("[ox-fabrics: Remote RIO offset is %ld]\n", con->remote_offset);

    con->running = 1;
    if (pthread_create(&con->recv_th, NULL, oxf_roce_client_recv, (void *) con)){
        printf ("[ox-fabrics: Receive reply thread not started.]\n");
        goto NOT_CONNECTED;
    }

    client->connections[cid] = con;
    client->n_con++;

    return con;

NOT_CONNECTED:
    con->running = 0;
    rshutdown (con->sock_fd, 0);
    rclose (con->sock_fd);
    free (con);
    return NULL;
}

static int oxf_roce_client_send (struct oxf_client_con *con, uint32_t size,
                                                                const void *buf)
{
    uint32_t ret;

    riowrite(con->sock_fd, buf, size, 0, con->remote_offset);
    ret = rsend(con->sock_fd, &size, sizeof(size), 0);
    if (ret != size)
        return -1;

    return 0;
}

static void oxf_roce_client_disconnect (struct oxf_client_con *con)
{
    if (con) {
        con->running = 0;
        pthread_join (con->recv_th, NULL);
        rshutdown (con->sock_fd, 0);
        rclose (con->sock_fd);
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
