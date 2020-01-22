/* OX: Open-Channel NVM Express SSD Controller
 *
 *  - OX NVMe over RoCE (helpers)
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

#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <rdma/rdma_cma.h>
#include <rdma/rdma_verbs.h>

inline static struct ibv_qp_init_attr *attr (void)
{
    struct ibv_qp_init_attr *attr = malloc(sizeof *attr);
    memset(attr, 0, sizeof *attr);
    attr->cap.max_send_wr = attr->cap.max_recv_wr = 1;
    attr->cap.max_send_sge = attr->cap.max_recv_sge = 1;
    attr->cap.max_inline_data = 16;
    attr->sq_sig_all = 1;
    return attr;
}

inline static struct rdma_addrinfo *hints (short isServer)
{
    struct rdma_addrinfo *hints = malloc(sizeof *hints);
    memset(hints, 0, sizeof *hints);
    hints->ai_port_space = RDMA_PS_TCP;
    if(isServer) hints->ai_flags = RAI_PASSIVE;
    return hints;
}
