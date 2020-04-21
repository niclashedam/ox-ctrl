/* OX: Open-Channel NVM Express SSD Controller
 *
 *  - OX NVMe over RoCE (RDMA Header)
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

#ifndef OX_FABRICS_RDMA_H
#define OX_FABRICS_RDMA_H

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

void *oxf_roce_rdma_handler(void *p);
inline off_t p2o(void *p){ return (off_t) p; }

#endif /* OX_FABRICS_RDMA_H */
