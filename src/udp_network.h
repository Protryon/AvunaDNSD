//
// Created by p on 4/9/19.
//

#ifndef AVUNA_DNSD_UDP_NETWORK_H
#define AVUNA_DNSD_UDP_NETWORK_H

#include "accept.h"
#include "tcp_network.h"

struct udp_param {
    struct work_param* work_param;
    struct accept_param* accept_param;
};

#endif //AVUNA_DNSD_UDP_NETWORK_H
