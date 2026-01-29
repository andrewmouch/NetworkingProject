#pragma once

#include "parsers/context.h"

void dispatch_link_layer(packet_ctx_t* ctx);

void dispatch_network_layer(packet_ctx_t* ctx);

void dispatch_transport_layer(packet_ctx_t* ctx);