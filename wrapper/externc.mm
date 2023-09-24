//
//  externc.cpp
//  OpenConnectNew
//
//  Created by Tran Viet Anh on 4/10/18.
//  Copyright © 2018 NextVPN Corporation. All rights reserved.
//

#include "externc.hpp"
#include "cplus_objectivec.h"
#include "base.h"
#import "OpenClient.h"
using namespace SSTPClientNameSpace;
//void mylibrary_mytype_destroy(mylibrary_mytype_t untyped_ptr) {
//   return;
//}
//
//void mylibrary_mytype_doit(mylibrary_mytype_t untyped_self, int param) {
//    return;
//}

int test_externc(struct oc_ip_info *info_ip, void * tb){
    OpenClientA *openclient = (OpenClientA *) tb;
    // reset
    /*
     Printing description of info_ip->addr:
     (const char *) addr = 0x000000010046de50 "10.10.85.165"
     Printing description of info_ip->netmask:
     (const char *) netmask = 0x000000010046de90 "255.255.0.0"
     Printing description of info_ip->dns:
     (const char *[3]) dns = ([0] = "8.8.8.8", [1] = "8.8.4.4", [2] = 0x0000000000000000)
     Printing description of info_ip->domain:
     (const char *) domain = 0x000000010046de10 "cisco.com"
     Printing description of info_ip->mtu:
     (int) mtu = 1279
     Printing description of info_ip->split_excludes->route:
     (const char *) route = 0x000000010046e090 "192.168.0.0/255.255.0.0"
     Printing description of info_ip->split_excludes->next->route:
     (const char *) route = 0x000000010046e020 "172.16.0.0/255.240.0.0"
     Printing description of info_ip->split_excludes->next->next->route:
     (const char *) route = 0x000000010046dfb0 "10.0.0.0/255.0.0.0"
     Printing description of info_ip->gateway_addr:
     (char *) gateway_addr = 0x0000000100468f60 "173.244.217.97"
     */
    openclient->tun_builder_new();
    // TODO AnhTV add address
//    openclient->tun_builder_add_address( std::string(info_ip->addr), 16, std::string(info_ip->gateway_addr), false, false);
    openclient->tun_builder_add_dns_server("8.8.8.8", false);
    openclient->tun_builder_add_dns_server("8.8.4.4", false);
    
    // TODO AnhTV add gateway
//    openclient->tun_builder_set_remote_address(std::string(info_ip->gateway_addr), false);
    // TODO AnhTV add mtu
//    openclient->tun_builder_set_mtu(info_ip->mtu);
    openclient->tun_builder_add_route("0.0.0.0", 16, -1, false);
    openclient->tun_builder_exclude_route("0.0.0.0", 16, -1, false);
    //openclient->tun_builder_add_route("10.0.0.0", 8, -1, false);
    //openclient->tun_builder_add_route("172.16.0.0", 12, -1, false);
    return openclient->tun_builder_establish();
}
