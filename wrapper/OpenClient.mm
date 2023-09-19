//
//  OpenClient.m
//  connect
//
//  Created by CYTECH on 4/11/18.
//  Copyright © 2018 Tran Viet Anh. All rights reserved.
//
#define INVALID_SOCKET -1
#import "OpenClient.h"
#import "cplus_objectivec.h"

#import <NetworkExtension/NetworkExtension.h>

OpenClientA::OpenClientA(id<OpenClientDelegate> delegate): ClientAPI::OpenClient() {
    this->delegate = delegate;
}

int tunnel(struct oc_ip_info *info_ip){
    buider->tun_builder_establish();
    return 0;
}
bool OpenClientA::tun_builder_new() {
    [this->delegate resetSettings];
    return true;
}

bool OpenClientA::tun_builder_set_remote_address(const std::string &address, bool ipv6) {
    NSString *remoteAddress = [NSString stringWithUTF8String:address.c_str()];
    return [this->delegate setRemoteAddress:remoteAddress];
}

bool OpenClientA::tun_builder_add_address(const std::string &address, int prefix_length, const std::string &gateway, bool ipv6, bool net30) {
    NSString *localAddress = [NSString stringWithUTF8String:address.c_str()];
    NSString *gatewayAddress = gateway.length() == 0 || gateway.compare("UNSPEC") == 0 ? nil :
    [NSString stringWithUTF8String:gateway.c_str()];
    
    if (ipv6) {
        return [this->delegate addIPV6Address:localAddress prefixLength:@(prefix_length) gateway:gatewayAddress];
    } else {
        //NSString *subnetMask = [NSString stringWithUTF8String:Addr::netmask_from_prefix_len(prefix_length).to_string().c_str()];
        
        NSString *subnetMask = @"255.255.0.0";
        return [this->delegate addIPV4Address:localAddress subnetMask:subnetMask gateway:gatewayAddress];
    }
}

bool OpenClientA::tun_builder_reroute_gw(bool ipv4, bool ipv6, unsigned int flags) {
    if (ipv4 && ![this->delegate addIPV4Route:[NEIPv4Route defaultRoute]]) {
        return false;
    }
    
    if (ipv6 && ![this->delegate addIPV6Route:[NEIPv6Route defaultRoute]]) {
        return false;
    }
    
    return true;
}

bool OpenClientA::tun_builder_add_route(const std::string& address, int prefix_length, int metric, bool ipv6) {
    NSString *routeAddress = [NSString stringWithUTF8String:address.c_str()];
    
    if (ipv6) {
        NEIPv6Route *route = [[NEIPv6Route alloc] initWithDestinationAddress:routeAddress networkPrefixLength:@(prefix_length)];
        return [this->delegate addIPV6Route:route];
    } else {
       // NSString *subnetMask = [NSString stringWithUTF8String:Addr::netmask_from_prefix_len(prefix_length).to_string().c_str()];
        NSString *subnetMask = @"0.0.0.0";
        NEIPv4Route *route = [[NEIPv4Route alloc] initWithDestinationAddress:routeAddress subnetMask:subnetMask];
        return [this->delegate addIPV4Route:route];
    }
}

bool OpenClientA::tun_builder_exclude_route(const std::string& address, int prefix_length, int metric, bool ipv6) {
    NSString *routeAddress = @"10.0.0.0";
    NSString *subnetMask = @"255.0.0.0";
    NEIPv4Route *route = [[NEIPv4Route alloc] initWithDestinationAddress:routeAddress subnetMask:subnetMask];
    [this->delegate excludeIPV4Route:route];
    
    routeAddress = @"172.16.0.0";
    subnetMask = @"255.240.0.0";
    route = [[NEIPv4Route alloc] initWithDestinationAddress:routeAddress subnetMask:subnetMask];
    [this->delegate excludeIPV4Route:route];
    
    routeAddress = @"192.168.0.0";
    subnetMask = @"255.255.0.0";
    route = [[NEIPv4Route alloc] initWithDestinationAddress:routeAddress subnetMask:subnetMask];
    return [this->delegate excludeIPV4Route:route];
}

bool OpenClientA::tun_builder_add_dns_server(const std::string& address, bool ipv6) {
    NSString *dns = [NSString stringWithUTF8String:address.c_str()];
    return [this->delegate addDNS:dns];
}

bool OpenClientA::tun_builder_add_search_domain(const std::string& domain) {
    NSString *searchDomain = [NSString stringWithUTF8String:domain.c_str()];
    return [this->delegate addSearchDomain:searchDomain];
}

bool OpenClientA::tun_builder_set_mtu(int mtu) {
    return [this->delegate setMTU:@(mtu)];
}

bool OpenClientA::tun_builder_set_session_name(const std::string& name) {
    NSString *sessionName = [NSString stringWithUTF8String:name.c_str()];
    return [this->delegate setSessionName:sessionName];
}

bool OpenClientA::tun_builder_add_proxy_bypass(const std::string& bypass_host) {
    NSString *bypassHost = [NSString stringWithUTF8String:bypass_host.c_str()];
    return [this->delegate addProxyBypassHost:bypassHost];
}

bool OpenClientA::tun_builder_set_proxy_auto_config_url(const std::string& url) {
    NSURL *configURL = [[NSURL alloc] initWithString:[NSString stringWithUTF8String:url.c_str()]];
    if (configURL) {
        return [this->delegate setProxyAutoConfigurationURL:configURL];
    } else {
        return false;
    }
}

bool OpenClientA::tun_builder_set_proxy_http(const std::string& host, int port) {
    NSString *proxyHost = [NSString stringWithUTF8String:host.c_str()];
    NEProxyServer *proxyServer = [[NEProxyServer alloc] initWithAddress:proxyHost port:port];
    return [this->delegate setProxyServer:proxyServer protocol:OpenProxyServerProtocolHTTP];
}

bool OpenClientA::tun_builder_set_proxy_https(const std::string& host, int port) {
    NSString *proxyHost = [NSString stringWithUTF8String:host.c_str()];
    NEProxyServer *proxyServer = [[NEProxyServer alloc] initWithAddress:proxyHost port:port];
    return [this->delegate setProxyServer:proxyServer protocol:OpenProxyServerProtocolHTTPS];
}

bool OpenClientA::tun_builder_set_block_ipv6(bool block_ipv6) {
    return block_ipv6;
}

int OpenClientA::tun_builder_establish() {
    
    return [this->delegate establishTunnel] ? [this->delegate socketHandle] : INVALID_SOCKET;
}

bool OpenClientA::tun_builder_persist() {
    return true;
}

void OpenClientA::tun_builder_teardown(bool disconnect) {
    [this->delegate resetSettings];
}

