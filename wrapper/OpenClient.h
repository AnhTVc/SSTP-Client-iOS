//
//  OpenClient.h
//  connect
//
//  Created by CYTECH on 4/11/18.
//  Copyright © 2018 Tran Viet Anh. All rights reserved.
//

#import <Foundation/Foundation.h>
//#import "../openconnect.h"
//#import "open_connect.hpp"

@class NEIPv4Route;
@class NEIPv6Route;
@class NEProxyServer;

typedef NS_ENUM(NSInteger, OpenVPNProxyServerProtocol) {
    OpenProxyServerProtocolHTTP,
    OpenProxyServerProtocolHTTPS
};
NS_ASSUME_NONNULL_BEGIN

@protocol OpenClientDelegate <NSObject>
- (BOOL)setRemoteAddress:(NSString *_Nullable)address;

- (BOOL)addIPV4Address:(NSString *_Nullable)address subnetMask:(NSString *_Nullable)subnetMask gateway:(nullable NSString *)gateway;
- (BOOL)addIPV6Address:(NSString *_Nullable)address prefixLength:(NSNumber *_Nullable)prefixLength gateway:(nullable NSString *)gateway;

- (BOOL)addIPV4Route:(NEIPv4Route *_Nullable)route;
- (BOOL)addIPV6Route:(NEIPv6Route *_Nullable)route;
- (BOOL)excludeIPV4Route:(NEIPv4Route *_Nullable)route;
- (BOOL)excludeIPV6Route:(NEIPv6Route *_Nullable)route;

- (BOOL)addDNS:(NSString *_Nullable)dns;
- (BOOL)addSearchDomain:(NSString *_Nullable)domain;

- (BOOL)setMTU:(NSNumber *_Nullable)mtu;
- (BOOL)setSessionName:(NSString *_Nullable)name;

- (BOOL)addProxyBypassHost:(NSString *_Nullable)bypassHost;
- (BOOL)setProxyAutoConfigurationURL:(NSURL *_Nullable)url;
- (BOOL)setProxyServer:(NEProxyServer *_Nullable)server protocol:(OpenVPNProxyServerProtocol)protocol;

- (BOOL)establishTunnel;
- (CFSocketNativeHandle)socketHandle;

- (void)clientEventName:(NSString *_Nullable)eventName message:(nullable NSString *)message;
- (void)clientErrorName:(NSString *_Nullable)errorName fatal:(BOOL)fatal message:(nullable NSString *)message;
- (void)clientLogMessage:(NSString *_Nullable)logMessage;

- (void)tick;

- (void)resetSettings;
@end
NS_ASSUME_NONNULL_END
using namespace openconnect;
class OpenClientA : public ClientAPI::OpenClient{
public:
    OpenClientA(id<OpenClientDelegate> _Nonnull delegate);
    
    bool tun_builder_new() override;
    
    bool tun_builder_set_remote_address(const std::string& address, bool ipv6) override;
    bool tun_builder_add_address(const std::string& address, int prefix_length, const std::string& gateway,
                                 bool ipv6, bool net30) override;
    bool tun_builder_reroute_gw(bool ipv4, bool ipv6, unsigned int flags) override;
    bool tun_builder_add_route(const std::string& address, int prefix_length, int metric, bool ipv6) override;
    bool tun_builder_exclude_route(const std::string& address, int prefix_length, int metric, bool ipv6) override;
    bool tun_builder_add_dns_server(const std::string& address, bool ipv6) override;
    bool tun_builder_add_search_domain(const std::string& domain) override;
    bool tun_builder_set_mtu(int mtu) override;
    bool tun_builder_set_session_name(const std::string& name) override;
    bool tun_builder_add_proxy_bypass(const std::string& bypass_host) override;
    bool tun_builder_set_proxy_auto_config_url(const std::string& urlString) override;
    bool tun_builder_set_proxy_http(const std::string& host, int port) override;
    bool tun_builder_set_proxy_https(const std::string& host, int port) override;
    bool tun_builder_set_block_ipv6(bool block_ipv6) override;
    
    int tun_builder_establish()  override;
    bool tun_builder_persist() override;
    void tun_builder_teardown(bool disconnect) override;
    
    
private:
    __weak id<OpenClientDelegate> _Nonnull delegate;
};
