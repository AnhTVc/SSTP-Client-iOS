//
//  OpenAdapter.m
//  connect
//
//  Created by CYTECH on 4/11/18.
//  Copyright © 2018 Tran Viet Anh. All rights reserved.
//

#import "OpenAdapter.h"
#import <NetworkExtension/NetworkExtension.h>
#import "OpenClient.h"
#import "OpenPacketFlowBridge.h"
//#import "open_connect.hpp"
#import "OpenNetworkSettingsBuilder.h"
@interface OpenAdapter () <OpenClientDelegate>
@property (nonatomic) OpenClientA *vpnClient;
@property (nonatomic) OpenPacketFlowBridge *packetFlowBridge;
@property (nonatomic) OpenNetworkSettingsBuilder *networkSettingsBuilder;
@end
@implementation OpenAdapter

- (instancetype)init {
    if (self = [super init]) {
        _vpnClient = new OpenClientA(self);
    }
    return self;
}
#pragma mark - Lazy Initialization

- (OpenNetworkSettingsBuilder *)networkSettingsBuilder {
    if (!_networkSettingsBuilder) { _networkSettingsBuilder = [[OpenNetworkSettingsBuilder alloc] init]; }
    return _networkSettingsBuilder;
}

#pragma mark - OpenVPNClientDelegate

- (BOOL)setRemoteAddress:(NSString *)address {
    self.networkSettingsBuilder.remoteAddress = address;
    return YES;
}

- (BOOL)addIPV4Address:(NSString *)address subnetMask:(NSString *)subnetMask gateway:(NSString *)gateway {
    self.networkSettingsBuilder.ipv4DefaultGateway = gateway;
    [self.networkSettingsBuilder.ipv4LocalAddresses addObject:address];
    [self.networkSettingsBuilder.ipv4SubnetMasks addObject:subnetMask];
    
    return YES;
}

- (BOOL)addIPV6Address:(NSString *)address prefixLength:(NSNumber *)prefixLength gateway:(NSString *)gateway {
    self.networkSettingsBuilder.ipv6DefaultGateway = gateway;
    [self.networkSettingsBuilder.ipv6LocalAddresses addObject:address];
    [self.networkSettingsBuilder.ipv6NetworkPrefixLengths addObject:prefixLength];
    
    return YES;
}

- (BOOL)addIPV4Route:(NEIPv4Route *)route {
    route.gatewayAddress = self.networkSettingsBuilder.ipv4DefaultGateway;
    [self.networkSettingsBuilder.ipv4IncludedRoutes addObject:route];
    
    return YES;
}

- (BOOL)addIPV6Route:(NEIPv6Route *)route {
    route.gatewayAddress = self.networkSettingsBuilder.ipv6DefaultGateway;
    [self.networkSettingsBuilder.ipv6IncludedRoutes addObject:route];
    
    return YES;
}

- (BOOL)excludeIPV4Route:(NEIPv4Route *)route {
    [self.networkSettingsBuilder.ipv4ExcludedRoutes addObject:route];
    return YES;
}

- (BOOL)excludeIPV6Route:(NEIPv6Route *)route {
    [self.networkSettingsBuilder.ipv6ExcludedRoutes addObject:route];
    return YES;
}

- (BOOL)addDNS:(NSString *)dns {
    [self.networkSettingsBuilder.dnsServers addObject:dns];
    return YES;
}

- (BOOL)addSearchDomain:(NSString *)domain {
    [self.networkSettingsBuilder.searchDomains addObject:domain];
    return YES;
}

- (BOOL)setMTU:(NSNumber *)mtu {
    self.networkSettingsBuilder.mtu = mtu;
    return YES;
}

- (BOOL)setSessionName:(NSString *)name {
    _sessionName = name;
    return YES;
}

- (BOOL)addProxyBypassHost:(NSString *)bypassHost {
    [self.networkSettingsBuilder.proxyExceptionList addObject:bypassHost];
    return YES;
}

- (BOOL)setProxyAutoConfigurationURL:(NSURL *)url {
    self.networkSettingsBuilder.autoProxyConfigurationEnabled = YES;
    self.networkSettingsBuilder.proxyAutoConfigurationURL = url;
    
    return YES;
}

- (BOOL)setProxyServer:(NEProxyServer *)server protocol:(OpenVPNProxyServerProtocol)protocol {
    switch (protocol) {
        case OpenProxyServerProtocolHTTP:
            self.networkSettingsBuilder.httpProxyServerEnabled = YES;
            self.networkSettingsBuilder.httpProxyServer = server;
            break;
            
        case OpenProxyServerProtocolHTTPS:
            self.networkSettingsBuilder.httpsProxyServerEnabled = YES;
            self.networkSettingsBuilder.httpsProxyServer = server;
            break;
    }
    
    return YES;
}

- (void)clientErrorName:(NSString * _Nullable)errorName fatal:(BOOL)fatal message:(nullable NSString *)message {
    
}


- (void)clientEventName:(NSString * _Nullable)eventName message:(nullable NSString *)message {
    
}


- (void)clientLogMessage:(NSString * _Nullable)logMessage {
    
}

- (void)connect: (NSString *) host user:(NSString *)username pass:(NSString *) password add:(Boolean) isGP{
    dispatch_queue_attr_t attributes = dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL, QOS_CLASS_UTILITY, 0);
    dispatch_queue_t connectQueue = dispatch_queue_create("me.ss-abramchuk.open-adapter.connection", attributes);
    dispatch_async(connectQueue, ^{
        // Call connect
        NSArray* options = [NSArray arrayWithObjects:@"--dtls-ciphers", @"OC-DTLS1_2-AES128-GCM",@"--no-cert-check", @"--user", username,
                            host,
                            nil];

        NSArray *paths = NSSearchPathForDirectoriesInDomains
        (NSDocumentDirectory, NSUserDomainMask, YES);
        //NSString *documentsDirectory = [paths objectAtIndex:0];
        
        NSMutableArray *arguments = [NSMutableArray arrayWithCapacity:1+[options count]];
        [arguments addObject:@"openconnect"];
        [arguments addObjectsFromArray:options];
        
        int argc = [arguments count];
        char **argv = (char **)malloc(sizeof(char*) * (argc + 1));
        
        [arguments enumerateObjectsUsingBlock:^(NSString *option, NSUInteger i, BOOL *stop) {
            const char * c_string = [option UTF8String];
            int length = strlen(c_string);
            char *c_string_copy = (char *) malloc(sizeof(char) * (length + 1));
            strcpy(c_string_copy, c_string);
            argv[i] = c_string_copy;
        }];
        argv[argc] = NULL;
        const char *cfPass=[password UTF8String];
        // TODO
        int result = self.vpnClient->connect();
    });
}

- (BOOL)establishTunnel {
    NEPacketTunnelNetworkSettings *networkSettings = [self.networkSettingsBuilder networkSettings];
    if (!networkSettings) { return NO; }
    
    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
    
    __weak typeof(self) weakSelf = self;
    void (^completionHandler)(id<OpenAdapterPacketFlow> _Nullable) = ^(id<OpenAdapterPacketFlow> flow) {
        __strong typeof(self) self = weakSelf;
        if (flow) {
            self.packetFlowBridge = [[OpenPacketFlowBridge alloc] initWithPacketFlow:flow];
        }
        
        dispatch_semaphore_signal(semaphore);
    };
    // send to
    [self.delegate openVPNAdapter:self configureTunnelWithNetworkSettings:networkSettings completionHandler:completionHandler];
    
    dispatch_semaphore_wait(semaphore, dispatch_time(DISPATCH_TIME_NOW, 30 * NSEC_PER_SEC));
    
    NSError *socketError;
    if (self.packetFlowBridge && [self.packetFlowBridge configureSocketsWithError:&socketError]) {
        [self.packetFlowBridge startReading];
        return YES;
    } else {
        if (socketError) { [self.delegate openVPNAdapter:self handleError:socketError]; }
        return NO;
    }
}


- (void)resetSettings {
    _sessionName = nil;
    _packetFlowBridge = nil;
    _networkSettingsBuilder = nil;
}


- (CFSocketNativeHandle)socketHandle {
    return CFSocketGetNative(self.packetFlowBridge.openVPNSocket);
}


- (void)tick {
    
}



@end


