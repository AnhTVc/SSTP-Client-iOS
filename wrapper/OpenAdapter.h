//
//  OpenAdapter.h
//  connect
//
//  Created by CYTECH on 4/11/18.
//  Copyright © 2018 Tran Viet Anh. All rights reserved.
//

#import <Foundation/Foundation.h>
@class NEPacketTunnelFlow;
@class NEPacketTunnelNetworkSettings;

@protocol OpenAdapterPacketFlow;

@class OpenAdapter;
@protocol OpenAdapterDelegate <NSObject>
/**
 This method is called once the network settings to be used have been established.
 The receiver should call the completion handler once these settings have been set, returning a NEPacketTunnelFlow object for
 the TUN interface, or nil if an error occurred.
 
 @param openVPNAdapter The OpenVPNAdapter instance requesting this information.
 @param networkSettings The NEPacketTunnelNetworkSettings to be used for the tunnel.
 @param completionHandler The completion handler to be called with a NEPacketTunnelFlow object, or nil if an error occurred.
 */
- (void)openVPNAdapter:(OpenAdapter *_Nullable)openVPNAdapter
configureTunnelWithNetworkSettings:(NEPacketTunnelNetworkSettings *_Nullable)networkSettings
     completionHandler:(void (^_Nullable)(id<OpenAdapterPacketFlow> _Nullable packetFlow))completionHandler
NS_SWIFT_NAME(openVPNAdapter(_:configureTunnelWithNetworkSettings:completionHandler:));

/**
 Informs the receiver that an OpenVPN error has occurred.
 Some errors are fatal and should trigger the diconnection of the tunnel, check for fatal errors with the
 OpenVPNAdapterErrorFatalKey.
 
 @param openVPNAdapter The OpenVPNAdapter instance which encountered the error.
 @param error The error which has occurred.
 */
- (void)openVPNAdapter:(OpenAdapter *_Nullable)openVPNAdapter handleError:(NSError *_Nullable)error;
@end
@interface OpenAdapter : NSObject

/**
 The object that acts as the delegate of the adapter.
 */
@property (nonatomic, weak) id<OpenAdapterDelegate> delegate;

/**
 The session name, nil unless the tunnel is connected.
 */
@property (nonatomic, nullable, readonly) NSString *sessionName;
/**
 Applies the given configuration object.
 Call this method prior to connecting, this method has no effect after calling connect.
 
 */
/**
 Starts the tunnel.
 */
- (void)connect: (NSString *) host user:(NSString *)username pass:(NSString *) password add:(Boolean) isGP;

@end
