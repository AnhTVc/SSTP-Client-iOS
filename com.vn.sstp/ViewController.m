//
//  ViewController.m
//  com.vn.sstp
//
//  Created by Anh Viet on 04/09/2023.
//

#import "ViewController.h"
#import <NetworkExtension/NETunnelProviderManager.h>
#import <NetworkExtension/NETunnelProviderProtocol.h>
#import <NetworkExtension/NEVPNConnection.h>
@interface ViewController ()
@property (weak, nonatomic) IBOutlet UITextField *server;
@property (weak, nonatomic) IBOutlet UITextField *username;
@property (weak, nonatomic) IBOutlet UITextField *password;
@property (strong, nonatomic) IBOutlet UIButton *uibtn;
@end

@implementation ViewController{
    __block NETunnelProviderManager * vpnManager;
}
Boolean isConnect = false;
- (void)viewDidLoad {
    [super viewDidLoad];
    
    UITapGestureRecognizer *tap = [[UITapGestureRecognizer alloc] initWithTarget:self
                                                                          action:@selector(dismissKeyboard)];
    
    [self.view addGestureRecognizer:tap];
}
-(void)dismissKeyboard {
    [_username resignFirstResponder];
    [_password resignFirstResponder];
    [_server resignFirstResponder];
}
- (IBAction)btnconnect:(id)sender {
    _uibtn.enabled = NO;
    if(isConnect){
        isConnect = false;
        [vpnManager.connection stopVPNTunnel];
        [_uibtn setTitle:@"CONNECT" forState:UIControlStateNormal];
        _uibtn.enabled = YES;
    }else{
        [_uibtn setTitle:@"CONNECTING" forState:UIControlStateNormal];
        [self initVPNTunnel];
        
    }
}

- (void)initVPNTunnel{
    NSString *tunnelBundleId = @"cen.com-vn-sstp.tunnel"; // Bundle of Extension
    
    [NETunnelProviderManager loadAllFromPreferencesWithCompletionHandler:^(NSArray* newManagers, NSError *error)
     {
         if(error != nil){
             NSLog(@"Load Preferences error: %@", error);
         }else{
             if([newManagers count] > 0)
             {
                 self->vpnManager = newManagers[0];
             }else{
                 self->vpnManager = [[NETunnelProviderManager alloc] init];
             }
             
             [self->vpnManager loadFromPreferencesWithCompletionHandler:^(NSError *error){
                 if(error != nil){
                     NSLog(@"Load Preferences error: %@", error);
                 }else{
                     __block NETunnelProviderProtocol *protocol = [[NETunnelProviderProtocol alloc] init];
                     protocol.providerBundleIdentifier = tunnelBundleId;
                     // get file
                     //NSString *path = [[NSBundle mainBundle] pathForResource:@"Windscribe-US-Central-UDP" ofType:@"ovpn"];
                     //NSString* content = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:NULL];
                     NSString *user = self->_username.text;
                     NSString *pass = self->_password.text;
                     protocol.providerConfiguration = @{@"server": _server.text,
                                                        @"username": user,
                                                        @"password": pass
                                                        };
                     
                     protocol.serverAddress = self->_server.text;
                     self->vpnManager.protocolConfiguration = protocol;
                     self->vpnManager.localizedDescription = @"OpenConnect VPN";
                     
                     [self->vpnManager setEnabled:true];
                     [self->vpnManager saveToPreferencesWithCompletionHandler:^(NSError *error){
                         if (error != nil) {
                             NSLog(@"Save to Preferences Error: %@", error);
                         }else{
                             NSLog(@"Save successfully");
                             
                             [[NSNotificationCenter defaultCenter] addObserver:self
                                                                      selector:@selector(receiveNotification:)
                                                                          name:NEVPNStatusDidChangeNotification
                                                                        object:nil];
                             [self openTunnel];
                         }
                     }];
                 }}];
         }
     }];
}
- (void) receiveNotification:(NSNotification *) notification{
    NEVPNStatus status = vpnManager.connection.status;
    
    UIAlertView *alert;
    if(status == NEVPNStatusInvalid){
        NSLog(@"NEVPNStatusInvalid");
        _uibtn.enabled = YES;
        alert = [[UIAlertView alloc] initWithTitle:@"Notification"
                                           message:@"wrong username or password"
                                          delegate:self
                                 cancelButtonTitle:@"OK"
                                 otherButtonTitles:nil,nil];
        [alert show];
       // _tfButton.enabled = YES;
    }
    if(status == NEVPNStatusConnecting){
        [_uibtn setTitle:@"CONNECTING" forState:UIControlStateNormal];
        NSLog(@"NEVPNStatusConnecting");
        
    }
    if(status == NEVPNStatusReasserting){
        NSLog(@"NEVPNStatusReasserting");
        
    }
    if(status == NEVPNStatusConnected){
        NSLog(@"NEVPNStatusConnected");
        alert = [[UIAlertView alloc] initWithTitle:@"Notification"
                                           message:@"VPN Started"
                                          delegate:self
                                 cancelButtonTitle:@"OK"
                                 otherButtonTitles:nil,nil];
        //[alert show];
        isConnect = true;
        _uibtn.enabled = YES;
        //_tfButton.enabled = YES;
        [_uibtn setTitle:@"DISCONNECT" forState:UIControlStateNormal];
        //vpnManagerStatic = vpnManager;
       
    }
    if(status == NEVPNStatusDisconnected){
        NSLog(@"NEVPNStatusDisconnected");
        
        [_uibtn setTitle:@"RECONNECT" forState:UIControlStateNormal];
        _uibtn.enabled = YES;
    }
    if(status == NEVPNStatusDisconnecting){
        NSLog(@"NEVPNStatusDisconnecting");
    }
    return;
}

- (void) openTunnel{
    [vpnManager loadFromPreferencesWithCompletionHandler:^(NSError *error){
        if(error != nil){
            NSLog(@"%@", error);
        }else{
            NSError *startError = nil;
            [self->vpnManager.connection startVPNTunnelWithOptions:nil andReturnError:&startError];
            if(startError != nil){
                NSLog(@"%@", startError);
            }else{
                NSLog(@"Complete");
                [self receiveNotification:nil];
            }
        }
    }];
}

@end
