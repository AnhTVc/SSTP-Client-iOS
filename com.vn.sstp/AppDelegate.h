//
//  AppDelegate.h
//  com.vn.sstp
//
//  Created by Anh Viet on 04/09/2023.
//

#import <UIKit/UIKit.h>
#import <CoreData/CoreData.h>

@interface AppDelegate : UIResponder <UIApplicationDelegate>

@property (readonly, strong) NSPersistentContainer *persistentContainer;

- (void)saveContext;


@end

