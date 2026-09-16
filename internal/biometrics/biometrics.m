#import <LocalAuthentication/LocalAuthentication.h>
#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#include <stdlib.h>
#include <string.h>

int play_biometric_sound(void) {
    const char *noSound = getenv("SEC_NO_SOUND");
    const char *testMode = getenv("SEC_TEST_MODE");
    if ((noSound != NULL && strcmp(noSound, "1") == 0) ||
        (testMode != NULL && strcmp(testMode, "1") == 0)) {
        return 0;
    }
    @autoreleasepool {
        NSSound *sound = [NSSound soundNamed:@"Pop"];
        if (sound != nil) {
            [sound play];
            return 1;
        }
    }
    return 0;
}

int authenticate_biometrics(const char* reason) {
    @autoreleasepool {
        LAContext *context = [[LAContext alloc] init];
        NSError *error = nil;
        NSString *nsReason = [NSString stringWithUTF8String:reason];
        
        // LAPolicyDeviceOwnerAuthentication supports Touch ID, Apple Watch, or OS password fallback
        if ([context canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:&error]) {
            // Trigger the native Pop chime asynchronously to alert the user
            play_biometric_sound();

            dispatch_semaphore_t sema = dispatch_semaphore_create(0);
            __block int result = 0;
            
            [context evaluatePolicy:LAPolicyDeviceOwnerAuthentication
                    localizedReason:nsReason
                              reply:^(BOOL success, NSError *error) {
                                  if (success) {
                                      result = 1;
                                  } else {
                                      result = 0;
                                  }
                                  dispatch_semaphore_signal(sema);
                              }];
            
            dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);
            return result;
        }
        return 0;
    }
}
