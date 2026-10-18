#import <LocalAuthentication/LocalAuthentication.h>
#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#include <stdlib.h>
#include <string.h>

#define BIOMETRIC_SUCCESS          0
#define BIOMETRIC_ERR_CANCELED     1
#define BIOMETRIC_ERR_UNAVAILABLE  2
#define BIOMETRIC_ERR_TIMEOUT      4
#define BIOMETRIC_ERR_LOCKOUT      5
#define BIOMETRIC_ERR_FAILED       6

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

int authenticate_biometrics(const char* reason, double timeoutSeconds) {
    if (timeoutSeconds <= 0.0) {
        timeoutSeconds = 120.0;
    }
    @autoreleasepool {
        LAContext *context = [[LAContext alloc] init];
        NSError *error = nil;
        NSString *nsReason = [NSString stringWithUTF8String:reason];
        
        // LAPolicyDeviceOwnerAuthentication supports Touch ID, Apple Watch, or OS password fallback
        if (![context canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:&error]) {
            return BIOMETRIC_ERR_UNAVAILABLE;
        }

        // Trigger the native Pop chime asynchronously to alert the user
        play_biometric_sound();

        dispatch_semaphore_t sema = dispatch_semaphore_create(0);
        __block int result = BIOMETRIC_ERR_FAILED;
        
        [context evaluatePolicy:LAPolicyDeviceOwnerAuthentication
                localizedReason:nsReason
                           reply:^(BOOL success, NSError *err) {
                               if (success) {
                                   result = BIOMETRIC_SUCCESS;
                               } else if (err != nil) {
                                   if (err.code == LAErrorUserCancel || err.code == LAErrorAppCancel) {
                                       result = BIOMETRIC_ERR_CANCELED;
                                   } else if (err.code == LAErrorSystemCancel) {
                                       result = BIOMETRIC_ERR_TIMEOUT;
                                   } else if (err.code == LAErrorBiometryLockout) {
                                       result = BIOMETRIC_ERR_LOCKOUT;
                                   } else if (err.code == LAErrorBiometryNotAvailable || err.code == LAErrorBiometryNotEnrolled) {
                                       result = BIOMETRIC_ERR_UNAVAILABLE;
                                   } else {
                                       result = BIOMETRIC_ERR_FAILED;
                                   }
                               }
                               dispatch_semaphore_signal(sema);
                           }];
        
        int64_t timeoutNanoseconds = (int64_t)(timeoutSeconds * NSEC_PER_SEC);
        intptr_t waitResult = dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, timeoutNanoseconds));
        if (waitResult != 0) {
            // Active timeout expired before user interacted with sensor
            [context invalidate];
            return BIOMETRIC_ERR_TIMEOUT;
        }
        return result;
    }
}
