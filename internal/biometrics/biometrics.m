#import <LocalAuthentication/LocalAuthentication.h>
#import <Foundation/Foundation.h>

int authenticate_biometrics(const char* reason) {
    @autoreleasepool {
        LAContext *context = [[LAContext alloc] init];
        NSError *error = nil;
        NSString *nsReason = [NSString stringWithUTF8String:reason];
        
        // LAPolicyDeviceOwnerAuthentication supports Touch ID, Apple Watch, or OS password fallback
        if ([context canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:&error]) {
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
