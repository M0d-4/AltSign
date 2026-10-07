//
//  ALTAppleAPI+Authentication.h
//  AltSign
//
//  Created by Riley Testut on 11/16/19.
//  Copyright © 2019 Riley Testut. All rights reserved.
//

@class ALTAppleAPISession;

#import <AltSign/AltSign.h>

@class ALTAppleAPISession;

NS_ASSUME_NONNULL_BEGIN

#pragma mark - Two-Factor Authentication

/// How Apple should deliver a two-factor verification code.
typedef NS_ENUM(NSInteger, ALTTwoFactorMethod)
{
    /// Push a code to the user's other signed-in Apple devices.
    ALTTwoFactorMethodTrustedDevice = 0,
    
    /// Text a code to one of the account's trusted phone numbers.
    ALTTwoFactorMethodSMS,
    
    /// Call one of the account's trusted phone numbers and read the code out.
    ALTTwoFactorMethodVoice,
};

/// What the handler is currently being asked to do.
typedef NS_ENUM(NSInteger, ALTTwoFactorStep)
{
    /// Nothing has been sent yet: let the user pick how they want to receive a code.
    ALTTwoFactorStepSelectMethod = 0,
    
    /// A code was sent via `activeMethod`: prompt the user to enter it.
    ALTTwoFactorStepEnterCode,
};

NS_SWIFT_NAME(TrustedPhoneNumber)
@interface ALTTrustedPhoneNumber : NSObject

/// Identifier Apple uses to refer to this number ("phoneNumber.id").
@property (nonatomic, copy, readonly) NSString *identifier;

/// Masked display string, e.g. "+1 (•••) •••-••12".
@property (nonatomic, copy, readonly) NSString *displayNumber;

- (instancetype)initWithIdentifier:(NSString *)identifier displayNumber:(NSString *)displayNumber NS_DESIGNATED_INITIALIZER;
- (instancetype)init NS_UNAVAILABLE;

@end

NS_SWIFT_NAME(TwoFactorRequest)
@interface ALTTwoFactorRequest : NSObject

@property (nonatomic, readonly) ALTTwoFactorStep step;

/// The method Apple suggested (trusted device if the account has one signed in, otherwise SMS).
@property (nonatomic, readonly) ALTTwoFactorMethod preferredMethod;

/// The method the most recent code was sent with. Only meaningful for `ALTTwoFactorStepEnterCode`.
@property (nonatomic, readonly) ALTTwoFactorMethod activeMethod;

/// All trusted phone numbers on the account (may be empty, e.g. if the account has none).
@property (nonatomic, copy, readonly) NSArray<ALTTrustedPhoneNumber *> *phoneNumbers;

/// Which phone number the last SMS/voice code went to, if any.
@property (nonatomic, copy, readonly, nullable) NSString *activePhoneID;

/// Set when a previous attempt failed (e.g. wrong code), so the UI can explain why it's asking again.
@property (nonatomic, copy, readonly, nullable) NSString *errorMessage;

/// Whether the user can choose trusted device as a delivery method for this sign-in.
@property (nonatomic, readonly) BOOL supportsTrustedDevice;

@end

typedef NS_ENUM(NSInteger, ALTTwoFactorAction)
{
    ALTTwoFactorActionRequestTrustedDevice = 0,
    ALTTwoFactorActionRequestSMS,
    ALTTwoFactorActionRequestVoice,
    ALTTwoFactorActionSubmitCode,
    ALTTwoFactorActionCancel,
    ALTTwoFactorActionFail,
};

NS_SWIFT_NAME(TwoFactorResponse)
@interface ALTTwoFactorResponse : NSObject

@property (nonatomic, readonly) ALTTwoFactorAction action;
@property (nonatomic, copy, readonly, nullable) NSString *phoneID;
@property (nonatomic, copy, readonly, nullable) NSString *code;
@property (nonatomic, strong, readonly, nullable) NSError *error;

+ (instancetype)requestTrustedDevice;
+ (instancetype)requestSMSWithPhoneID:(nullable NSString *)phoneID;
+ (instancetype)requestVoiceWithPhoneID:(nullable NSString *)phoneID;
+ (instancetype)submitCode:(NSString *)code;
+ (instancetype)cancel;
+ (instancetype)failWithError:(NSError *)error;

@end

typedef void (^ALTTwoFactorHandler)(ALTTwoFactorRequest *request, void (^completionHandler)(ALTTwoFactorResponse *response))
NS_SWIFT_NAME(TwoFactorHandler);

#pragma mark - Authentication

@interface ALTAppleAPI (Authentication)

/// Signs in, supporting every verification method Apple offers: trusted-device codes, SMS and voice call
/// to any trusted phone number. `twoFactorHandler` is called (possibly several times) while 2FA is pending.
- (void)authenticateWithAppleID:(NSString *)appleID
                       password:(NSString *)password
                   anisetteData:(ALTAnisetteData *)anisetteData
               twoFactorHandler:(nullable ALTTwoFactorHandler)twoFactorHandler
              completionHandler:(void (^)(ALTAccount *_Nullable account, ALTAppleAPISession *_Nullable session, NSError *_Nullable error))completionHandler
NS_SWIFT_NAME(authenticate(appleID:password:anisetteData:twoFactorHandler:completionHandler:));

/// Legacy entry point: trusted-device codes only. Kept so existing callers continue to work.
- (void)authenticateWithAppleID:(NSString *)appleID
                       password:(NSString *)password
                   anisetteData:(ALTAnisetteData *)anisetteData
              verificationHandler:(nullable void (^)(void (^completionHandler)(NSString *_Nullable verificationCode)))verificationHandler
              completionHandler:(void (^)(ALTAccount *_Nullable account, ALTAppleAPISession *_Nullable session, NSError *_Nullable error))completionHandler
NS_SWIFT_NAME(authenticate(appleID:password:anisetteData:verificationHandler:completionHandler:));

@end

NS_ASSUME_NONNULL_END
