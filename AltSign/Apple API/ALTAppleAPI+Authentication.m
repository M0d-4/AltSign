//
//  ALTAppleAPI+Authentication.m
//  AltSign
//
//  Created by Riley Testut on 11/16/19.
//  Copyright © 2019 Riley Testut. All rights reserved.
//
//  Heavily based on sample code provided by Kabir Oberai (https://github.com/kabiroberai)
//

#import "ALTAppleAPI+Authentication.h"
#import "ALTAppleAPI_Private.h"

#import "ALTModel+Internal.h"

// Core Crypto
#import <corecrypto/ccsrp.h>
#import <corecrypto/ccdrbg.h>
#import <corecrypto/ccsrp_gp.h>
#import <corecrypto/ccdigest.h>
#import <corecrypto/ccsha2.h>
#import <corecrypto/ccpbkdf2.h>
#import <corecrypto/cchmac.h>
#import <corecrypto/ccaes.h>
#import <corecrypto/ccpad.h>

static const char ALTHexCharacters[] = "0123456789abcdef";

struct ccrng_state *ccDRBGGetRngState(void);

void ALTDigestUpdateString(const struct ccdigest_info *di_info, struct ccdigest_ctx *di_ctx, NSString *string)
{
    ccdigest_update(di_info, di_ctx, string.length, string.UTF8String);
}

void ALTDigestUpdateData(const struct ccdigest_info *di_info, struct ccdigest_ctx *di_ctx, NSData *data)
{
    uint32_t data_len = (uint32_t)data.length; // 4 bytes for length
    ccdigest_update(di_info, di_ctx, sizeof(data_len), &data_len);
    ccdigest_update(di_info, di_ctx, data_len, data.bytes);
}

NSData *ALTPBKDF2SRP(const struct ccdigest_info *di_info, BOOL isS2k, NSString *password, NSData *salt, int iterations)
{
    const struct ccdigest_info *password_di_info = ccsha256_di();
    char *digest_raw = (char *)malloc(password_di_info->output_size);
    const char *passwordUTF8 = password.UTF8String;
    ccdigest(password_di_info, strlen(passwordUTF8), passwordUTF8, digest_raw);

    size_t final_digest_len = password_di_info->output_size * (isS2k ? 1 : 2);
    char *digest = (char *)malloc(final_digest_len);

    if (isS2k)
    {
        memcpy(digest, digest_raw, final_digest_len);
    }
    else
    {
        for (int i = 0; i < password_di_info->output_size; i++)
        {
            char byte = digest_raw[i];
            digest[i * 2 + 0] = ALTHexCharacters[(byte >> 4) & 0x0F];
            digest[i * 2 + 1] = ALTHexCharacters[(byte >> 0) & 0x0F];
        }
    }

    NSMutableData *data = [NSMutableData dataWithLength:di_info->output_size];
    
    if (ccpbkdf2_hmac(di_info, final_digest_len, digest, salt.length, salt.bytes, iterations, di_info->output_size, data.mutableBytes) != 0)
    {
        return nil;
    }
    
    return data;
}

NSData *ALTCreateSessionKey(ccsrp_ctx_t srp_ctx, const char *key_name)
{
    size_t key_len;
    const void *session_key = ccsrp_get_session_key(srp_ctx, &key_len);
    
    const struct ccdigest_info *di_info = ccsha256_di();
    
    size_t hmac_len = di_info->output_size;
    unsigned char *hmac_bytes = (unsigned char *)malloc(hmac_len);
    cchmac(di_info, key_len, session_key, strlen(key_name), key_name, hmac_bytes);
    
    NSData *sessionKey = [NSData dataWithBytes:hmac_bytes length:hmac_len];
    return sessionKey;
}

NSData *ALTDecryptDataCBC(ccsrp_ctx_t srp_ctx, NSData *spd)
{
    NSData *extraDataKey = ALTCreateSessionKey(srp_ctx, "extra data key:");
    NSData *extraDataIV = ALTCreateSessionKey(srp_ctx, "extra data iv:");

    NSMutableData *decryptedData = [NSMutableData dataWithLength:spd.length];

    const struct ccmode_cbc *decrypt_mode = ccaes_cbc_decrypt_mode();
    
    cccbc_iv *iv = (cccbc_iv *)malloc(decrypt_mode->block_size);
    if (extraDataIV.bytes)
    {
        memcpy(iv, extraDataIV.bytes, decrypt_mode->block_size);
    }
    else
    {
        bzero(iv, decrypt_mode->block_size);
    }

    cccbc_ctx *ctx_buf = (cccbc_ctx *)malloc(decrypt_mode->size);
    decrypt_mode->init(decrypt_mode, ctx_buf, extraDataKey.length, extraDataKey.bytes);

    size_t length = ccpad_pkcs7_decrypt(decrypt_mode, ctx_buf, iv, spd.length, spd.bytes, decryptedData.mutableBytes);
    if (length > spd.length)
    {
        return nil;
    }

    return decryptedData;
}

NSData *ALTDecryptDataGCM(NSData *sk, NSData *encryptedData)
{
    const struct ccmode_gcm *decrypt_mode = ccaes_gcm_decrypt_mode();
    
    ccgcm_ctx *gcm_ctx = (ccgcm_ctx *)malloc(decrypt_mode->size);
    decrypt_mode->init(decrypt_mode, gcm_ctx, sk.length, sk.bytes);
    
    if (encryptedData.length < 35)
    {
        NSLog(@"ERROR: Encrypted token too short.");
        return nil;
    }
    
    if (cc_cmp_safe(3, encryptedData.bytes, "XYZ"))
    {
        NSLog(@"ERROR: Encrypted token wrong version!");
        return nil;
    }
    
    decrypt_mode->set_iv(gcm_ctx, 16, encryptedData.bytes + 3);
    decrypt_mode->gmac(gcm_ctx, 3, encryptedData.bytes);

    size_t decrypted_len = encryptedData.length - 35;
    NSMutableData *decryptedData = [NSMutableData dataWithLength:decrypted_len];
    
    decrypt_mode->gcm(gcm_ctx, decrypted_len, encryptedData.bytes + 16 + 3, decryptedData.mutableBytes);

    char tag[16];
    decrypt_mode->finalize(gcm_ctx, 16, tag);
    
    if (cc_cmp_safe(16, encryptedData.bytes + decrypted_len + 19, tag))
    {
        NSLog(@"Invalid tag version");
        return nil;
    }

    return decryptedData;
}

NSData *ALTCreateAppTokensChecksum(NSData *sk, NSString *adsid, NSArray<NSString *> *apps)
{
    const struct ccdigest_info *di_info = ccsha256_di();
    size_t hmac_size = cchmac_di_size(di_info);
    struct cchmac_ctx *hmac_ctx = (struct cchmac_ctx *)malloc(hmac_size);
    cchmac_init(di_info, hmac_ctx, sk.length, sk.bytes);

    const char *key = "apptokens";
    cchmac_update(di_info, hmac_ctx, strlen(key), key);

    const char *adsidUTF8 = adsid.UTF8String;
    cchmac_update(di_info, hmac_ctx, strlen(adsidUTF8), adsidUTF8);

    for (NSString *app in apps)
    {
        cchmac_update(di_info, hmac_ctx, app.length, app.UTF8String);
    }
    
    NSMutableData *checksum = [NSMutableData dataWithLength:di_info->output_size];
    cchmac_final(di_info, hmac_ctx, checksum.mutableBytes);

    return checksum;
}

#pragma mark - Two-Factor Models

@implementation ALTTrustedPhoneNumber

- (instancetype)initWithIdentifier:(NSString *)identifier displayNumber:(NSString *)displayNumber
{
    self = [super init];
    if (self)
    {
        _identifier = [identifier copy];
        _displayNumber = [displayNumber copy];
    }
    
    return self;
}

- (NSString *)description
{
    return [NSString stringWithFormat:@"<ALTTrustedPhoneNumber %@: %@>", self.identifier, self.displayNumber];
}

@end

@interface ALTTwoFactorRequest ()

@property (nonatomic, readwrite) ALTTwoFactorStep step;
@property (nonatomic, readwrite) ALTTwoFactorMethod preferredMethod;
@property (nonatomic, readwrite) ALTTwoFactorMethod activeMethod;
@property (nonatomic, copy, readwrite) NSArray<ALTTrustedPhoneNumber *> *phoneNumbers;
@property (nonatomic, copy, readwrite, nullable) NSString *activePhoneID;
@property (nonatomic, copy, readwrite, nullable) NSString *errorMessage;
@property (nonatomic, readwrite) BOOL supportsTrustedDevice;

@end

@implementation ALTTwoFactorRequest

- (NSString *)description
{
    return [NSString stringWithFormat:@"<ALTTwoFactorRequest step: %@ active: %@ phones: %@ error: %@>", @(self.step), @(self.activeMethod), self.phoneNumbers, self.errorMessage];
}

@end

@interface ALTTwoFactorResponse ()

@property (nonatomic, readwrite) ALTTwoFactorAction action;
@property (nonatomic, copy, readwrite, nullable) NSString *phoneID;
@property (nonatomic, copy, readwrite, nullable) NSString *code;
@property (nonatomic, strong, readwrite, nullable) NSError *error;

@end

@implementation ALTTwoFactorResponse

+ (instancetype)responseWithAction:(ALTTwoFactorAction)action
{
    ALTTwoFactorResponse *response = [[ALTTwoFactorResponse alloc] init];
    response.action = action;
    return response;
}

+ (instancetype)requestTrustedDevice
{
    return [self responseWithAction:ALTTwoFactorActionRequestTrustedDevice];
}

+ (instancetype)requestSMSWithPhoneID:(NSString *)phoneID
{
    ALTTwoFactorResponse *response = [self responseWithAction:ALTTwoFactorActionRequestSMS];
    response.phoneID = phoneID;
    return response;
}

+ (instancetype)requestVoiceWithPhoneID:(NSString *)phoneID
{
    ALTTwoFactorResponse *response = [self responseWithAction:ALTTwoFactorActionRequestVoice];
    response.phoneID = phoneID;
    return response;
}

+ (instancetype)submitCode:(NSString *)code
{
    ALTTwoFactorResponse *response = [self responseWithAction:ALTTwoFactorActionSubmitCode];
    response.code = code;
    return response;
}

+ (instancetype)cancel
{
    return [self responseWithAction:ALTTwoFactorActionCancel];
}

+ (instancetype)failWithError:(NSError *)error
{
    ALTTwoFactorResponse *response = [self responseWithAction:ALTTwoFactorActionFail];
    response.error = error;
    return response;
}

@end

/// Mutable bookkeeping for one in-flight two-factor sign-in.
@interface ALTTwoFactorState : NSObject

@property (nonatomic, copy) NSString *dsid;
@property (nonatomic, copy) NSString *idmsToken;
@property (nonatomic, strong) ALTAnisetteData *anisetteData;
@property (nonatomic, strong) NSMutableArray<ALTTrustedPhoneNumber *> *phoneNumbers;
@property (nonatomic) ALTTwoFactorMethod preferredMethod;
@property (nonatomic) BOOL supportsTrustedDevice;

@property (nonatomic) ALTTwoFactorMethod activeMethod;
@property (nonatomic, copy, nullable) NSString *activePhoneID;
@property (nonatomic) BOOL hasActiveMethod;

@end

@implementation ALTTwoFactorState
@end

@implementation ALTAppleAPI (Authentication)

#pragma mark - Legacy entry point

- (void)authenticateWithAppleID:(NSString *)appleID
                       password:(NSString *)password
                   anisetteData:(ALTAnisetteData *)anisetteData
            verificationHandler:(void (^)(void (^ _Nonnull)(NSString * _Nullable)))verificationHandler
              completionHandler:(void (^)(ALTAccount * _Nullable, ALTAppleAPISession * _Nullable, NSError * _Nullable))completionHandler
{
    ALTTwoFactorHandler twoFactorHandler = nil;
    
    if (verificationHandler != nil)
    {
        // Old callers only understand "enter the code sent to your devices", so adapt that onto the
        // multi-method flow: always use a trusted device, ask for the code once, and don't retry.
        twoFactorHandler = ^(ALTTwoFactorRequest *request, void (^completion)(ALTTwoFactorResponse *response)) {
            if (request.errorMessage != nil)
            {
                NSError *error = [NSError errorWithDomain:ALTAppleAPIErrorDomain code:ALTAppleAPIErrorIncorrectVerificationCode userInfo:nil];
                completion([ALTTwoFactorResponse failWithError:error]);
                return;
            }
            
            switch (request.step)
            {
                case ALTTwoFactorStepSelectMethod:
                    completion([ALTTwoFactorResponse requestTrustedDevice]);
                    break;
                    
                case ALTTwoFactorStepEnterCode:
                    verificationHandler(^(NSString *_Nullable verificationCode) {
                        if (verificationCode == nil)
                        {
                            NSError *error = [NSError errorWithDomain:ALTAppleAPIErrorDomain code:ALTAppleAPIErrorRequiresTwoFactorAuthentication userInfo:nil];
                            completion([ALTTwoFactorResponse failWithError:error]);
                        }
                        else
                        {
                            completion([ALTTwoFactorResponse submitCode:verificationCode]);
                        }
                    });
                    break;
            }
        };
    }
    
    [self authenticateWithAppleID:appleID password:password anisetteData:anisetteData twoFactorHandler:twoFactorHandler completionHandler:completionHandler];
}

#pragma mark - Authentication

- (void)authenticateWithAppleID:(NSString *)appleID
                       password:(NSString *)password
                   anisetteData:(ALTAnisetteData *)anisetteData
               twoFactorHandler:(ALTTwoFactorHandler)twoFactorHandler
              completionHandler:(void (^)(ALTAccount * _Nullable, ALTAppleAPISession * _Nullable, NSError * _Nullable))completionHandler
{
    NSMutableDictionary *clientDictionary = [@{
        @"bootstrap": @YES,
        @"icscrec": @YES,
        @"loc": NSLocale.currentLocale.localeIdentifier,
        @"pbe": @NO,
        @"prkgen": @YES,
        @"svct": @"iCloud",
        @"X-Apple-I-Client-Time": [self.dateFormatter stringFromDate:anisetteData.date],
        @"X-Apple-Locale": NSLocale.currentLocale.localeIdentifier,
        @"X-Apple-I-TimeZone": NSTimeZone.localTimeZone.abbreviation,
        @"X-Apple-I-MD": anisetteData.oneTimePassword,
        @"X-Apple-I-MD-LU": anisetteData.localUserID,
        @"X-Apple-I-MD-M": anisetteData.machineID,
        @"X-Apple-I-MD-RINFO": @(anisetteData.routingInfo),
        @"X-Mme-Device-Id": anisetteData.deviceUniqueIdentifier,
        @"X-Apple-I-SRL-NO": anisetteData.deviceSerialNumber,
    } mutableCopy];
    
    /* Begin CoreCrypto Logic */
    ccsrp_const_gp_t gp = ccsrp_gp_rfc5054_2048();
    
    const struct ccdigest_info *di_info = ccsha256_di();
    struct ccdigest_ctx *di_ctx = (struct ccdigest_ctx *)malloc(ccdigest_di_size(di_info));
    ccdigest_init(di_info, di_ctx);
    
    const struct ccdigest_info *srp_di = ccsha256_di();
    struct ccsrp_ctx *srp_ctx = (struct ccsrp_ctx *)malloc(ccsrp_sizeof_srp(di_info, gp));
    ccsrp_ctx_init(srp_ctx, srp_di, gp);
    ccsrp_client_set_noUsernameInX(srp_ctx, true);
    SRP_RNG(srp_ctx) = ccrng(NULL);
    
    NSArray<NSString *> *ps = @[@"s2k", @"s2k_fo"];
    ALTDigestUpdateString(di_info, di_ctx, ps[0]);
    ALTDigestUpdateString(di_info, di_ctx, @",");
    ALTDigestUpdateString(di_info, di_ctx, ps[1]);
    
    size_t A_size = ccsrp_exchange_size(srp_ctx);
    char *A_bytes = (char *)malloc(A_size);
    ccsrp_client_start_authentication(srp_ctx, ccDRBGGetRngState(), A_bytes);
    
    NSData *A_data = [NSData dataWithBytes:A_bytes length:A_size];
    
    ALTDigestUpdateString(di_info, di_ctx, @"|");
    
    NSDictionary *parameters = @{
        @"A2k": A_data,
        @"ps": ps,
        @"cpd": clientDictionary,
        @"u": appleID,
        @"o": @"init"
    };
    
    // 1st Request
    [self sendAuthenticationRequestWithParameters:parameters anisetteData:anisetteData completionHandler:^(NSDictionary *responseDictionary, NSError *requestError) {
        if (responseDictionary == nil)
        {
            completionHandler(nil, nil, requestError);
            return;
        }
        
        size_t M_size = ccsrp_get_session_key_length(srp_ctx);
        char *M_bytes = (char *)malloc(A_size);
        NSData *M_data = [NSData dataWithBytes:M_bytes length:M_size];
        
        NSString *sp = responseDictionary[@"sp"];
        BOOL isS2K = [sp isEqualToString:@"s2k"];
        
        ALTDigestUpdateString(di_info, di_ctx, @"|");
        
        if (sp)
        {
            ALTDigestUpdateString(di_info, di_ctx, sp);
        }

        NSString *c = responseDictionary[@"c"];
        NSData *salt = responseDictionary[@"s"];
        NSNumber *iterations = responseDictionary[@"i"];
        NSData *B_data = responseDictionary[@"B"];
        
        if (c == nil || salt == nil || iterations == nil || B_data == nil)
        {
            completionHandler(nil, nil, [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorBadServerResponse userInfo:nil]);
            return;
        }
        
        NSData *passwordKey = ALTPBKDF2SRP(di_info, isS2K, password, salt, [iterations intValue]);
        if (passwordKey == nil)
        {
            completionHandler(nil, nil, [NSError errorWithDomain:ALTAppleAPIErrorDomain code:ALTAppleAPIErrorAuthenticationHandshakeFailed userInfo:nil]);
            return;
        }
        
        int result = ccsrp_client_process_challenge(srp_ctx, appleID.UTF8String, passwordKey.length, passwordKey.bytes,
                                                    salt.length, salt.bytes, B_data.bytes, (void *)M_data.bytes);
        if (result != 0)
        {
            completionHandler(nil, nil, [NSError errorWithDomain:ALTAppleAPIErrorDomain code:ALTAppleAPIErrorAuthenticationHandshakeFailed userInfo:nil]);
            return;
        }
        
        NSDictionary *parameters = @{
            @"c": c,
            @"M1": M_data,
            @"cpd": clientDictionary,
            @"u": appleID,
            @"o": @"complete"
        };
        
        // 2nd Request
        [self sendAuthenticationRequestWithParameters:parameters anisetteData:anisetteData completionHandler:^(NSDictionary *responseDictionary, NSError *requestError) {
            if (responseDictionary == nil)
            {
                completionHandler(nil, nil, requestError);
                return;
            }
            
            NSData *M2_data = responseDictionary[@"M2"];
            if (M2_data == nil)
            {
                NSLog(@"ERROR: M2 data not found!");
                
                completionHandler(nil, nil,  [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorBadServerResponse userInfo:nil]);
                return;
            }
            
            if (!ccsrp_client_verify_session(srp_ctx, M2_data.bytes))
            {
                NSLog(@"ERROR: Failed to verify session.");
                
                completionHandler(nil, nil, [NSError errorWithDomain:ALTAppleAPIErrorDomain code:ALTAppleAPIErrorAuthenticationHandshakeFailed userInfo:nil]);
                return;
            }

            ALTDigestUpdateString(di_info, di_ctx, @"|");
            
            NSData *spd = responseDictionary[@"spd"];
            if (spd)
            {
                ALTDigestUpdateData(di_info, di_ctx, spd);
            }
            
            ALTDigestUpdateString(di_info, di_ctx, @"|");
            
            NSData *sc = responseDictionary[@"sc"];
            if (sc)
            {
                ALTDigestUpdateData(di_info, di_ctx, sc);
            }
            
            ALTDigestUpdateString(di_info, di_ctx, @"|");
            
            NSData *np = responseDictionary[@"np"];
            if (np == nil)
            {
                NSLog(@"ERROR: Missing np dictionary.");
                
                completionHandler(nil, nil, [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorBadServerResponse userInfo:nil]);
                return;
            }
            
            size_t digest_len = di_info->output_size;
            if (np.length != digest_len)
            {
                NSLog(@"ERROR: Neg proto hash is too short.");
                
                completionHandler(nil, nil, [NSError errorWithDomain:ALTAppleAPIErrorDomain code:ALTAppleAPIErrorAuthenticationHandshakeFailed userInfo:nil]);
                return;
            }
            
            unsigned char *digest = (unsigned char *)malloc(digest_len);
            di_info->final(di_info, di_ctx, digest);

            NSData *hmacKey = ALTCreateSessionKey(srp_ctx, "HMAC key:");
            unsigned char *hmac_out = (unsigned char *)malloc(digest_len);
            cchmac(di_info, hmacKey.length, hmacKey.bytes, digest_len, digest, hmac_out);
            
            if (cc_cmp_safe(digest_len, hmac_out, np.bytes))
            {
                NSLog(@"ERROR: Invalid neg prot hmac.");
                
                completionHandler(nil, nil, [NSError errorWithDomain:ALTAppleAPIErrorDomain code:ALTAppleAPIErrorAuthenticationHandshakeFailed userInfo:nil]);
                return;
            }
            
            NSData *decryptedData = ALTDecryptDataCBC(srp_ctx, spd);
            if (decryptedData == nil)
            {
                NSLog(@"ERROR: Could not decrypt login response.");
                
                completionHandler(nil, nil, [NSError errorWithDomain:ALTAppleAPIErrorDomain code:ALTAppleAPIErrorAuthenticationHandshakeFailed userInfo:nil]);
                return;
            }
            
            NSError *parseError = nil;
            NSDictionary *decryptedDictionary = [NSPropertyListSerialization propertyListWithData:decryptedData options:0 format:nil error:&parseError];
            if (decryptedDictionary == nil)
            {
                NSLog(@"ERROR: Could not parse decrypted login response plist!");
                
                completionHandler(nil, nil, parseError);
                return;
            }
                        
            NSString *adsid = decryptedDictionary[@"adsid"];
            NSString *idmsToken = decryptedDictionary[@"GsIdmsToken"];
            
            if (adsid == nil || idmsToken == nil)
            {
                NSLog(@"ERROR: adsid and/or idmsToken is nil. adsid: %@. idmsToken: %@", adsid, idmsToken);
                
                completionHandler(nil, nil, [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorBadServerResponse userInfo:nil]);
                return;
            }
            
            NSDictionary *statusDictionary = responseDictionary[@"Status"];
            
            NSString *authType = statusDictionary[@"au"];
            if ([self isTwoFactorAuthType:authType])
            {
                // Handle Two-Factor
                
                if (twoFactorHandler != nil)
                {
                    BOOL isTrustedDevice = ([authType isEqualToString:@"trustedDeviceSecondaryAuth"] || [authType isEqualToString:@"trustedDevice"]);
                    
                    NSMutableArray<ALTTrustedPhoneNumber *> *phoneNumbers = [[self parseTrustedPhoneNumbersFromDictionary:responseDictionary] mutableCopy];
                    if (phoneNumbers.count == 0)
                    {
                        [phoneNumbers addObjectsFromArray:[self parseTrustedPhoneNumbersFromDictionary:statusDictionary]];
                    }
                    
                    ALTTwoFactorState *state = [[ALTTwoFactorState alloc] init];
                    state.dsid = adsid;
                    state.idmsToken = idmsToken;
                    state.anisetteData = anisetteData;
                    state.phoneNumbers = phoneNumbers;
                    state.preferredMethod = isTrustedDevice ? ALTTwoFactorMethodTrustedDevice : ALTTwoFactorMethodSMS;
                    state.supportsTrustedDevice = isTrustedDevice;
                    
                    [self performTwoFactorWithState:state handler:twoFactorHandler completionHandler:^(BOOL success, NSError *error) {
                        if (success)
                        {
                            // We've successfully signed-in with two-factor, so restart authentication (which will now succeed).
                            [self authenticateWithAppleID:appleID password:password anisetteData:anisetteData twoFactorHandler:twoFactorHandler completionHandler:completionHandler];
                        }
                        else
                        {
                            completionHandler(nil, nil, error);
                        }
                    }];
                }
                else
                {
                    completionHandler(nil, nil, [NSError errorWithDomain:ALTAppleAPIErrorDomain code:ALTAppleAPIErrorRequiresTwoFactorAuthentication userInfo:nil]);
                }
            }
            else
            {
                // Fetch Auth Token
                
                NSData *sk = decryptedDictionary[@"sk"];
                NSData *c = decryptedDictionary[@"c"];
                
                if (sk == nil || c == nil)
                {
                    NSLog(@"ERROR: No ak and/or c data.");
                    
                    completionHandler(nil, nil, [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorBadServerResponse userInfo:nil]);
                    return;
                }
                
                NSArray *apps = @[@"com.apple.gs.xcode.auth"];
                NSData *checksum = ALTCreateAppTokensChecksum(sk, adsid, apps);
                
                NSDictionary *parameters = @{
                    @"u": adsid,
                    @"app": apps,
                    @"c": c,
                    @"t": idmsToken,
                    @"checksum": checksum,
                    @"cpd": clientDictionary,
                    @"o": @"apptokens"
                };
                
                [self fetchAuthTokenWithParameters:parameters sk:sk anisetteData:anisetteData completionHandler:^(NSString *authToken, NSError *error) {
                    if (authToken == nil)
                    {
                        completionHandler(nil, nil, error);
                        return;
                    }
                    
                    ALTAppleAPISession *session = [[ALTAppleAPISession alloc] initWithDSID:adsid authToken:authToken anisetteData:anisetteData];
                    [self fetchAccountForSession:session completionHandler:^(ALTAccount *account, NSError *error) {
                        if (account == nil)
                        {
                            completionHandler(nil, nil, error);
                        }
                        else
                        {
                            completionHandler(account, session, nil);
                        }
                    }];
                }];
            }
        }];
    }];
}

- (void)fetchAuthTokenWithParameters:(NSDictionary *)parameters sk:(NSData *)sk anisetteData:(ALTAnisetteData *)anisetteData completionHandler:(void (^)(NSString *authToken, NSError *error))completionHandler
{
    [self sendAuthenticationRequestWithParameters:parameters anisetteData:anisetteData completionHandler:^(NSDictionary *responseDictionary, NSError *requestError) {
        if (responseDictionary == nil)
        {
            completionHandler(nil, requestError);
            return;
        }
        
        NSData *encryptedToken = responseDictionary[@"et"];
        NSData *decryptedToken = ALTDecryptDataGCM(sk, encryptedToken);
        
        if (decryptedToken == nil)
        {
            NSLog(@"ERROR: Failed to decrypt apptoken.");
            
            completionHandler(nil, [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorBadServerResponse userInfo:nil]);
            return;
        }
        
        NSError *parseError = nil;
        NSDictionary *decryptedTokenDictionary = [NSPropertyListSerialization propertyListWithData:decryptedToken options:0 format:nil error:&parseError];
        if (decryptedTokenDictionary == nil)
        {
            NSLog(@"ERROR: Could not parse decrypted apptoken plist.");
            
            completionHandler(nil, parseError);
            return;
        }
                
        NSString *app = [parameters[@"app"] firstObject];
        
        NSDictionary *tokenDictionary = decryptedTokenDictionary[@"t"][app];
        NSString *token = tokenDictionary[@"token"];
        NSNumber *expirationDataMS = tokenDictionary[@"expiry"];
        
        if (token == nil)
        {
            completionHandler(nil, [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorBadServerResponse userInfo:nil]);
            return;
        }
        
        NSDate *expirationDate = [NSDate dateWithTimeIntervalSince1970:(double)expirationDataMS.integerValue / 1000];
        NSLog(@"Got token for %@!\nExpires: %@\nValue: %@\n", app, expirationDate, token);
        
        completionHandler(token, nil);
    }];
}

#pragma mark - Two-Factor Flow

- (BOOL)isTwoFactorAuthType:(NSString *)authType
{
    if (![authType isKindOfClass:[NSString class]])
    {
        return NO;
    }
    
    static NSSet<NSString *> *types = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        types = [NSSet setWithArray:@[@"trustedDeviceSecondaryAuth", @"trustedDevice", @"secondaryAuth", @"sms", @"voice", @"phone"]];
    });
    
    return [types containsObject:authType];
}

/// Drives the whole 2FA exchange: asks the handler what to do, performs it, and loops until the code is
/// accepted, the user cancels, or something unrecoverable happens.
- (void)performTwoFactorWithState:(ALTTwoFactorState *)state
                          handler:(ALTTwoFactorHandler)handler
                completionHandler:(void (^)(BOOL success, NSError *_Nullable error))completionHandler
{
    __block void (^prompt)(ALTTwoFactorStep, NSString *) = nil;
    __block BOOL finished = NO;
    
    void (^finish)(BOOL, NSError *) = ^(BOOL success, NSError *error) {
        if (finished)
        {
            return;
        }
        
        finished = YES;
        prompt = nil; // Break the retain cycle.
        completionHandler(success, error);
    };
    
    prompt = ^(ALTTwoFactorStep step, NSString *errorMessage) {
        ALTTwoFactorRequest *request = [[ALTTwoFactorRequest alloc] init];
        request.step = step;
        request.preferredMethod = state.preferredMethod;
        request.activeMethod = state.activeMethod;
        request.phoneNumbers = [state.phoneNumbers copy];
        request.activePhoneID = state.activePhoneID;
        request.errorMessage = errorMessage;
        request.supportsTrustedDevice = state.supportsTrustedDevice;
        
        handler(request, ^(ALTTwoFactorResponse *response) {
            switch (response.action)
            {
                case ALTTwoFactorActionCancel:
                    finish(NO, [NSError errorWithDomain:ALTAppleAPIErrorDomain code:ALTAppleAPIErrorVerificationCancelled userInfo:nil]);
                    break;
                    
                case ALTTwoFactorActionFail:
                    finish(NO, response.error ?: [NSError errorWithDomain:ALTAppleAPIErrorDomain code:ALTAppleAPIErrorVerificationFailed userInfo:nil]);
                    break;
                    
                case ALTTwoFactorActionRequestTrustedDevice:
                    [self sendTrustedDeviceCodeRequestWithState:state completionHandler:^(NSError *error) {
                        if (error != nil)
                        {
                            // Let the user pick another way to receive a code instead of failing the whole sign-in.
                            prompt(ALTTwoFactorStepSelectMethod, error.localizedDescription);
                            return;
                        }
                        
                        state.activeMethod = ALTTwoFactorMethodTrustedDevice;
                        state.activePhoneID = nil;
                        state.hasActiveMethod = YES;
                        prompt(ALTTwoFactorStepEnterCode, nil);
                    }];
                    break;
                    
                case ALTTwoFactorActionRequestSMS:
                case ALTTwoFactorActionRequestVoice:
                {
                    ALTTwoFactorMethod method = (response.action == ALTTwoFactorActionRequestSMS) ? ALTTwoFactorMethodSMS : ALTTwoFactorMethodVoice;
                    
                    [self sendPhoneCodeRequestWithMethod:method phoneID:response.phoneID state:state completionHandler:^(NSString *phoneID, NSError *error) {
                        if (error != nil)
                        {
                            prompt(ALTTwoFactorStepSelectMethod, error.localizedDescription);
                            return;
                        }
                        
                        state.activeMethod = method;
                        state.activePhoneID = phoneID;
                        state.hasActiveMethod = YES;
                        prompt(ALTTwoFactorStepEnterCode, nil);
                    }];
                    break;
                }
                    
                case ALTTwoFactorActionSubmitCode:
                {
                    if (!state.hasActiveMethod)
                    {
                        // The handler skipped choosing a delivery method, so there's nothing to verify against.
                        prompt(ALTTwoFactorStepSelectMethod, nil);
                        break;
                    }
                    
                    NSString *code = [response.code stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
                    if (code.length == 0)
                    {
                        prompt(ALTTwoFactorStepEnterCode, nil);
                        break;
                    }
                    
                    [self validateTwoFactorCode:code state:state completionHandler:^(BOOL success, NSString *retryMessage, NSError *error) {
                        if (success)
                        {
                            finish(YES, nil);
                        }
                        else if (retryMessage != nil)
                        {
                            prompt(ALTTwoFactorStepEnterCode, retryMessage);
                        }
                        else
                        {
                            finish(NO, error);
                        }
                    }];
                    break;
                }
            }
        });
    };
    
    prompt(ALTTwoFactorStepSelectMethod, nil);
}

#pragma mark Requests

- (NSDictionary<NSString *, NSString *> *)twoFactorHeadersWithState:(ALTTwoFactorState *)state
{
    ALTAnisetteData *anisetteData = state.anisetteData;
    
    NSString *identityToken = [NSString stringWithFormat:@"%@:%@", state.dsid, state.idmsToken];
    NSString *encodedIdentityToken = [[identityToken dataUsingEncoding:NSUTF8StringEncoding] base64EncodedStringWithOptions:0];
    
    return @{
        @"Content-Type": @"text/x-xml-plist",
        @"User-Agent": @"Xcode",
        @"Accept": @"text/x-xml-plist",
        @"Accept-Language": @"en-us",
        @"X-Apple-App-Info": @"com.apple.gs.xcode.auth",
        @"X-Xcode-Version": @"11.2 (11B41)",
        @"X-Apple-Identity-Token": encodedIdentityToken,
        @"X-Apple-I-MD-M": anisetteData.machineID,
        @"X-Apple-I-MD": anisetteData.oneTimePassword,
        @"X-Apple-I-MD-LU": anisetteData.localUserID,
        @"X-Apple-I-MD-RINFO": [@(anisetteData.routingInfo) description],
        @"X-Mme-Device-Id": anisetteData.deviceUniqueIdentifier,
        @"X-MMe-Client-Info": anisetteData.deviceDescription,
        @"X-Apple-I-Client-Time": [self.dateFormatter stringFromDate:anisetteData.date],
        @"X-Apple-Locale": anisetteData.locale.localeIdentifier,
        @"X-Apple-I-TimeZone": anisetteData.timeZone.abbreviation,
        @"X-Apple-I-SRL-NO": anisetteData.deviceSerialNumber ?: @"",
    };
}

/// The phone endpoints answer with Apple's "buddyml" UI markup, so they need a slightly different Accept/Content-Type.
- (NSMutableURLRequest *)phoneRequestWithURL:(NSURL *)URL state:(ALTTwoFactorState *)state
{
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:URL];
    
    [[self twoFactorHeadersWithState:state] enumerateKeysAndObjectsUsingBlock:^(NSString *key, NSString *value, BOOL *stop) {
        [request setValue:value forHTTPHeaderField:key];
    }];
    
    [request setValue:@"application/x-buddyml" forHTTPHeaderField:@"Accept"];
    [request setValue:@"application/x-plist" forHTTPHeaderField:@"Content-Type"];
    [request setValue:@"close" forHTTPHeaderField:@"Connection"];
    
    return request;
}

- (void)sendTrustedDeviceCodeRequestWithState:(ALTTwoFactorState *)state completionHandler:(void (^)(NSError *_Nullable error))completionHandler
{
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:@"https://gsa.apple.com/auth/verify/trusteddevice"]];
    
    [[self twoFactorHeadersWithState:state] enumerateKeysAndObjectsUsingBlock:^(NSString *key, NSString *value, BOOL *stop) {
        [request setValue:value forHTTPHeaderField:key];
    }];
    
    NSURLSessionDataTask *task = [self.session dataTaskWithRequest:request completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        if (data == nil || error != nil)
        {
            completionHandler(error ?: [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorBadServerResponse userInfo:nil]);
            return;
        }
        
        NSInteger statusCode = [(NSHTTPURLResponse *)response isKindOfClass:[NSHTTPURLResponse class]] ? [(NSHTTPURLResponse *)response statusCode] : 0;
        
        NSError *alertError = [self errorForXMLUIAlertInData:data];
        if (alertError != nil)
        {
            completionHandler(alertError);
            return;
        }
        
        if (statusCode != 200)
        {
            NSString *message = [NSString stringWithFormat:NSLocalizedString(@"Couldn't send a code to your devices (HTTP %@).", @""), @(statusCode)];
            completionHandler([NSError errorWithDomain:ALTAppleAPIErrorDomain code:ALTAppleAPIErrorVerificationFailed userInfo:@{NSLocalizedDescriptionKey: message}]);
            return;
        }
        
        completionHandler(nil);
    }];
    
    [task resume];
}

- (void)sendPhoneCodeRequestWithMethod:(ALTTwoFactorMethod)method
                               phoneID:(NSString *)requestedPhoneID
                                 state:(ALTTwoFactorState *)state
                     completionHandler:(void (^)(NSString *_Nullable phoneID, NSError *_Nullable error))completionHandler
{
    NSString *mode = (method == ALTTwoFactorMethodVoice) ? @"voice" : @"sms";
    
    NSString *phoneID = [requestedPhoneID stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    if (phoneID.length == 0)
    {
        // Apple's primary trusted number.
        phoneID = state.phoneNumbers.firstObject.identifier ?: @"1";
    }
    
    NSString *URLString = [NSString stringWithFormat:@"https://gsa.apple.com/auth/verify/phone/put?mode=%@", mode];
    NSMutableURLRequest *request = [self phoneRequestWithURL:[NSURL URLWithString:URLString] state:state];
    request.HTTPMethod = @"POST";
    
    NSDictionary *body = @{@"serverInfo": @{@"mode": mode, @"phoneNumber.id": phoneID}};
    request.HTTPBody = [NSPropertyListSerialization dataWithPropertyList:body format:NSPropertyListXMLFormat_v1_0 options:0 error:nil];
    
    NSURLSessionDataTask *task = [self.session dataTaskWithRequest:request completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        if (data == nil || error != nil)
        {
            completionHandler(nil, error ?: [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorBadServerResponse userInfo:nil]);
            return;
        }
        
        NSInteger statusCode = [(NSHTTPURLResponse *)response isKindOfClass:[NSHTTPURLResponse class]] ? [(NSHTTPURLResponse *)response statusCode] : 0;
        
        NSError *alertError = [self errorForXMLUIAlertInData:data];
        if (alertError != nil)
        {
            completionHandler(nil, alertError);
            return;
        }
        
        NSDictionary *responseDictionary = [self propertyListOrJSONFromData:data];
        NSInteger errorCode = [responseDictionary[@"ec"] integerValue];
        
        if ([self isRateLimitErrorCode:errorCode statusCode:statusCode])
        {
            completionHandler(nil, [self rateLimitErrorWithMessage:responseDictionary[@"em"]]);
            return;
        }
        
        if (errorCode != 0)
        {
            NSString *message = responseDictionary[@"em"] ?: [NSString stringWithFormat:NSLocalizedString(@"Couldn't send a code (%@).", @""), @(errorCode)];
            completionHandler(nil, [NSError errorWithDomain:ALTAppleAPIErrorDomain code:ALTAppleAPIErrorVerificationFailed userInfo:@{NSLocalizedDescriptionKey: message}]);
            return;
        }
        
        if (statusCode != 200)
        {
            NSString *message = [NSString stringWithFormat:NSLocalizedString(@"Couldn't send a code (HTTP %@).", @""), @(statusCode)];
            completionHandler(nil, [NSError errorWithDomain:ALTAppleAPIErrorDomain code:ALTAppleAPIErrorVerificationFailed userInfo:@{NSLocalizedDescriptionKey: message}]);
            return;
        }
        
        // Apple echoes back the phone it actually used, and often a masked version of the number.
        NSString *string = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        NSString *usedPhoneID = [self firstMatchForPattern:@"(?<=phoneNumber\\.id=\")[^\"]+" inString:string] ?: phoneID;
        
        NSString *obfuscated = [self firstMatchForPattern:@"(?<=obfuscatedNumber=\")[^\"]+" inString:string]
            ?: [self firstMatchForPattern:@"(?<=numberWithDialCode=\")[^\"]+" inString:string];
        
        if (obfuscated != nil && ![state.phoneNumbers filteredArrayUsingPredicate:[NSPredicate predicateWithFormat:@"identifier == %@", usedPhoneID]].count)
        {
            [state.phoneNumbers addObject:[[ALTTrustedPhoneNumber alloc] initWithIdentifier:usedPhoneID displayNumber:obfuscated]];
        }
        
        completionHandler(usedPhoneID, nil);
    }];
    
    [task resume];
}

- (void)validateTwoFactorCode:(NSString *)code
                        state:(ALTTwoFactorState *)state
            completionHandler:(void (^)(BOOL success, NSString *_Nullable retryMessage, NSError *_Nullable error))completionHandler
{
    BOOL isTrustedDevice = (state.activeMethod == ALTTwoFactorMethodTrustedDevice);
    
    NSMutableURLRequest *request = nil;
    if (isTrustedDevice)
    {
        request = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:@"https://gsa.apple.com/grandslam/GsService2/validate"]];
        
        [[self twoFactorHeadersWithState:state] enumerateKeysAndObjectsUsingBlock:^(NSString *key, NSString *value, BOOL *stop) {
            [request setValue:value forHTTPHeaderField:key];
        }];
        [request setValue:code forHTTPHeaderField:@"security-code"];
    }
    else
    {
        NSString *mode = (state.activeMethod == ALTTwoFactorMethodVoice) ? @"voice" : @"sms";
        NSString *phoneID = state.activePhoneID ?: (state.phoneNumbers.firstObject.identifier ?: @"1");
        
        request = [self phoneRequestWithURL:[NSURL URLWithString:@"https://gsa.apple.com/auth/verify/phone/securitycode?referrer=/auth/verify/phone/put"] state:state];
        request.HTTPMethod = @"POST";
        
        NSDictionary *body = @{
            @"securityCode": @{@"code": code},
            @"serverInfo": @{@"mode": mode, @"phoneNumber.id": phoneID},
        };
        request.HTTPBody = [NSPropertyListSerialization dataWithPropertyList:body format:NSPropertyListXMLFormat_v1_0 options:0 error:nil];
    }
    
    NSURLSessionDataTask *task = [self.session dataTaskWithRequest:request completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        if (data == nil || error != nil)
        {
            completionHandler(NO, nil, error ?: [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorBadServerResponse userInfo:nil]);
            return;
        }
        
        NSHTTPURLResponse *httpResponse = [response isKindOfClass:[NSHTTPURLResponse class]] ? (NSHTTPURLResponse *)response : nil;
        NSInteger statusCode = httpResponse.statusCode;
        
        NSDictionary *responseDictionary = [self propertyListOrJSONFromData:data];
        NSDictionary *statusDictionary = [responseDictionary[@"Status"] isKindOfClass:[NSDictionary class]] ? responseDictionary[@"Status"] : nil;
        NSInteger errorCode = [responseDictionary[@"ec"] integerValue]; // Same for NSString or NSNumber.
        
        NSString *alertTitle = nil;
        NSString *alertMessage = nil;
        [self parseXMLUIAlertFromData:data title:&alertTitle message:&alertMessage];
        
        NSString *errorMessage = responseDictionary[@"em"] ?: statusDictionary[@"em"] ?: alertMessage ?: alertTitle;
        
        if ([self isRateLimitErrorCode:errorCode statusCode:statusCode])
        {
            completionHandler(NO, nil, [self rateLimitErrorWithMessage:errorMessage]);
            return;
        }
        
        if (errorCode == -21669)
        {
            completionHandler(NO, errorMessage ?: NSLocalizedString(@"Incorrect verification code. Please try again.", @""), nil);
            return;
        }
        
        if (errorCode != 0)
        {
            NSString *description = [NSString stringWithFormat:@"%@ (%@)", errorMessage ?: NSLocalizedString(@"Verification error", @""), @(errorCode)];
            completionHandler(NO, nil, [NSError errorWithDomain:ALTAppleAPIErrorDomain code:ALTAppleAPIErrorUnknown userInfo:@{NSLocalizedDescriptionKey: description}]);
            return;
        }
        
        if (alertTitle != nil || alertMessage != nil)
        {
            NSString *message = alertMessage ?: errorMessage ?: alertTitle ?: NSLocalizedString(@"Verification failed", @"");
            completionHandler(NO, nil, [NSError errorWithDomain:ALTAppleAPIErrorDomain code:ALTAppleAPIErrorVerificationFailed userInfo:@{NSLocalizedDescriptionKey: message}]);
            return;
        }
        
        if (statusCode != 200)
        {
            completionHandler(NO, errorMessage ?: NSLocalizedString(@"Incorrect verification code. Please try again.", @""), nil);
            return;
        }
        
        if (!isTrustedDevice)
        {
            // A phone code is only accepted if Apple hands back its "PE" token.
            BOOL hasPEToken = NO;
            for (id key in httpResponse.allHeaderFields)
            {
                if ([key isKindOfClass:[NSString class]] && [(NSString *)key caseInsensitiveCompare:@"x-apple-pe-token"] == NSOrderedSame)
                {
                    hasPEToken = YES;
                    break;
                }
            }
            
            if (!hasPEToken)
            {
                completionHandler(NO, errorMessage ?: NSLocalizedString(@"Incorrect verification code. Please try again.", @""), nil);
                return;
            }
        }
        
        completionHandler(YES, nil, nil);
    }];
    
    [task resume];
}

#pragma mark Parsing

- (BOOL)isRateLimitErrorCode:(NSInteger)errorCode statusCode:(NSInteger)statusCode
{
    // -21668: too many attempts, -20102: too many codes requested, -22411: rate limited.
    return (errorCode == -21668 || errorCode == -20102 || errorCode == -22411 || statusCode == 429);
}

- (NSError *)rateLimitErrorWithMessage:(NSString *)message
{
    NSDictionary *userInfo = message.length > 0 ? @{NSLocalizedDescriptionKey: message} : nil;
    return [NSError errorWithDomain:ALTAppleAPIErrorDomain code:ALTAppleAPIErrorTooManyVerificationAttempts userInfo:userInfo];
}

- (NSDictionary *)propertyListOrJSONFromData:(NSData *)data
{
    id object = [NSPropertyListSerialization propertyListWithData:data options:0 format:nil error:nil];
    if (![object isKindOfClass:[NSDictionary class]])
    {
        object = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    }
    
    return [object isKindOfClass:[NSDictionary class]] ? object : nil;
}

- (NSString *)firstMatchForPattern:(NSString *)pattern inString:(NSString *)string
{
    if (string == nil)
    {
        return nil;
    }
    
    NSRegularExpression *expression = [NSRegularExpression regularExpressionWithPattern:pattern options:0 error:nil];
    NSTextCheckingResult *match = [expression firstMatchInString:string options:0 range:NSMakeRange(0, string.length)];
    return match ? [string substringWithRange:match.range] : nil;
}

/// Apple reports some failures as a buddyml `<alert title="…" message="…">` rather than a status code.
- (void)parseXMLUIAlertFromData:(NSData *)data title:(NSString **)outTitle message:(NSString **)outMessage
{
    NSString *string = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (string == nil || [string containsString:@"<pinView"])
    {
        return;
    }
    
    NSString *tag = [self firstMatchForPattern:@"<alert(?![^>]*\\bid=)[^>]*>" inString:string];
    if (tag == nil)
    {
        return;
    }
    
    *outTitle = [self firstMatchForPattern:@"(?<=title=\")[^\"]+" inString:tag];
    *outMessage = [self firstMatchForPattern:@"(?<=message=\")[^\"]+" inString:tag];
}

- (NSError *)errorForXMLUIAlertInData:(NSData *)data
{
    NSString *title = nil;
    NSString *message = nil;
    [self parseXMLUIAlertFromData:data title:&title message:&message];
    
    NSString *text = message ?: title;
    if (text == nil)
    {
        return nil;
    }
    
    return [NSError errorWithDomain:ALTAppleAPIErrorDomain code:ALTAppleAPIErrorVerificationFailed userInfo:@{NSLocalizedDescriptionKey: text}];
}

- (NSArray<ALTTrustedPhoneNumber *> *)parseTrustedPhoneNumbersFromDictionary:(NSDictionary *)dictionary
{
    if (![dictionary isKindOfClass:[NSDictionary class]])
    {
        return @[];
    }
    
    NSArray *list = dictionary[@"trustedPhoneNumbers"] ?: dictionary[@"phoneNumbers"];
    if (![list isKindOfClass:[NSArray class]])
    {
        list = nil;
    }
    
    if (list.count == 0 && [dictionary[@"phoneNumber"] isKindOfClass:[NSDictionary class]])
    {
        list = @[dictionary[@"phoneNumber"]];
    }
    
    NSMutableArray<ALTTrustedPhoneNumber *> *numbers = [NSMutableArray array];
    for (NSDictionary *item in list)
    {
        if (![item isKindOfClass:[NSDictionary class]])
        {
            continue;
        }
        
        NSString *identifier = [[NSString stringWithFormat:@"%@", item[@"id"] ?: @""] stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
        if (identifier.length == 0)
        {
            continue;
        }
        
        NSString *display = item[@"numberWithDialCode"] ?: item[@"obfuscatedNumber"];
        if (display == nil && item[@"lastTwoDigits"] != nil)
        {
            display = [NSString stringWithFormat:@"••%@", item[@"lastTwoDigits"]];
        }
        
        [numbers addObject:[[ALTTrustedPhoneNumber alloc] initWithIdentifier:identifier displayNumber:display ?: [NSString stringWithFormat:@"Phone %@", identifier]]];
    }
    
    return numbers;
}


- (void)fetchAccountForSession:(ALTAppleAPISession *)session completionHandler:(void (^)(ALTAccount *account, NSError *error))completionHandler
{
    NSURL *URL = [NSURL URLWithString:@"viewDeveloper.action" relativeToURL:self.baseURL];
    
    [self sendRequestWithURL:URL additionalParameters:nil session:session team:nil completionHandler:^(NSDictionary *responseDictionary, NSError *requestError) {
        if (responseDictionary == nil)
        {
            completionHandler(nil, requestError);
            return;
        }

        NSError *error = nil;
        ALTAccount *account = [self processResponse:responseDictionary parseHandler:^id _Nullable{
            NSDictionary *dictionary = responseDictionary[@"developer"];
            if (dictionary == nil)
            {
                return nil;
            }
            
            ALTAccount *account = [[ALTAccount alloc] initWithResponseDictionary:dictionary];
            return account;
        } resultCodeHandler:nil error:&error];
        
        completionHandler(account, error);
    }];
}

- (void)sendAuthenticationRequestWithParameters:(NSDictionary *)requestDictionary anisetteData:(ALTAnisetteData *)anisetteData completionHandler:(void (^)(NSDictionary *responseDictionary, NSError *error))completionHandler
{
    NSURL *requestURL = [NSURL URLWithString:@"https://gsa.apple.com/grandslam/GsService2"];
    
    NSDictionary<NSString *, NSDictionary<NSString *, id> *> *parameters = @{
        @"Header": @{ @"Version": @"1.0.1" },
        @"Request": requestDictionary
    };
    
    NSError *serializationError = nil;
    NSData *bodyData = [NSPropertyListSerialization dataWithPropertyList:parameters format:NSPropertyListXMLFormat_v1_0 options:0 error:&serializationError];
    if (bodyData == nil)
    {
        NSError *error = [NSError errorWithDomain:ALTAppleAPIErrorDomain code:ALTAppleAPIErrorInvalidParameters userInfo:@{NSUnderlyingErrorKey: serializationError}];
        completionHandler(nil, error);
        return;
    }
    
    NSDictionary<NSString *, NSString *> *httpHeaders = @{
        @"Content-Type": @"text/x-xml-plist",
        @"X-MMe-Client-Info": anisetteData.deviceDescription,
        @"Accept": @"*/*",
        @"User-Agent": @"akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0"
    };
    
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:requestURL];
    request.HTTPMethod = @"POST";
    request.HTTPBody = bodyData;
    [httpHeaders enumerateKeysAndObjectsUsingBlock:^(NSString *key, NSString *value, BOOL *stop) {
        [request setValue:value forHTTPHeaderField:key];
    }];
    
    NSURLSessionDataTask *dataTask = [self.session dataTaskWithRequest:request completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error) {
        if (data == nil)
        {
            completionHandler(nil, error);
            return;
        }
        
        NSError *parseError = nil;
        NSDictionary *responseDictionary = [NSPropertyListSerialization propertyListWithData:data options:0 format:nil error:&parseError];
        
        if (responseDictionary == nil)
        {
            NSError *error = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorBadServerResponse userInfo:@{NSUnderlyingErrorKey: parseError}];
            completionHandler(nil, error);
            return;
        }
        
        NSDictionary *dictionary = responseDictionary[@"Response"];
        
        NSDictionary *status = dictionary[@"Status"];
        
        NSInteger errorCode = [status[@"ec"] integerValue];
        if (errorCode != 0)
        {
            NSError *error = nil;
            switch (errorCode)
            {
                case -22406:
                    error = [NSError errorWithDomain:ALTAppleAPIErrorDomain code:ALTAppleAPIErrorIncorrectCredentials userInfo:nil];
                    break;
                    
                default:
                    break;
            }
            
            if (error == nil)
            {
                NSString *errorDescription = status[@"em"];
                NSString *localizedDescription = [NSString stringWithFormat:@"%@ (%@)", errorDescription, @(errorCode)];
                
                error = [NSError errorWithDomain:ALTAppleAPIErrorDomain code:ALTAppleAPIErrorUnknown userInfo:@{NSLocalizedDescriptionKey: localizedDescription}];
            }
            
            completionHandler(nil, error);
        }
        else
        {
            completionHandler(dictionary, nil);
        }
    }];
    
    [dataTask resume];
}

@end
