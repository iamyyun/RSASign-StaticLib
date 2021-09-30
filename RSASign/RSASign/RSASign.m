//
//  RSASign.m
//  RSASign
//
//  Created by Yunju Yang on 2021/09/28.
//

#import "RSASign.h"
#import "RSASignError.h"

#import <UIKit/UIKit.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonHMAC.h>
#import <CommonCrypto/CommonCryptor.h>
#import <LocalAuthentication/LocalAuthentication.h>

SecKeyRef prvKeyRef = nil;
SecKeyRef pubKeyRef = nil;

@implementation RSASign

// Get library version (Sync)
+(NSDictionary *_Nonnull)getVersion
{
    @synchronized (self) {
        NSMutableDictionary *resDic = [NSMutableDictionary dictionary];
        [resDic setObject:RSASIGN_SUCCESS forKey:def_resultCode];
        [resDic setObject:RSASIGN_SUCCESS_MSG forKey:def_resultMsg];
        
        // ios version check
        if ([[[UIDevice currentDevice] systemVersion] floatValue] < 8.0)
        {
            [resDic setObject:RSASIGN_ERR_E001 forKey:def_resultCode];
            [resDic setObject:RSASIGN_ERR_E001_MSG forKey:def_resultMsg];
            return resDic;
        }
        
        [resDic setObject:RSASIGN_LIBRARY_VERSION forKey:def_libVersion];
        return resDic;
    }
}

// Get library version (Async)
+(void)getVersion:(RSASignCallback)callback
{
    @synchronized (self) {
        NSDictionary *resDic = [self getVersion];
        if (callback) {
            callback([resDic[def_resultCode] isEqualToString:RSASIGN_SUCCESS], resDic);
        }
    }
}


// Generate RSA 2048 Key pair (Sync)
+(NSDictionary *_Nonnull)generateKey
{
    @synchronized (self) {
        NSMutableDictionary *resDic = [NSMutableDictionary dictionary];
        [resDic setObject:RSASIGN_SUCCESS forKey:def_resultCode];
        [resDic setObject:RSASIGN_SUCCESS_MSG forKey:def_resultMsg];
        
        // ios version check
        if ([[[UIDevice currentDevice] systemVersion] floatValue] < 8.0)
        {
            [resDic setObject:RSASIGN_ERR_E001 forKey:def_resultCode];
            [resDic setObject:RSASIGN_ERR_E001_MSG forKey:def_resultMsg];
            return resDic;
        }
        
        // delete RSA key
        resDic = [NSMutableDictionary dictionaryWithDictionary:[self deleteKey]];
        NSString *deleteCode = [resDic objectForKey:def_resultCode];
        if ([deleteCode isEqualToString:RSASIGN_SUCCESS] == NO && [deleteCode isEqualToString:RSASIGN_ERR_E003] == NO) {
            return resDic;
        }
        
        NSString *keyAlias = @"RSASIGN_KEY_ALIAS";
        
        // Key tag
        NSString *pubTag = [NSString stringWithFormat:@"%@_PUB", keyAlias];
        NSString *prvTag = [NSString stringWithFormat:@"%@_PRV", keyAlias];
        
        // Generate KeyPair
        NSDictionary *pubKeyAttr =
        @{ (id)kSecAttrIsPermanent:             @NO,
           (id)kSecAttrApplicationTag:          [pubTag dataUsingEncoding:NSUTF8StringEncoding],
           (id)kSecAttrAccessible:              (id)kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
           (id)kSecClass:                       (id)kSecClassKey,
           (id)kSecReturnRef:                   @YES,
           (id)kSecReturnData:                  @YES
        };
        
        NSDictionary *prvKeyAttr =
        @{ (id)kSecAttrIsPermanent:             @NO,
           (id)kSecAttrApplicationTag:          [prvTag dataUsingEncoding:NSUTF8StringEncoding],
           (id)kSecAttrAccessible:              (id)kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
           (id)kSecClass:                       (id)kSecClassKey,
           (id)kSecReturnRef:                   @YES,
           (id)kSecReturnData:                  @YES
        };
        
        NSDictionary *attributes =
        @{ (id)kSecAttrKeyType:             (id)kSecAttrKeyTypeRSA,
           (id)kSecAttrKeySizeInBits:       @2048,
    //       (id)kSecAttrTokenID:             (id)kSecAttrTokenIDSecureEnclave,
    //       (id)kSecAttrCanSign:              @YES,
           (id)kSecPublicKeyAttrs:          pubKeyAttr,
           (id)kSecPrivateKeyAttrs:         prvKeyAttr
           };
        
        NSData *pubData = nil;
        
        // After iOS 10
        if ([[NSProcessInfo processInfo] isOperatingSystemAtLeastVersion:(NSOperatingSystemVersion){10,3,0}]) {
            CFErrorRef errRef = NULL;
            prvKeyRef = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attributes, &errRef);
            
            if (!prvKeyRef) {
//                NSError *error = CFBridgingRelease(errRef);
                [resDic setObject:RSASIGN_ERR_E005 forKey:def_resultCode];
                [resDic setObject:RSASIGN_ERR_E005_MSG forKey:def_resultMsg];
                return resDic;
            } else {
                pubKeyRef = SecKeyCopyPublicKey(prvKeyRef);
                
                if (!pubKeyRef) {
                    [resDic setObject:RSASIGN_ERR_E005 forKey:def_resultCode];
                    [resDic setObject:RSASIGN_ERR_E005_MSG forKey:def_resultMsg];
                    return resDic;
                }
            }
            
            // SecKeyRef -> NSData
            CFErrorRef cfError = nil;
            pubData = (__bridge_transfer  NSData *)SecKeyCopyExternalRepresentation(pubKeyRef, &cfError);
            
        } else {
            OSStatus status = SecKeyGeneratePair((__bridge CFDictionaryRef)attributes, &pubKeyRef, &prvKeyRef);
            if (status != errSecSuccess) {
                [resDic setObject:RSASIGN_ERR_E005 forKey:def_resultCode];
                [resDic setObject:RSASIGN_ERR_E005_MSG forKey:def_resultMsg];
                return resDic;
            } else {
                if (!pubKeyRef) {
                    [resDic setObject:RSASIGN_ERR_E005 forKey:def_resultCode];
                    [resDic setObject:RSASIGN_ERR_E005_MSG forKey:def_resultMsg];
                    return resDic;
                }
            }
            
            // SecKeyRef -> NSData
            SecKeyRef finalPubRef = nil;
            
            NSDictionary *attributes = @{ (id)kSecClass: (id)kSecClassKey,
                                       (id)kSecAttrApplicationTag: pubTag,
                                       (id)kSecAttrKeyType: (id)kSecAttrKeyTypeRSA,
                                       (id)kSecAttrKeyClass: (id)kSecAttrKeyClassPublic,
                                         (id)kSecReturnData: @YES};

            OSStatus ostatus = SecItemCopyMatching((__bridge CFDictionaryRef)attributes,
                                                (CFTypeRef *)&finalPubRef);
            if (ostatus == errSecSuccess) {
                if (!finalPubRef) {
                    [resDic setObject:RSASIGN_ERR_E003 forKey:def_resultCode];
                    [resDic setObject:RSASIGN_ERR_E003_MSG forKey:def_resultMsg];
                    return resDic;
                } else {
                    pubData = CFBridgingRelease(finalPubRef);
                }
            } else {
                [resDic setObject:RSASIGN_ERR_E005 forKey:def_resultCode];
                [resDic setObject:RSASIGN_ERR_E005_MSG forKey:def_resultMsg];
                return resDic;
            }
        }
        
        if (!pubData) {
            [resDic setObject:RSASIGN_ERR_E004 forKey:def_resultCode];
            [resDic setObject:RSASIGN_ERR_E004_MSG forKey:def_resultMsg];
            return resDic;
        } else {
            [resDic setObject:RSASIGN_SUCCESS forKey:def_resultCode];
            [resDic setObject:RSASIGN_SUCCESS_MSG forKey:def_resultMsg];
            [resDic setObject:pubData forKey:def_publicKey];
        }
        
        return resDic;
    }
}

// Generate RSA 2048 Key pair (Async)
+(void)generateKey:(RSASignCallback)callback
{
    @synchronized (self) {
        NSDictionary *resDic = [self generateKey];
        if (callback) {
            callback([resDic[def_resultCode] isEqualToString:RSASIGN_SUCCESS], resDic);
        }
    }
}


// Get Public Key (Sync)
+(NSDictionary *_Nonnull)getPublicKey
{
    @synchronized (self) {
        NSMutableDictionary *resDic = [NSMutableDictionary dictionary];
        [resDic setObject:RSASIGN_SUCCESS forKey:def_resultCode];
        [resDic setObject:RSASIGN_SUCCESS_MSG forKey:def_resultMsg];
        
        // ios version check
        if ([[[UIDevice currentDevice] systemVersion] floatValue] < 8.0)
        {
            [resDic setObject:RSASIGN_ERR_E001 forKey:def_resultCode];
            [resDic setObject:RSASIGN_ERR_E001_MSG forKey:def_resultMsg];
            return resDic;
        }
        
        // get public key
        if (!pubKeyRef) {
            [resDic setObject:RSASIGN_ERR_E003 forKey:def_resultCode];
            [resDic setObject:RSASIGN_ERR_E003_MSG forKey:def_resultMsg];
            return resDic;
        } else {
            // SecKeyRef -> NSData
            NSData *pubData = nil;
            
            // After iOS 10
            if ([[NSProcessInfo processInfo] isOperatingSystemAtLeastVersion:(NSOperatingSystemVersion){10,3,0}]) {
                CFErrorRef cfError = nil;
                pubData = (__bridge_transfer  NSData *)SecKeyCopyExternalRepresentation(pubKeyRef, &cfError);
            } else {
                NSString *keyAlias = @"RSASIGN_KEY_ALIAS";
                NSString *pubTag = [NSString stringWithFormat:@"%@_PUB", keyAlias];
                
                SecKeyRef finalPubRef = nil;
                NSDictionary *attributes = @{ (id)kSecClass: (id)kSecClassKey,
                                           (id)kSecAttrApplicationTag: pubTag,
                                           (id)kSecAttrKeyType: (id)kSecAttrKeyTypeRSA,
                                           (id)kSecAttrKeyClass: (id)kSecAttrKeyClassPublic,
                                             (id)kSecReturnData: @YES};

                OSStatus ostatus = SecItemCopyMatching((__bridge CFDictionaryRef)attributes,
                                                    (CFTypeRef *)&finalPubRef);
                if (ostatus == errSecSuccess) {
                    if (!finalPubRef) {
                        [resDic setObject:RSASIGN_ERR_E003 forKey:def_resultCode];
                        [resDic setObject:RSASIGN_ERR_E003_MSG forKey:def_resultMsg];
                        return resDic;
                    } else {
                        pubData = CFBridgingRelease(finalPubRef);
                    }
                } else {
                    [resDic setObject:RSASIGN_ERR_E005 forKey:def_resultCode];
                    [resDic setObject:RSASIGN_ERR_E005_MSG forKey:def_resultMsg];
                    return resDic;
                }
            }
            
            if (!pubData) {
                [resDic setObject:RSASIGN_ERR_E004 forKey:def_resultCode];
                [resDic setObject:RSASIGN_ERR_E004_MSG forKey:def_resultMsg];
                return resDic;
            } else {
                [resDic setObject:pubData forKey:def_publicKey];
            }
        }
        
        return resDic;
    }
}

// Get Public Key (Async)
+(void)getPublicKey:(RSASignCallback)callback
{
    @synchronized (self) {
        NSDictionary *resDic = [self getPublicKey];
        if (callback) {
            callback([resDic[def_resultCode] isEqualToString:RSASIGN_SUCCESS], resDic);
        }
    }
}


// Signature with PKCS1 & sha256 (Sync)
+(NSDictionary *_Nonnull)createSignature:(NSData *_Nullable)signData
{
    @synchronized (self) {
        NSMutableDictionary *resDic = [NSMutableDictionary dictionary];
        [resDic setObject:RSASIGN_SUCCESS forKey:def_resultCode];
        [resDic setObject:RSASIGN_SUCCESS_MSG forKey:def_resultMsg];
        
        // check parameter
        if (signData == nil) {
            [resDic setObject:RSASIGN_ERR_E002 forKey:def_resultCode];
            [resDic setObject:RSASIGN_ERR_E002_MSG forKey:def_resultMsg];
            return resDic;
        }
        
        // ios version check
        if ([[[UIDevice currentDevice] systemVersion] floatValue] < 8.0)
        {
            [resDic setObject:RSASIGN_ERR_E001 forKey:def_resultCode];
            [resDic setObject:RSASIGN_ERR_E001_MSG forKey:def_resultMsg];
            return resDic;
        }
        
        // get private key
        if (!prvKeyRef) {
            [resDic setObject:RSASIGN_ERR_E003 forKey:def_resultCode];
            [resDic setObject:RSASIGN_ERR_E003_MSG forKey:def_resultMsg];
            return resDic;
        } else {
            // sign Data
            NSData *hashData = [self sha256Data:signData];
            
            // signature
            NSData *signature = nil;
            
            // After iOS 10
            if ([[NSProcessInfo processInfo] isOperatingSystemAtLeastVersion:(NSOperatingSystemVersion){10,0,0}]) {
                BOOL canSign = SecKeyIsAlgorithmSupported(prvKeyRef, kSecKeyOperationTypeSign, kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256);
                
                if (canSign) {
                    CFErrorRef error = NULL;
                    signature = (NSData *)CFBridgingRelease(SecKeyCreateSignature(prvKeyRef, kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256, (__bridge CFDataRef)hashData, &error));
                    if (!signature || signature.length == 0) {
    //                        NSError *error = CFBridgingRelease(error);
                        [resDic setObject:RSASIGN_ERR_E006 forKey:def_resultCode];
                        [resDic setObject:RSASIGN_ERR_E006_MSG forKey:def_resultMsg];
                        return resDic;
                    } else {
                        [resDic setObject:signature forKey:def_signature];
                    }
                } else {
                    [resDic setObject:RSASIGN_ERR_E006 forKey:def_resultCode];
                    [resDic setObject:RSASIGN_ERR_E006_MSG forKey:def_resultMsg];
                    return resDic;
                }
            } else {
                const uint8_t* const digestData = [hashData bytes];
                size_t digestLength = [hashData length];
                
                uint8_t sign[256] = {0};
                size_t signLength = sizeof(sign);
                
                OSStatus status = SecKeyRawSign(prvKeyRef, kSecPaddingPKCS1SHA256, digestData, digestLength, sign, &signLength);
                if (status != errSecSuccess) {
                    [resDic setObject:RSASIGN_ERR_E006 forKey:def_resultCode];
                    [resDic setObject:RSASIGN_ERR_E006_MSG forKey:def_resultMsg];
                    return resDic;
                } else {
                    if (signLength == 0) {
                        [resDic setObject:RSASIGN_ERR_E006 forKey:def_resultCode];
                        [resDic setObject:RSASIGN_ERR_E006_MSG forKey:def_resultMsg];
                        return resDic;
                    } else {
                        signature = [NSData dataWithBytes:sign length:signLength];
                        [resDic setObject:signature forKey:def_signature];
                    }
                }
            }
        }
        
        return resDic;
    }
}

// Signature with PKCS1 & sha256 (Async)
+(void)createSignature:(NSData *_Nullable)signData callback:(RSASignCallback)callback
{
    @synchronized (self) {
        NSDictionary *resDic = [self createSignature:signData];
        if (callback) {
            callback([resDic[def_resultCode] isEqualToString:RSASIGN_SUCCESS], resDic);
        }
    }
}


// Verify RSA Signature (Sync)
+(NSDictionary *_Nonnull)verifySignature:(NSData *_Nullable)signData signature:(NSData *_Nullable)signature
{
    @synchronized (self) {
        NSMutableDictionary *resDic = [NSMutableDictionary dictionary];
        [resDic setObject:RSASIGN_SUCCESS forKey:def_resultCode];
        [resDic setObject:RSASIGN_SUCCESS_MSG forKey:def_resultMsg];
        
        // check parameter
        if (signData == nil || signature == nil) {
            [resDic setObject:RSASIGN_ERR_E002 forKey:def_resultCode];
            [resDic setObject:RSASIGN_ERR_E002_MSG forKey:def_resultMsg];
            return resDic;
        }
        
        // ios version check
        if ([[[UIDevice currentDevice] systemVersion] floatValue] < 8.0)
        {
            [resDic setObject:RSASIGN_ERR_E001 forKey:def_resultCode];
            [resDic setObject:RSASIGN_ERR_E001_MSG forKey:def_resultMsg];
            return resDic;
        }
        
        // get public key
        if (!pubKeyRef) {
            [resDic setObject:RSASIGN_ERR_E003 forKey:def_resultCode];
            [resDic setObject:RSASIGN_ERR_E003_MSG forKey:def_resultMsg];
            return resDic;
        } else {
            // sign Data
            NSData *hashData = [self sha256Data:signData];
            
            // After iOS 10
            if ([[NSProcessInfo processInfo] isOperatingSystemAtLeastVersion:(NSOperatingSystemVersion){10,0,0}]) {
                BOOL canVerify = SecKeyIsAlgorithmSupported(pubKeyRef,
                                                            kSecKeyOperationTypeVerify,
                                                            kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256);
                
                if (canVerify) {
                    BOOL result = NO;
                    CFErrorRef error = NULL;
                    
                    result = SecKeyVerifySignature(pubKeyRef,
                                                   kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256,
                                                       (__bridge CFDataRef)hashData,
                                                       (__bridge CFDataRef)signature,
                                                       &error);
                    if (!result) {
                        [resDic setObject:RSASIGN_ERR_E007 forKey:def_resultCode];
                        [resDic setObject:RSASIGN_ERR_E007_MSG forKey:def_resultMsg];
                        return resDic;
                    }
                } else {
                    [resDic setObject:RSASIGN_ERR_E007 forKey:def_resultCode];
                    [resDic setObject:RSASIGN_ERR_E007_MSG forKey:def_resultMsg];
                    return resDic;
                }
            } else {
                // signData
                const uint8_t* const digestData = [hashData bytes];
                size_t digestLength = [hashData length];
                
                // signature
                const uint8_t* const signatureData = [signature bytes];
                size_t signatureLength = [signature length];
                
                OSStatus status = SecKeyRawVerify(pubKeyRef, kSecPaddingPKCS1SHA256, digestData, digestLength, signatureData, signatureLength);
                if (status != errSecSuccess) {
                    [resDic setObject:RSASIGN_ERR_E007 forKey:def_resultCode];
                    [resDic setObject:RSASIGN_ERR_E007_MSG forKey:def_resultMsg];
                    return resDic;
                }
            }
        }
        
        return resDic;
    }
}

// Verify RSA signature (Async)
+(void)verifySignature:(NSData *_Nullable)signData signature:(NSData *_Nullable)signature callback:(RSASignCallback)callback
{
    @synchronized (self) {
        NSDictionary *resDic = [self verifySignature:signData signature:signature];
        if (callback) {
            callback([resDic[def_resultCode] isEqualToString:RSASIGN_SUCCESS], resDic);
        }
    }
}


// Delete RSA 2048 Key pair (Sync)
+(NSDictionary *_Nonnull)deleteKey
{
    @synchronized (self) {
        NSMutableDictionary *resDic = [NSMutableDictionary dictionary];
        [resDic setObject:RSASIGN_SUCCESS forKey:def_resultCode];
        [resDic setObject:RSASIGN_SUCCESS_MSG forKey:def_resultMsg];
        
        // ios version check
        if ([[[UIDevice currentDevice] systemVersion] floatValue] < 8.0)
        {
            [resDic setObject:RSASIGN_ERR_E001 forKey:def_resultCode];
            [resDic setObject:RSASIGN_ERR_E001_MSG forKey:def_resultMsg];
            return resDic;
        }
        
        // check private key
        if (!prvKeyRef) {
            [resDic setObject:RSASIGN_ERR_E003 forKey:def_resultCode];
            [resDic setObject:RSASIGN_ERR_E003_MSG forKey:def_resultMsg];
            return resDic;
        } else {
            // delete SecKeyRef
            pubKeyRef = nil;
            prvKeyRef = nil;
        }
        
        return resDic;
    }
}

// Delete RSA 2048 Key pair (Async)
+(void)deleteKey:(RSASignCallback)callback
{
    @synchronized (self) {
        NSDictionary *resDic = [self deleteKey];
        if (callback) {
            callback([resDic[def_resultCode] isEqualToString:RSASIGN_SUCCESS], resDic);
        }
    }
}


#pragma mark - Common APIs
+(NSData*)sha256Data:(NSData*)data
{
    NSData *hashData = data;
    
    unsigned char *digest = malloc(CC_SHA256_DIGEST_LENGTH);
    CC_SHA256([hashData bytes], (CC_LONG)[hashData length], digest);
    hashData = [NSData dataWithBytes:digest length:CC_SHA256_DIGEST_LENGTH];
    free(digest);
    
    return hashData;
}

@end
