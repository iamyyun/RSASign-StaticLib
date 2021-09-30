//
//  RSASign.h
//  RSASign
//
//  Created by Yunju Yang on 2021/09/28.
//

#import <Foundation/Foundation.h>

typedef void(^_Nonnull RSASignCallback)(BOOL success, NSDictionary *_Nonnull result);

@interface RSASign : NSObject

/*!
 @discussion Get Library version (Sync)
 @result NSDictionary (resultCode, resultMsg, libVersion)
 */
+(NSDictionary *_Nonnull)getVersion;

/*!
 @discussion Get Library version (Async)
 @param callback RSASignCallback
 */
+(void)getVersion:(RSASignCallback)callback;


/*!
 @discussion Generate RSA 2048 Key pair (Sync)
 @result NSDictionary (resultCode, resultMsg, publicKey)
 */
+(NSDictionary *_Nonnull)generateKey;

/*!
 @discussion Generate RSA 2048 Key pair (Async)
 @param callback RSASignCallback
 */
+(void)generateKey:(RSASignCallback)callback;


/*!
 @discussion Get Public Key (Sync)
 @result NSDictionary (resultCode, resultMsg, publicKey)
 */
+(NSDictionary *_Nonnull)getPublicKey;

/*!
 @discussion Get Public Key (Async)
 @param callback RSASignCallback
 */
+(void)getPublicKey:(RSASignCallback)callback;


/*!
 @discussion Signature with PKCS1 & sha256 (Sync)
 @param signData Data to sign
 @result NSDictionary (resultCode, resultMsg, signature)
 */
+(NSDictionary *_Nonnull)createSignature:(NSData *_Nullable)signData;

/*!
 @discussion Signature with PKCS1 & sha256 (Async)
 @param signData Data to sign
 @param callback RSASignCallback
 */
+(void)createSignature:(NSData *_Nullable)signData callback:(RSASignCallback)callback;


/*!
 @discussion Verify RSA signature (Sync)
 @param signData Data to sign
 @param signature Signature to verify
 */
+(NSDictionary *_Nonnull)verifySignature:(NSData *_Nullable)signData signature:(NSData *_Nullable)signature;

/*!
 @discussion Verify RSA signature (Async)
 @param signData Data to sign
 @param signature Signature to verify
 @param callback RSASignCallback
 */
+(void)verifySignature:(NSData *_Nullable)signData signature:(NSData *_Nullable)signature callback:(RSASignCallback)callback;


/*!
 @discussion Delete RSA 2048 Key pair (Sync)
 @result NSDictionary (resultCode, resultMsg)
 */
+(NSDictionary *_Nonnull)deleteKey;

/*!
 @discussion Delete RSA 2048 Key pair (Async)
 @param callback RSASignCallback
 */
+(void)deleteKey:(RSASignCallback)callback;

@end
