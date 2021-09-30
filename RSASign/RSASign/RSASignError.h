//
//  RSASignError.h
//  RSASign
//
//  Created by Yunju Yang on 2021/09/28.
//

#define RSASIGN_LIBRARY_VERSION  @"1.0.0"

#pragma mark - Define Constant
/**
 @brief result code
 */
static NSString *const def_resultCode       = @"resultCode";

/**
 @brief result message
 */
static NSString *const def_resultMsg        = @"resultMsg";

/**
 @brief library version
 */
static NSString *const def_libVersion       = @"libVersion";

/**
 @brief publicKey
 */
static NSString *const def_publicKey        = @"publicKey";

/**
 @brief signature
 */
static NSString *const def_signature        = @"signature";


#pragma mark - Define Success Code
/**
 @brief Success
 */
static NSString *const RSASIGN_SUCCESS          = @"0000";
static NSString *const RSASIGN_SUCCESS_MSG      = @"Success";


#pragma mark - Define Error Code
/**
 @brief E000 - General Fail
 */
static NSString *const RSASIGN_ERR_E000        = @"E000";
static NSString *const RSASIGN_ERR_E000_MSG    = @"General Fail";

/**
 @brief E001 - Unsupported OS Version
 */
static NSString *const RSASIGN_ERR_E001        = @"E001";
static NSString *const RSASIGN_ERR_E001_MSG    = @"Unsupported OS Version";

/**
 @brief E002 - Missing required parameter
 */
static NSString *const RSASIGN_ERR_E002        = @"E002";
static NSString *const RSASIGN_ERR_E002_MSG    = @"Missing required parameter";

/**
 @brief E003 - RSA key not found
 */
static NSString *const RSASIGN_ERR_E003        = @"E003";
static NSString *const RSASIGN_ERR_E003_MSG    = @"RSA key not found";

/**
 @brief E004 - Public key not found
 */
static NSString *const RSASIGN_ERR_E004        = @"E004";
static NSString *const RSASIGN_ERR_E004_MSG    = @"Public key not found";

/**
 @brief E005 - RSA Key generating failed
 */
static NSString *const RSASIGN_ERR_E005        = @"E005";
static NSString *const RSASIGN_ERR_E005_MSG    = @"RSA Key generating failed";

/**
 @brief E006 - RSA signature failed
 */
static NSString *const RSASIGN_ERR_E006        = @"E006";
static NSString *const RSASIGN_ERR_E006_MSG    = @"RSA signature failed";

/**
 @brief E007 - RSA signature verify failed
 */
static NSString *const RSASIGN_ERR_E007        = @"E007";
static NSString *const RSASIGN_ERR_E007_MSG    = @"RSA signature verify failed";
