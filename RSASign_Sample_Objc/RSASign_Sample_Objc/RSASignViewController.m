//
//  RSASignViewController.m
//  RSASign_Sample_Objc
//
//  Created by Yunju on 2020/11/20.
//

#import "RSASignViewController.h"
#import "RSASign.h"

#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonHMAC.h>
#import <CommonCrypto/CommonCryptor.h>

#define RESULT_CODE_SUCCESS  @"0000"

@interface RSASignViewController () <UITextViewDelegate> {
    UITapGestureRecognizer *bgTap;
}

@end

@implementation RSASignViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view from its nib.
    
    bgTap = [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(writeFinished)];
    
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(handleKeyboardWillShowNote:) name:UIKeyboardWillShowNotification object:self.view.window];
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(handleKeyboardWillHideNote:) name:UIKeyboardWillHideNotification object:self.view.window];
}

#pragma mark - Commons
- (void) writeFinished {
    [self.view endEditing:YES];
}

-(void)showResult:(NSString *)title message:(NSString *)message
{
    UIAlertController * alert=   [UIAlertController
                                  alertControllerWithTitle:title
                                  message:message
                                  preferredStyle:UIAlertControllerStyleAlert];
    
    UIAlertAction* ok = [UIAlertAction
                         actionWithTitle:@"OK"
                         style:UIAlertActionStyleDefault
                         handler:^(UIAlertAction * action)
                         {
                             [alert dismissViewControllerAnimated:YES completion:nil];
                         }];
    
    [alert addAction:ok];
    
    [self presentViewController:alert animated:YES completion:nil];
}

-(NSString*)jsonStringPrint : (NSDictionary *)dic
{
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:dic
                                                       options:NSJSONWritingPrettyPrinted
                                                         error:nil];
    return [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
}

-(NSData *) hexToByteArray:(NSString *)hex
{
    if (hex.length == 0) { return nil; }
    
    static const unsigned char HexDecodeChars[] =
    {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 1, //49
        2, 3, 4, 5, 6, 7, 8, 9, 0, 0, //59
        0, 0, 0, 0, 0, 10, 11, 12, 13, 14,
        15, 0, 0, 0, 0, 0, 0, 0, 0, 0, //79
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 10, 11, 12, //99
        13, 14, 15
    };
    
    // convert data(NSString) to CString
    const char *source = [hex cStringUsingEncoding:NSUTF8StringEncoding];
    // malloc buffer
    unsigned char *buffer;
    NSUInteger length = strlen(source) / 2;
    buffer = malloc(length);
    for (NSUInteger index = 0; index < length; index++) {
        buffer[index] = (unsigned char)(HexDecodeChars[(size_t)source[index * 2]] << 4) + (HexDecodeChars[(size_t)source[index * 2 + 1]]);
    }
    
    // init result NSData
    NSData *result = [NSData dataWithBytes:buffer length:length];
    free(buffer);
    source = nil;
    
    return result;
}

-(NSString*)dataToHexString:(NSData*)data {
    size_t size = [data length];
    const uint8_t * const randomBytes = [data bytes];
    NSMutableString *hexStr;
    hexStr = [[NSMutableString alloc] initWithCapacity:size];
    for(NSInteger index = 0; index < data.length; index++)
    {
        [hexStr appendFormat: @"%02x", randomBytes[index]];
    }
    return hexStr;
}

#pragma mark - UITextViewDelegate
- (BOOL)textViewShouldEndEditing:(UITextView *)textView {
    [textView resignFirstResponder];
    return YES;
}

- (void)textViewDidEndEditing:(UITextView *)textView {
}

- (void)textViewDidChange:(UITextView *)textView {
}

#pragma mark - keyboard actions
- (void)handleKeyboardWillShowNote:(NSNotification *)notification
{
    [self.view addGestureRecognizer:bgTap];
}

- (void)handleKeyboardWillHideNote:(NSNotification *)notification
{
    [self.view removeGestureRecognizer:bgTap];
}

#pragma mark - Buton Actions
- (IBAction)actionBtnVersion:(id)sender {
    NSString *title = @"Get library version";
    __block NSString *msg = nil;
    
    // Sync
    NSDictionary *resDic = [RSASign getVersion];
    msg = [self jsonStringPrint:resDic];
    [self showResult:title message:msg];
    
    // Async
//    [RSASign getVersion:^(BOOL success, NSDictionary *result) {
//        msg = [self jsonStringPrint:result];
//        [self showResult:title message:msg];
//    }];
}

- (IBAction)actionBtnGenKey:(id)sender {
    NSString *title = @"Generate RSA key";
    __block NSString *msg = nil;
    
    [self.textSignature setText:@""];
    
    // Sync
    __block NSMutableDictionary *resDic = [NSMutableDictionary dictionaryWithDictionary:[RSASign generateKey]];
    if ([[resDic objectForKey:@"resultCode"] isEqualToString:RESULT_CODE_SUCCESS]) {
        NSString *pubKey = [self dataToHexString:[resDic objectForKey:@"publicKey"]];
        [resDic setObject:pubKey forKey:@"publicKey"];
    }
    msg = [self jsonStringPrint:resDic];
    [self showResult:title message:msg];
    
    
    // Async
//    [RSASign generateKey:^(BOOL success, NSDictionary *result) {
//        if (success) {
//            NSMutableDictionary *resDic = [NSMutableDictionary dictionaryWithDictionary:result];
//            NSString *pubKey = [self dataToHexString:[result objectForKey:@"publicKey"]];
//            [resDic setObject:pubKey forKey:@"publicKey"];
//        }
//        msg = [self jsonStringPrint:resDic];
//        [self showResult:title message:msg];
//    }];
}

- (IBAction)actionBtnGetPubKey:(id)sender {
    NSString *title = @"Get public key";
    __block NSString *msg = nil;
    
    // Sync
    __block NSMutableDictionary *resDic = [NSMutableDictionary dictionaryWithDictionary:[RSASign getPublicKey]];
    if ([[resDic objectForKey:@"resultCode"] isEqualToString:RESULT_CODE_SUCCESS]) {
        NSString *pubKey = [self dataToHexString:[resDic objectForKey:@"publicKey"]];
        [resDic setObject:pubKey forKey:@"publicKey"];
    }
    msg = [self jsonStringPrint:resDic];
    [self showResult:title message:msg];
    
    // Async
//    [RSASign getPublicKey:^(BOOL success, NSDictionary *result) {
//        if (success) {
//            NSMutableDictionary *resDic = [NSMutableDictionary dictionaryWithDictionary:result];
//            NSString *pubKey = [self dataToHexString:[resDic objectForKey:@"publicKey"]];
//            [resDic setObject:pubKey forKey:@"publicKey"];
//        }
//        msg = [self jsonStringPrint:resDic];
//        [self showResult:title message:msg];
//    }];
}

- (IBAction)actionBtnCreateSign:(id)sender {
    NSString *title = @"Create Signature";
    __block NSString *msg = nil;
    
    NSData *signData = [@"original data" dataUsingEncoding:NSUTF8StringEncoding];
    
    // Sync
    __block NSMutableDictionary *resDic = [NSMutableDictionary dictionaryWithDictionary:[RSASign createSignature:signData]];
    if ([[resDic objectForKey:@"resultCode"] isEqualToString:RESULT_CODE_SUCCESS]) {
        NSString *signature = [self dataToHexString:[resDic objectForKey:@"signature"]];
        [resDic setObject:signature forKey:@"signature"];
        
        [self.textSignature setText:signature];
    }
    msg = [self jsonStringPrint:resDic];
    [self showResult:title message:msg];
        
    // Async
//    [RSASign createSignature:signData callback:^(BOOL success, NSDictionary *result) {
//        if (success) {
//            NSString *signature = [self dataToHexString:[resDic objectForKey:@"signature"]];
//            [resDic setObject:signature forKey:@"signature"];
//
//            [self.textSignature setText:signature];
//        }
//        msg = [self jsonStringPrint:result];
//        [self showResult:title message:msg];
//    }];
}

- (IBAction)actionBtnVerifySign:(id)sender {
    NSString *title = @"Verify Signature";
    __block NSString *msg = nil;
    
    NSData *signData = [@"original data" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *signature = [self hexToByteArray:self.textSignature.text];
//    NSData *signature = [self.textSignature.text dataUsingEncoding:NSUTF8StringEncoding];
        
    // Sync
    __block NSMutableDictionary *resDic = [NSMutableDictionary dictionaryWithDictionary:[RSASign verifySignature:signData signature:signature]];
    msg = [self jsonStringPrint:resDic];
    [self showResult:title message:msg];
    
    // Async
//    [RSASign verifySignature:signData signature:signature callback:^(BOOL success, NSDictionary *result) {
//        msg = [self jsonStringPrint:resDic];
//        [self showResult:title message:msg];
//    }];
}

- (IBAction)actionBtnDelKey:(id)sender {
    NSString *title = @"Delete RSA Key";
    __block NSString *msg = nil;
    
    [self.textSignature setText:@""];
    
    // Sync
    __block NSMutableDictionary *resDic = [NSMutableDictionary dictionaryWithDictionary:[RSASign deleteKey]];
    msg = [self jsonStringPrint:resDic];
    [self showResult:title message:msg];
    
    // Async
//    [RSASign deleteKey:^(BOOL success, NSDictionary *result) {
//        msg = [self jsonStringPrint:resDic];
//        [self showResult:title message:msg];
//    }];
}

@end
