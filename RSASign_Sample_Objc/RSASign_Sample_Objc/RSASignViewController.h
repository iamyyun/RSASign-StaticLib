//
//  RSASignViewController.h
//  RSASign_Sample_Objc
//
//  Created by Yunju on 2020/11/20.
//

#import <UIKit/UIKit.h>

@interface RSASignViewController : UIViewController

@property (weak, nonatomic) IBOutlet UITextView *textSignature;

- (IBAction)actionBtnVersion:(id)sender;
- (IBAction)actionBtnGenKey:(id)sender;
- (IBAction)actionBtnGetPubKey:(id)sender;
- (IBAction)actionBtnCreateSign:(id)sender;
- (IBAction)actionBtnVerifySign:(id)sender;
- (IBAction)actionBtnDelKey:(id)sender;

@end
