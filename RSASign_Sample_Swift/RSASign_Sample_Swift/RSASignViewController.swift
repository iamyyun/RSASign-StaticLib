//
//  RSASignViewController.swift
//  MobileRSign_iOS_Swift
//
//  Created by Yunju on 03/09/2019.
//  Copyright © 2019 ATON. All rights reserved.
//

import UIKit
import CommonCrypto.CommonDigest
import CommonCrypto.CommonHMAC
import CommonCrypto.CommonCryptor

let RESULT_CODE_SUCCESS =     "0000"

class RSASignViewController: UIViewController, UITextViewDelegate {
    
    @IBOutlet weak var textSignature: UITextView!
    
    private var bgTap: UITapGestureRecognizer?
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        bgTap = UITapGestureRecognizer.init(target: self, action: #selector(writeFinished))
        
        NotificationCenter.default.addObserver(self, selector: #selector(keyboardWillShow), name: UIResponder.keyboardWillShowNotification, object: nil)
        NotificationCenter.default.addObserver(self, selector: #selector(keyboardWillHide), name: UIResponder.keyboardWillHideNotification, object: nil)
    }
    
    // MARK: Common Functions
    @objc func writeFinished()
    {
        self.view.endEditing(true)
    }
    
    func showResult (title: String, message: String)
    {
        let alert = UIAlertController.init(title: title, message: message, preferredStyle: UIAlertController.Style.alert)
        alert.addAction(UIAlertAction.init(title: "OK", style: UIAlertAction.Style.default, handler: {
            action in
            alert.dismiss(animated: true, completion: nil)
            
        }))
        
        self.present(alert, animated: true, completion: nil)
    }
    
    func jsonStringPrint (dic: [AnyHashable : Any]) -> String
    {
        let jsonData: Data! = try? JSONSerialization.data(withJSONObject: dic, options: JSONSerialization.WritingOptions.prettyPrinted)
        let jsonString: String! = String(data: jsonData, encoding: String.Encoding.utf8)
        
        return jsonString ?? ""
    }
    
    func hexToBytes(_ string: String) -> [UInt8]? {
        let length = string.count
        if length & 1 != 0 {
            return nil
        }
        var bytes = [UInt8]()
        bytes.reserveCapacity(length/2)
        var index = string.startIndex
        for _ in 0..<length/2 {
            let nextIndex = string.index(index, offsetBy: 2)
            if let b = UInt8(string[index..<nextIndex], radix: 16) {
                bytes.append(b)
            } else {
                return nil
            }
            index = nextIndex
        }
        return bytes
    }
    
    // MARK: UITextViewDelegate
    func textViewShouldEndEditing(_ textView: UITextView) -> Bool {
        textView.resignFirstResponder()
        return true
    }
    
    func textViewDidEndEditing(_ textView: UITextView) {
    }
    
    func textViewDidChange(_ textView: UITextView) {
    }
    
    // MARK: Actions
    @IBAction func actionBtnVersion(_ sender: Any) {
        let title: String! = "Get library version"
        var msg: String! = ""
        
        // Sync
        let resDic: Dictionary! = RSASign.getVersion()
        msg = self.jsonStringPrint(dic: resDic)
        self.showResult(title: title, message: msg)
        
        // Async
//        RSASign.getVersion({ (success: Bool, result: Dictionary) in
//            msg = self.jsonStringPrint(dic: result)
//            self.showResult(title: title, message: msg)
//        })
    }
    
    @IBAction func actionBtnGenKey(_ sender: Any) {
        let title: String! = "Generate RSA key"
        var msg: String! = ""
        
        self.textSignature.text = ""
        
        // Sync
        var resDic: Dictionary! = RSASign.generateKey()
        if (resDic["resultCode"] as! String? == RESULT_CODE_SUCCESS) {
            let pubKey: Data! = resDic["publicKey"] as? Data
            resDic["publicKey"] = pubKey.hexEncodedString()
        }
        msg = self.jsonStringPrint(dic: resDic);
        self.showResult(title: title, message: msg)
        
        // Async
//        RSASign.generateKey({ (success: Bool, result: Dictionary) in
//            if success == true {
//                var resDic: Dictionary = result;
//                let pubKey: Data! = resDic["publicKey"] as? Data
//                resDic["publicKey"] = pubKey.hexEncodedString()
//            }
//            msg = self.jsonStringPrint(dic: resDic);
//            self.showResult(title: title, message: msg)
//        })
    }
    
    @IBAction func actionBtnGetPubKey(_ sender: Any) {
        let title: String! = "Get public key"
        var msg: String! = ""

        // Sync
        var resDic: Dictionary! = RSASign.getPublicKey()
        if (resDic["resultCode"] as! String? == RESULT_CODE_SUCCESS) {
            let pubKey: Data! = resDic["publicKey"] as? Data
            resDic["publicKey"] = pubKey.hexEncodedString()
        }
        msg = self.jsonStringPrint(dic: resDic);
        self.showResult(title: title, message: msg)
        
        // Async
//        RSASign.getPublicKey({ (success: Bool, result: Dictionary) in
//            if success == true {
//                var resDic: Dictionary = result;
//                let pubKey: Data! = resDic["publicKey"] as? Data
//                resDic["publicKey"] = pubKey.hexEncodedString()
//            }
//            msg = self.jsonStringPrint(dic: resDic);
//            self.showResult(title: title, message: msg)
//        })
    }
    
    @IBAction func actionBtnCreateSign(_ sender: Any) {
        let title: String! = "Create Signature"
        var msg: String! = ""
        
        let signData: Data! = "original data".data(using: .utf8)

        // Sync
        var resDic: Dictionary! = RSASign.createSignature(signData)
        if resDic["resultCode"] as! String? == RESULT_CODE_SUCCESS {
            let signature: Data! = resDic["signature"] as? Data
            resDic["signature"] = signature.hexEncodedString()
            
            self.textSignature.text = signature.hexEncodedString()
        }
        msg = self.jsonStringPrint(dic: resDic);
        self.showResult(title: title, message: msg)
            
        // Async
//        RSASign.createSignature(signData, callback:{ (success: Bool, result: Dictionary) in
//            if success == true {
//                let signature: Data! = resDic["signature"] as? Data
//                resDic["signature"] = signature.hexEncodedString()
//
//                self.textSignature.text = signature.hexEncodedString()
//            }
//            msg = self.jsonStringPrint(dic: result);
//            self.showResult(title: title, message: msg)
//        })
    }
    
    @IBAction func actionBtnVerifySign(_ sender: Any) {
        let title: String! = "Verify Signature"
        var msg: String! = ""
        
        let signData: Data! = "original data".data(using: .utf8)
        let signature: [UInt8]! = self.hexToBytes(self.textSignature.text)
        let signatureData: NSData! = NSData(bytes: signature, length: signature.count)
        
        // Sync
        let resDic: Dictionary! = RSASign.verifySignature(signData, signature: (signatureData as Data?))
        msg = self.jsonStringPrint(dic: resDic);
        self.showResult(title: title, message: msg)
        
        // Async
//        RSASign.verifySignature(signData, signature: (signatureData as Data?), callback:{ (success: Bool, result: Dictionary) in
//            msg = self.jsonStringPrint(dic: resDic);
//            self.showResult(title: title, message: msg)
//        })
    }
    
    @IBAction func actionBtnDelKey(_ sender: Any) {
        let title: String! = "Delete RSA key"
        var msg: String! = ""
        
        self.textSignature.text = ""
        
        // Sync
        let resDic: Dictionary! = RSASign.deleteKey()
        msg = self.jsonStringPrint(dic: resDic);
        self.showResult(title: title, message: msg)
        
        // Async
//        RSASign.deleteKey({ (success: Bool, result: Dictionary) in
//            msg = self.jsonStringPrint(dic: result);
//            self.showResult(title: title, message: msg)
//        })
    }
    
    
    // MARK: Keyboard Notification
    @objc func keyboardWillShow(notification: NSNotification) {
        view.addGestureRecognizer(bgTap!)
    }
    
    @objc func keyboardWillHide(notification: NSNotification) {
        view.removeGestureRecognizer(bgTap!)
    }
    
}
