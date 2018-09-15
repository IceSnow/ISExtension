//
//  NSString+DES.m
//  GMS
//
//  Created by Roster on 2018/9/14.
//  Copyright © 2018 IceSnow. All rights reserved.
//

#import "NSString+DES.h"
#import <CommonCrypto/CommonCrypto.h>

@implementation NSString (DES)

// 字符串DES加密
- (NSString *)des_encryptionWithKey:(NSString *)key {
    
    NSString *ciphertext = nil;
    const char *textBytes = [self UTF8String];
    size_t dataLength = [self length];
    //==================
    
    uint8_t *bufferPtr = NULL;
    size_t bufferPtrSize = 0;
    size_t movedBytes = 0;
    
    bufferPtrSize = (dataLength + kCCBlockSizeDES) & ~(kCCBlockSizeDES - 1);
    bufferPtr = malloc( bufferPtrSize * sizeof(uint8_t));
    memset((void *)bufferPtr, 0x0, bufferPtrSize);
    
    
    NSString *testString = key;
    NSData *testData = [testString dataUsingEncoding: NSUTF8StringEncoding];
    Byte *iv = (Byte *)[testData bytes];
    
    
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt, kCCAlgorithmDES,
                                          kCCOptionPKCS7Padding,
                                          [key UTF8String], kCCKeySizeDES,
                                          iv,
                                          textBytes, dataLength,
                                          (void *)bufferPtr, bufferPtrSize,
                                          &movedBytes);
    if (cryptStatus == kCCSuccess) {
        
        ciphertext= [[self class] hexStringWithByte:bufferPtr withLength:(NSUInteger)movedBytes];
    } else {
        NSLog(@"Error: %s > %@", __FUNCTION__, self);
    }
    ciphertext = [ciphertext uppercaseString];//字符变大写
    
    return ciphertext;
}

// 字符串DES解密
- (NSString *)des_dencryptionWithKey:(NSString *)key {
    
    NSData* cipherData = [[self lowercaseString] dataInHexString];
    
    unsigned char buffer[1024];
    memset(buffer, 0, sizeof(char));
    size_t numBytesDecrypted = 0;
    NSString *testString = key;
    NSData *testData = [testString dataUsingEncoding: NSUTF8StringEncoding];
    Byte *iv = (Byte *)[testData bytes];
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt,
                                          kCCAlgorithmDES,
                                          kCCOptionPKCS7Padding,
                                          [key UTF8String],
                                          kCCKeySizeDES,
                                          iv,
                                          [cipherData bytes],
                                          [cipherData length],
                                          buffer,
                                          1024,
                                          &numBytesDecrypted);
    NSString* plainText = nil;
    if (cryptStatus == kCCSuccess) {
        NSData* data = [NSData dataWithBytes:buffer length:(NSUInteger)numBytesDecrypted];
        plainText = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    } else {
        NSLog(@"Error: %s > %@", __FUNCTION__, self);
    }
    return plainText;
}


#pragma mark - Private Method

/// 转换为16进制字符串
+ (NSString *)hexStringWithByte:(Byte *)bytes withLength:(NSUInteger)length {
    
    NSString *hexStr = @"";
    if(bytes) {
        
        for(int i=0; i<length; i++) {
            
            NSString *newHexStr = [NSString stringWithFormat:@"%x",bytes[i]&0xff]; ///16进制数
            if([newHexStr length]==1)
                hexStr = [NSString stringWithFormat:@"%@0%@",hexStr,newHexStr];
            else {
                hexStr = [NSString stringWithFormat:@"%@%@",hexStr,newHexStr];
            }
        }
    }
    return hexStr;
}

/// 16进制字符串转为Data
- (NSData *)dataInHexString {
    
    if ([self length] == 0) {
        return nil;
    }
    
    NSMutableData *hexData = [[NSMutableData alloc] initWithCapacity:8];
    NSRange range;
    if ([self length] % 2 == 0) {
        range = NSMakeRange(0, 2);
    } else {
        range = NSMakeRange(0, 1);
    }
    for (NSInteger i = range.location; i < [self length]; i += 2) {
        unsigned int anInt;
        NSString *hexCharStr = [self substringWithRange:range];
        NSScanner *scanner = [[NSScanner alloc] initWithString:hexCharStr];
        
        [scanner scanHexInt:&anInt];
        NSData *entity = [[NSData alloc] initWithBytes:&anInt length:1];
        [hexData appendData:entity];
        
        range.location += range.length;
        range.length = 2;
    }
    return hexData;
}

@end
