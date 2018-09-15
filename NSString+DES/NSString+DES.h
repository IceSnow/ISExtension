//
//  NSString+DES.h
//  GMS
//
//  Created by Roster on 2018/9/14.
//  Copyright © 2018 IceSnow. All rights reserved.
//

#import <Foundation/Foundation.h>

/// DES加密解密
@interface NSString (DES)

/**
 字符串DES加密

 @param key 密钥
 @return 加密结果>Hex字符串
 */
- (NSString *)des_encryptionWithKey:(NSString *)key;

/**
 Hex字符串DES解密

 @param key 密钥
 @return 解密结果>字符串
 */
- (NSString *)des_dencryptionWithKey:(NSString *)key;


@end
