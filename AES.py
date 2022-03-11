# _*_ coding: utf-8 _*_
# @Time:2022/3/11 5:25 下午
# @Author:YwY(慕白)
# @File:AES.py

import hashlib, base64
from Crypto.Cipher import AES
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.ciphers import algorithms
import json

def pkcs7padding(text):
    """
    明文使用PKCS7填充
    最终调用AES加密方法时，传入的是一个byte数组，要求是16的整数倍，因此需要对明文进行处理
    :param text: 待加密内容(明文)
    :return:
    """
    bs = AES.block_size  # 16
    length = len(text)
    bytes_length = len(bytes(text, encoding='utf-8'))
    # tips：utf-8编码时，英文占1个byte，而中文占3个byte
    padding_size = length if (bytes_length == length) else bytes_length
    padding = bs - padding_size % bs
    # tips：chr(padding)看与其它语言的约定，有的会使用'\0'
    padding_text = chr(padding) * padding
    return text + padding_text


def pkcs7_unpad(content):
    """
    解密时候用
    :param content:
    :return:
    """
    if not isinstance(content, bytes):
        content = content.encode()
    pad = PKCS7(algorithms.AES.block_size).unpadder()
    pad_content = pad.update(content) + pad.finalize()
    return pad_content


def encrypt(key, content):
    """
    AES加密
    key,iv使用同一个
    模式cbc
    填充pkcs7
    :param key: 密钥
    :param content: 加密内容
    :return:
    """
    key_bytes = bytes(key, encoding='utf-8')
    iv = key_bytes
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    # 处理明文
    content_padding = pkcs7padding(content)
    # 加密
    encrypt_bytes = cipher.encrypt(bytes(content_padding, encoding='utf-8'))
    # 重新编码
    result = str(base64.b64encode(encrypt_bytes), encoding='utf-8')
    return result

def decrypt(key,text):
    key_bytes = bytes(key, encoding='utf-8')
    iv = key_bytes
    cryptos = AES.new(key_bytes, AES.MODE_ECB)
    data = cryptos.decrypt(text)
    return json.loads(pkcs7_unpad(data))