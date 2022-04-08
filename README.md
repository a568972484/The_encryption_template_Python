`都是作者累积的,且看其珍惜,大家可以尽量可以保存一下,如果转载请写好出处https://www.cnblogs.com/pythonywy`

`git地址https://github.com/a568972484/The_encryption_template_Python`

## 一.md5加密

### 1.简介

`这是一种使用非常广泛的加密方式，不可逆的,常见16位和32位一般都是md5`

```python
import hashlib

data = '你好'
print(hashlib.md5(data.encode(encoding="UTF-8")).hexdigest())  #32位
print(hashlib.md5(data.encode(encoding="UTF-8")).hexdigest()[8:-8])  #16位
```

## 二.RSA加密

### 1.简介

`非对称加密算法,也就是比较常见的公钥私钥加密,可逆的`

### 2.指数和模加密无填充-模板一

```python
import rsa
#模
m = "ae068c2039bd2d82a529883f273cf20a48e0b6faa564e740402375a9cb332a029b8492ae342893d9c9d53d94d3ab8ae95de9607c2e03dd46cebe211532810b73cc764995ee61ef435437bcddb3f4a52fca66246dbdf2566dd85fbc4930c548e7033c2bcc825b038e8dd4b3553690e0c438bbd5ade6f5a476b1cbc1612f5d501f"
#指数
e = '10001'
#加密参数
message = '123456'

class Encrypt(object):
    def __init__(self, e, m):
        self.e = e
        self.m = m

    def encrypt(self, message):
        mm = int(self.m, 16)
        ee = int(self.e, 16)
        rsa_pubkey = rsa.PublicKey(mm, ee)
        crypto = self._encrypt(message.encode(), rsa_pubkey)
        return crypto.hex()

    def _pad_for_encryption(self, message, target_length):
        message = message[::-1]
        max_msglength = target_length - 11
        msglength = len(message)

        padding = b''
        padding_length = target_length - msglength - 3

        for i in range(padding_length):
            padding += b'\x00'

        return b''.join([b'\x00\x00', padding, b'\x00', message])

    def _encrypt(self, message, pub_key):
        keylength = rsa.common.byte_size(pub_key.n)
        padded = self._pad_for_encryption(message, keylength)

        payload = rsa.transform.bytes2int(padded)
        encrypted = rsa.core.encrypt_int(payload, pub_key.e, pub_key.n)
        block = rsa.transform.int2bytes(encrypted, keylength)

        return block

if __name__ == '__main__':
    en = Encrypt(e, m)
    print(en.encrypt(message))
```

### 3.指数和模加密无填充-模板二

```python
import codecs

def rsa_encrypt(content):
    public_exponent = '010001'
    public_modulus = 'ae068c2039bd2d82a529883f273cf20a48e0b6faa564e740402375a9cb332a029b8492ae342893d9c9d53d94d3ab8ae95de9607c2e03dd46cebe211532810b73cc764995ee61ef435437bcddb3f4a52fca66246dbdf2566dd85fbc4930c548e7033c2bcc825b038e8dd4b3553690e0c438bbd5ade6f5a476b1cbc1612f5d501f'

    content = content[::-1]
    rsa = int(codecs.encode(content.encode('utf-8'), 'hex_codec'),
              16) ** int(public_exponent, 16) % int(public_modulus, 16)
    # 把10进制数rsa转为16进制（'x'表示16进制），再取前256位，不够的在最前面补0
    return format(rsa, 'x').zfill(256)
```

### 4.指数和模加密无填充-模板三

```python
import math
if __name__ == '__main__':
    # 实为16进制串，前补0
    e = ''
    # m也需要补00
    m = '008eb933413be3234dddd2730fbb1d05c8848a43d5dc3bdd997f2a9935fba6beb9ffb36854482b0b46cf7e6f9afbbe2e2e7d606fde20bec57dbf722e7985192e8813e6b67628a6f202cf655b7d2ffce4e9dc682dd6034ae706c8e255f25e4051b9ca43f25b3ad686aac9c8f6aeb71d921c13a255c806f78a5a7b9a356c2dd274e3'
    m = int.from_bytes(bytearray.fromhex(m), byteorder='big')
    e = int.from_bytes(bytearray.fromhex(e), byteorder='big')
    # js加密为反向，为保持一致原文应反向处理，所以这里原文实际为204dowls
    plaintext = 'slwod402'.encode('utf-8')
    # 无填充加密逻辑
    input_nr = int.from_bytes(plaintext, byteorder='big')
    crypted_nr = pow(input_nr, e, m)
    keylength = math.ceil(m.bit_length() / 8)
    crypted_data = crypted_nr.to_bytes(keylength, byteorder='big')
    print(crypted_data.hex())
```

### 5.指数和模加密有填充

```python
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
import base64
import binascii

"""
另种rsa加密
"""


def data_encrypt(text):
    """
        RSA 加密
    :param text:    加密前内容
    :return:        加密后内容
    """
    # 判断系统,加载指定模块
    public_exponent = int("010001",16)  #指数
    print(public_exponent)
    public_modulus=int('B23322F080BD5876C0735D585D25C7BC409F637237B07744D27FBF39FB100ABE59DF380EA6BFCDF28C286E7A0CD95BE87F6099F8F39B0E97D9782C3D33FCFB80D43D2F22A9D9417ECFD1A0B8421DEE1CD4B323E8078336E77419A97F94E60A90CA06551202F63819FC8E73425F06ECA4C05BBF8CA32366240A6C36CA61D85019',16) #模
    # content = 'leadeon' + text + time.strftime("%Y%m%d%H%M%S", time.localtime())
    content = text
    max_length = 117
    # public_key = serialization.load_pem_public_key(key, backend=default_backend())
    public_key = rsa.RSAPublicNumbers(public_exponent, public_modulus).public_key(default_backend())
    data = b''
    for i in range(0, len(content), max_length):
        data += public_key.encrypt(content[i: i + max_length].encode(),
                                   padding.PKCS1v15())
    data = base64.b64encode(data).decode()
    #data =binascii.b2a_hex(data).decode()  hex输出
    return data
```

### 6.公钥加密

```python
# 公钥加密
import base64
import rsa
from Crypto.PublicKey import RSA

def encryptPassword(data, publicKeyStr):
    '''
    data:内容
    publicKeyStr:不需要-----BEGIN PUBLIC KEY-----开头，-----END PUBLIC KEY-----结尾的格式,只要中间部分即可
    key_encoded:需要-----BEGIN PUBLIC KEY-----开头，-----END PUBLIC KEY-----结尾的格式
    '''
    key_encoded='''-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCdZGziIrJOlRomzh7M9qzo4ibw
QmwORcVDI0dsfUICLUVRdUN+MJ8ELd55NKsfYy4dZodWX7AmdN02zm1Gk5V5i2Vw
GVWE205u7DhtRe85W1oR9WTsMact5wuqU6okJd2GKrEGotgd9iuAJm90N6TDeDZ4
KHEvVEE1yTyvrxQgkwIDAQAB
-----END PUBLIC KEY-----'''
    # 1、base64解码
    publicKeyBytes = base64.b64decode(publicKeyStr.encode())
    # 3、生成publicKey对象
    key = RSA.import_key(publicKeyBytes)
    #key = RSA.import_key(key_encoded)
    # 4、对原密码加密
    encryptPassword = rsa.encrypt(data.encode(), key)
    return base64.b64encode(encryptPassword).decode()
```

### 7.私钥解密

```python
# rsa 解密
def long_decrypt(msg):
    rsa_private_key = """-----BEGIN RSA PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQClceuXNXcT7H8ElMfzfRhgOoxqmINR7LGXk+tUrIHHP8VCJfqxTKmow45dNK+kfBRKT9+uSxFlNV5uBdfaBFX13Eq8Ynq12hgvILYihU0gUNVuESTdFGaSS60AaCbuPpD9ENVgs4hrHfJwD4PWXCSpoPPcw9s4DSsxmapcHdE8hR21uWeEbQKISrZe+wdqI5Bv+iVqqd6MbX+pO3QJ4CcmVILomAEn64dHqP1cmRZaZ59J/Y9aP9qYtiPYO0kArsxVDM6ZWkDyrbjJJcbaPBmi4JppNTD/fRhDrSdRn8CBTZEnqRKLANhb4V+qaPaU9wAOWDwJqcT18RjfTcuxWi/zAgMBAAECggEAIBabUgWNpfCdph7RNTmTC77vUxFnjvEwdKy83PxkY2fL84t4NwEeetwK9artUiK6sLsTMDPhGNckDITXm7JxlbD3Udhr4m99d06J5OIj1lu3OZTbqIF3b3J8CHMq8dRyvJKSQCIyGEyDpBZuRJo0hi3wfmYCU7nCIemi8CDcXzdGXTaRdiAW73nn+Ow8sFX+XG6/6hPw9t+0r8GhrEfknC29NIPtAQqjamrKQm4lcW9eClId7vknZoNXsWw7w3B1pHy71GDFs+wquG8A3GjHOwySptrb0XexzwEzuxR0HJOdKrsNRSUncm0eY6lfQNW0PEN6IXopK0DooyCQO00rCQKBgQDZAEL6zDXPctCaPtS8qifd/hN3aMz+XvX+O811sXYaB/5ySndaR3mApJnbcoYDvL3EvFWL3YgjWL8Qp0HX7gTrdDuOv8yY+K2i347CCU+B0E81gP1tvUCVTc3x+hLKgcOs8UDH+GouLe1qycVs2FliuYngUFaZwOX4H4MFMiTgdQKBgQDDLa4JsnwY7kR88TLteEqC2G6Jk9IPRMut/PDvdrGHyj6YEw7WbZLnyAMOEm1NeTa+bIr8mPPEEM1mrS3xaWwgn1rMqqzkSC/DpgFppiJGBGX6cDFs2fYJOFBMzKlGIoHcWdl1SSEYbzxNo5ljoK6r+UaBfMcuuS5BHQ56nKpBxwKBgF2Lu1QajGftevfDdjoOsDkGuqWTTCusDCeY6C2AXwVBxPLIH0OP5FUMoDb128foqXYSKl6tFW8HZvZq4/uN5BkMdlBHZo/bRB8eeJA1K00u27aY8KdKGnlCnTFfOJKL9iqrpd2OvVdC/UI30R/m9EGW8lT8zRhjC8A29WhcAYGxAoGAA9U20LvvkfHD6Iw4Cs/M7srfSNZdTq10LoOEG7/B9r+zAPuG1BEszF5yKOmVuerCd3TcOd+rEdOepQCLoW0HkZBvkQtc/9KnFXmCF5gKnkNh2UwwvEl/emjfstJmFJmC4VfmXFZGTxuIHKI01e8G3xuzFcHki3dZgC/Y4/GFqmsCgYBvQbz9raUVVxJwkN+9UsciTNzW10Tkt2OLYlFRiD+QAC9XK7ZjrjIkQIXEL5OrzYDTU3aHNWt3QwZskSfwFD4P118ICkVdPI9If/I0iqtQwCoIM83dtTFhJrImq0zxFn/dxhJv6ga+/CqJQmLHXMWt+vtvlSgcosvU3eYlVpoPjQ==
-----END RSA PRIVATE KEY-----"""
    msg = base64.b64decode(msg)
    # 私钥解密
    priobj = Cipher_pkcs1_v1_5.new(RSA.importKey(rsa_private_key))
    data = priobj.decrypt(msg,None).decode()
    return data
```

### 8..验签

```python
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.Signature import PKCS1_v1_5

from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
import base64


class RsaUtil:

    def __init__(self, pub_key, pri_key):
        self.pri_key_obj = None
        self.pub_key_obj = None
        self.verifier = None
        self.signer = None
        if pub_key:
            pub_key = RSA.importKey(base64.b64decode(pub_key))
            self.pub_key_obj = Cipher_pkcs1_v1_5.new(pub_key)
            self.verifier = PKCS1_v1_5.new(pub_key)
        if pri_key:
            pri_key = RSA.importKey(base64.b64decode(pri_key))
            self.pri_key_obj = Cipher_pkcs1_v1_5.new(pri_key)
            self.signer = PKCS1_v1_5.new(pri_key)

    def public_long_encrypt(self, data, charset='utf-8'):
        data = data.encode(charset)
        length = len(data)
        default_length = 117
        res = []
        for i in range(0, length, default_length):
            res.append(self.pub_key_obj.encrypt(data[i:i + default_length]))
        byte_data = b''.join(res)
        return base64.b64encode(byte_data)

    def private_long_decrypt(self, data, sentinel=b'decrypt error'):
        data = base64.b64decode(data)
        length = len(data)
        default_length = 128
        res = []
        for i in range(0, length, default_length):
            res.append(self.pri_key_obj.decrypt(data[i:i + default_length], sentinel))
        return str(b''.join(res), encoding = "utf-8")

    def sign(self, data, charset='utf-8'):
        h = SHA256.new(data.encode(charset)) 
        signature = self.signer.sign(h)
        return base64.b64encode(signature)

    def verify(self, data, sign,  charset='utf-8'):
        h = SHA256.new(data.encode(charset))
        return self.verifier.verify(h, base64.b64decode(sign))

```

#### 8.1MD5withRSA 签名

```python
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import MD5, SHA1, SHA256
import base64
from flask import current_app
import warnings
warnings.filterwarnings("ignore")



def RSA_sign(data):
    privateKey = '''MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAIooE+9hmb6GvAUQ3j9FDRgrhWMmVWKepKNmQerrvovmySUSPzFHainDMl6HuQAWHCMI9O8S9kzqG3o9pnetpG7JShB6Oc9eX0kA6n0vLR2rYXNo5uVC29/Koqp250T7lzQ9bv6P0rkjIrqjTNIPVQXToyAwQcZQ5rVhUbtnP7YlAgMBAAECgYBpSzpGS0B9sPpDciOwXNQqA6FZe7G/w+D+l8TNYnaK8Y2Dr3ByAlerFJWi7hXVNwSivwTN4MnOvO3MMIha1gBnQCFStI4PjRv2qz6vsGfzZKFadUw3ngzGhT5UtIVAd+IFbbr4J+cGjGMmF5lIEaKrRCS5u4p11uf6LmhvbBTm0QJBAMQA7RYimdU9UStIm/RSkLQg6K89Om3S2AFXwqymiqhM4m6n7lRTE1xNX4pGm1BV8C/qL0d7AHbrJBFi+hN5onMCQQC0cjAXmKdnfhTo0IvYtzpXr77odBz4zt2Ake65ssBJEWFzle69MbWgkbrTKLLjGxBwM+C7fPDGNckqhlpjMGcHAkB+vcKRT6p9svqrrHX8FO+xKp6LwmHn5jD7HU6q6b47egvpVfnM2TNpujaPaXzBA/EeaqZL6IOyYfaer4vZ0At1AkEAqezuRQpIezlMT4I0b7z8gB7MVPMjZVrJVI4YlV8znJt1ffevfxMUy0Tw/nDRJPUTodX4yBZ8VuvHqPgknkuyeQJBALYpXGOH/GjlSVtnhq7eZxvoEqiBLawW5k7Rl1IyNdGR2qxY/nnoCyP2mMCs1Ba05sCcX08zzOzMPvttbSyjqPI='''

    private_keyBytes = base64.b64decode(privateKey)
    priKey = RSA.importKey(private_keyBytes)
    # priKey = RSA.importKey(privateKey)
    signer = PKCS1_v1_5.new(priKey,)
    # SIGNATURE_ALGORITHM = "MD5withRSA"
    hash_obj = MD5.new(data.encode('utf-8'))
    # SIGNATURE_ALGORITHM = "SHA1withRSA"
    # hash_obj = SHA1.new(data.encode('utf-8'))
    # SIGNATURE_ALGORITHM = "SHA256withRSA"
    # hash_obj = SHA256.new(data.encode('utf-8'))

    signature = base64.b64encode(signer.sign(hash_obj))
    return signature


if __name__ == '__main__':
    data = "phone=15811352072&timestamp=1612496512540&device=Android"
    res_sign1 = RSA_sign(data)
    signature = res_sign1.decode('utf8')
    print(signature)
```

#### 8.2实现SHA1withRSA 签名

```python
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import MD5, SHA1, SHA256
import base64
from flask import current_app
import warnings
warnings.filterwarnings("ignore")



def RSA_sign(data):
    privateKey = '''MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAIooE+9hmb6GvAUQ3j9FDRgrhWMmVWKepKNmQerrvovmySUSPzFHainDMl6HuQAWHCMI9O8S9kzqG3o9pnetpG7JShB6Oc9eX0kA6n0vLR2rYXNo5uVC29/Koqp250T7lzQ9bv6P0rkjIrqjTNIPVQXToyAwQcZQ5rVhUbtnP7YlAgMBAAECgYBpSzpGS0B9sPpDciOwXNQqA6FZe7G/w+D+l8TNYnaK8Y2Dr3ByAlerFJWi7hXVNwSivwTN4MnOvO3MMIha1gBnQCFStI4PjRv2qz6vsGfzZKFadUw3ngzGhT5UtIVAd+IFbbr4J+cGjGMmF5lIEaKrRCS5u4p11uf6LmhvbBTm0QJBAMQA7RYimdU9UStIm/RSkLQg6K89Om3S2AFXwqymiqhM4m6n7lRTE1xNX4pGm1BV8C/qL0d7AHbrJBFi+hN5onMCQQC0cjAXmKdnfhTo0IvYtzpXr77odBz4zt2Ake65ssBJEWFzle69MbWgkbrTKLLjGxBwM+C7fPDGNckqhlpjMGcHAkB+vcKRT6p9svqrrHX8FO+xKp6LwmHn5jD7HU6q6b47egvpVfnM2TNpujaPaXzBA/EeaqZL6IOyYfaer4vZ0At1AkEAqezuRQpIezlMT4I0b7z8gB7MVPMjZVrJVI4YlV8znJt1ffevfxMUy0Tw/nDRJPUTodX4yBZ8VuvHqPgknkuyeQJBALYpXGOH/GjlSVtnhq7eZxvoEqiBLawW5k7Rl1IyNdGR2qxY/nnoCyP2mMCs1Ba05sCcX08zzOzMPvttbSyjqPI='''

    private_keyBytes = base64.b64decode(privateKey)
    priKey = RSA.importKey(private_keyBytes)
    # priKey = RSA.importKey(privateKey)
    signer = PKCS1_v1_5.new(priKey,)
    # SIGNATURE_ALGORITHM = "MD5withRSA"
    # hash_obj = MD5.new(data.encode('utf-8'))
    # SIGNATURE_ALGORITHM = "SHA1withRSA"
    hash_obj = SHA1.new(data.encode('utf-8'))
    # SIGNATURE_ALGORITHM = "SHA256withRSA"
    # hash_obj = SHA256.new(data.encode('utf-8'))

    signature = base64.b64encode(signer.sign(hash_obj))
    return signature

if __name__ == '__main__':
    data = "phone=15811352072&timestamp=1612496512540&device=Android"
    res_sign1 = RSA_sign(data)
    signature = res_sign1.decode('utf8')
    print(signature)
```

#### 8.3SHA256withRSA签名

```python
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import MD5, SHA1, SHA256
import base64
from flask import current_app
import warnings
warnings.filterwarnings("ignore")



def RSA_sign(data):
    privateKey = '''MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAIooE+9hmb6GvAUQ3j9FDRgrhWMmVWKepKNmQerrvovmySUSPzFHainDMl6HuQAWHCMI9O8S9kzqG3o9pnetpG7JShB6Oc9eX0kA6n0vLR2rYXNo5uVC29/Koqp250T7lzQ9bv6P0rkjIrqjTNIPVQXToyAwQcZQ5rVhUbtnP7YlAgMBAAECgYBpSzpGS0B9sPpDciOwXNQqA6FZe7G/w+D+l8TNYnaK8Y2Dr3ByAlerFJWi7hXVNwSivwTN4MnOvO3MMIha1gBnQCFStI4PjRv2qz6vsGfzZKFadUw3ngzGhT5UtIVAd+IFbbr4J+cGjGMmF5lIEaKrRCS5u4p11uf6LmhvbBTm0QJBAMQA7RYimdU9UStIm/RSkLQg6K89Om3S2AFXwqymiqhM4m6n7lRTE1xNX4pGm1BV8C/qL0d7AHbrJBFi+hN5onMCQQC0cjAXmKdnfhTo0IvYtzpXr77odBz4zt2Ake65ssBJEWFzle69MbWgkbrTKLLjGxBwM+C7fPDGNckqhlpjMGcHAkB+vcKRT6p9svqrrHX8FO+xKp6LwmHn5jD7HU6q6b47egvpVfnM2TNpujaPaXzBA/EeaqZL6IOyYfaer4vZ0At1AkEAqezuRQpIezlMT4I0b7z8gB7MVPMjZVrJVI4YlV8znJt1ffevfxMUy0Tw/nDRJPUTodX4yBZ8VuvHqPgknkuyeQJBALYpXGOH/GjlSVtnhq7eZxvoEqiBLawW5k7Rl1IyNdGR2qxY/nnoCyP2mMCs1Ba05sCcX08zzOzMPvttbSyjqPI='''

    private_keyBytes = base64.b64decode(privateKey)
    priKey = RSA.importKey(private_keyBytes)
    # priKey = RSA.importKey(privateKey)
    signer = PKCS1_v1_5.new(priKey,)
    # SIGNATURE_ALGORITHM = "MD5withRSA"
    # hash_obj = MD5.new(data.encode('utf-8'))
    # SIGNATURE_ALGORITHM = "SHA1withRSA"
    # hash_obj = SHA1.new(data.encode('utf-8'))
    # SIGNATURE_ALGORITHM = "SHA256withRSA"
    hash_obj = SHA256.new(data.encode('utf-8'))

    signature = base64.b64encode(signer.sign(hash_obj))
    return signature

if __name__ == '__main__':
    data = "phone=15811352072&timestamp=1612496512540&device=Android"
    res_sign1 = RSA_sign(data)
    signature = res_sign1.decode('utf8')
    print(signature)
```

### 9.最原始方法生成公钥和私钥生成通过(crtCoefficient,primeExponentP,primeP,modulus.....)

```python
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
import base64
import binascii

"""
"crtCoefficient": 84432856058147832764138703472538317942464795044718601494587194148378563942685,
"primeExponentP": 55430473883101152246097615323756881862950432952434504984590276578045386834041,
"primeExponentQ": 41230473446336148758497170998210312513410109720579275453308960734626604833351,
"primeP": 109910049826842557628963433845850622251367013324570378590557090526907918339059,
"primeQ": 106061213575088596820097699717773256317123615840075518129430834072505546216719,
"publicExponent": 65537,
"modulus": 11657193268733377953496174345085266431511790176736829620324311319483544845433376888008449023832068012445414318729055242605500539982129558003843075736527421,
"privateExponent": 3398954883077133822319581237472486629533832773658606240974980011352534575146593099441248529746198644134125073285288483505741834384822184028018785454859181
"""



def gen_rsa_keypair():
    d = 3398954883077133822319581237472486629533832773658606240974980011352534575146593099441248529746198644134125073285288483505741834384822184028018785454859181
    dmp1 = 55430473883101152246097615323756881862950432952434504984590276578045386834041
    dmq1 = 41230473446336148758497170998210312513410109720579275453308960734626604833351
    iqmp = 84432856058147832764138703472538317942464795044718601494587194148378563942685
    p = 109910049826842557628963433845850622251367013324570378590557090526907918339059
    q = 106061213575088596820097699717773256317123615840075518129430834072505546216719

    # public key numbers
    e = 65537
    n = 11657193268733377953496174345085266431511790176736829620324311319483544845433376888008449023832068012445414318729055242605500539982129558003843075736527421

    public_numbers = rsa.RSAPublicNumbers(e, n)
    private_numbers = rsa.RSAPrivateNumbers(p, q, d, dmp1, dmq1, iqmp,public_numbers)
    private_key = default_backend().load_rsa_private_numbers(private_numbers)

    pubkey = public_numbers.public_key(default_backend())

    puem = pubkey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # 将PEM个数的数据写入文本文件中
    with open("pu_key.pem", 'w+') as f:
        f.writelines(puem.decode())

    rpem = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                     format=serialization.PrivateFormat.TraditionalOpenSSL,
                             encryption_algorithm=serialization.NoEncryption())
    with open("pr_key.pem", 'w+') as f:
        f.writelines(rpem.decode())

    return


if __name__ == '__main__':
    gen_rsa_keypair()
```

## 三.DES

### 1.简介

`这是一个分组加密算法，解密和加密是同一个算法,可逆的`

### 2.DES加密与解密以及hex输出和bs64格式输出

```python
import pyDes
import base64

Key = "12345678"  #加密的key

Iv = None   #偏移量


def bytesToHexString(bs):
    '''
    bytes转16进制
    '''
    return ''.join(['%02X ' % b for b in bs])
def hexStringTobytes(str):
    '''16进制转bytes'''
    str = str.replace(" ", "")
    return bytes.fromhex(str)

# 加密
def encrypt_str(data):
    # 加密方法
    #padmode填充方式
    #pyDes.ECB模式
    method = pyDes.des(Key, pyDes.ECB, Iv, pad=None, padmode=pyDes.PAD_PKCS5)
    # 执行加密码 hex输出
    k = method.encrypt(data)
    data = bytesToHexString(k).replace(' ','')
    #bs64手粗
    #data =base64.b64encode(k)
    return data

# 解密
def decrypt_str(data):
    method = pyDes.des(Key, pyDes.ECB, Iv, pad=None, padmode=pyDes.PAD_PKCS5)
    k =hexStringTobytes(data)
    #bs64
    #k = base64.b64decode(data)
    return method.decrypt(k)


Encrypt = encrypt_str("aaa")
print(Encrypt)
Decrypt = decrypt_str(Encrypt)
print(Decrypt)
```

## 四.3des

### 代码模板

````python
import hashlib, base64
import json
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.ciphers import algorithms
from Crypto.Cipher import DES3
import json

def pkcs7padding(text):
    """
    明文使用PKCS7填充
    最终调用DES3加密方法时，传入的是一个byte数组，要求是16的整数倍，因此需要对明文进行处理
    :param text: 待加密内容(明文)
    :return:
    """
    bs = DES3.block_size  # 16
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
    pad = PKCS7(algorithms.DES3.block_size).unpadder()
    pad_content = pad.update(content) + pad.finalize()
    return pad_content


def encrypt(key, content):
    """
    DES3加密
    key,iv使用同一个
    模式cbc
    填充pkcs7
    :param key: 密钥
    :param content: 加密内容
    :return:
    """
    key_bytes = bytes(key, encoding='utf-8')
    iv = key_bytes
    cipher = DES3.new(key_bytes, DES3.MODE_ECB)
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
    cryptos = DES3.new(key_bytes, DES3.MODE_ECB)
    data = cryptos.decrypt(text)
    return json.loads(pkcs7_unpad(data))
````

## 五.AES加密

### 1.简介

`和DES差不多,可逆的`

### 2.AES_ECB_pkcs5padding(该模板不兼容中文)

```python
from Crypto.Cipher import AES
import base64

class Aes_ECB(object):
    def __init__(self):
        self.key = 'XXXXXXXXXXX'  #秘钥
        self.MODE = AES.MODE_ECB
        self.BS = AES.block_size
        self.pad = lambda s: s + (self.BS - len(s) % self.BS) * chr(self.BS - len(s) % self.BS)
        self.unpad = lambda s: s[0:-ord(s[-1])]

    # str不是16的倍数那就补足为16的倍数
    def add_to_16(value):
        while len(value) % 16 != 0:
            value += '\0'
        return str.encode(value)  # 返回bytes

    def AES_encrypt(self, text):
        aes = AES.new(Aes_ECB.add_to_16(self.key), self.MODE)  # 初始化加密器
        encrypted_text = str(base64.encodebytes(aes.encrypt(Aes_ECB.add_to_16(self.pad(text)))),
                             encoding='utf-8').replace('\n', '')  # 这个replace大家可以先不用，然后在调试出来的结果中看是否有'\n'换行符
        # 执行加密并转码返回bytes
        return encrypted_text
```

### 3.AES_ECB_pkcs7padding(支持中文)

```python
import hashlib, base64
from Crypto.Cipher import AES
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.ciphers import algorithms


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
```

### 4.魔改的AES能解密,但是加密长度和js不同模板

`可能是当中的中文影响的` 

```python
# _*_ coding: utf-8 _*_
import base64
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.ciphers import algorithms
import json
import binascii
from Crypto.Cipher import AES


def pkcs7_pad(content):
    """
    :param content:
    :return:
    """
    if not isinstance(content, bytes):
        content = content.encode("raw_unicode_escape")
    pad = PKCS7(algorithms.AES.block_size).padder()
    pad_content = pad.update(content) + pad.finalize()
    print(pad_content)

    return pad_content


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


def encrypt_2(key, content, need_replace_wrod_list):
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
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    # 处理明文
    print("need_replace_wrod_list:", need_replace_wrod_list)
    b = content.encode('utf-8')
    for word in need_replace_wrod_list:  # str
        b = b.replace(word.encode("unicode_escape"), str_to_hex_x(word))
    content_padding = pkcs7_pad(b)

    # 加密
    encrypt_bytes = cipher.encrypt(content_padding)
    # 重新编码
    result = str(base64.urlsafe_b64encode(encrypt_bytes), encoding="utf-8").replace("+", "-").replace("_", "/")
    return result


def decrypt(key, text):
    text = base64.b64decode(text)
    key_bytes = bytes(key, encoding='utf-8')
    cryptos = AES.new(key_bytes, AES.MODE_ECB)
    data = cryptos.decrypt(text)
    print(data)
    return json.loads(pkcs7_unpad(data))


def dict_json(d):
    '''python字典转json字符串, 去掉一些空格'''
    j = json.dumps(d).replace('": ', '":').replace(', "', ',"').replace(", {", ",{")
    return j


def str_to_hex(s):
    return r"/x" + r'/x'.join([hex(ord(c)).replace('0x', '') for c in s])


def str_to_hex_x(s):
    '''
    字符串转b'\xe7\xaf\xae\xe7\x90\x83'
    :param s:
    :return:
    '''

    s = binascii.hexlify(s.encode()).decode()
    s_list = []
    for index in range(2, len(s) + 2, 2):
        ss = f"x{s[index - 2:index]}"
        s_list.append(ss)

    s_1 = "\\".join(s_list)
    s_2 = f'b"\\{s_1}"'
    return eval(s_2)


def get_chinese(string):
    """
    检查整个字符串是否包含中文
    :param string: 需要检查的字符串
    :return: bool
    """
    s_list = []
    s = ""
    for ch in string:
        if '\u4e00' <= ch <= '\u9fff':
            s += ch
        else:
            if s:
                s_list.append(s)
                s = ""

    return s_list


if __name__ == '__main__':
    keyStr = "V2ZRDLQKR7IL1GZC"
    a = decrypt(keyStr,
                "Ui2PiLP14MUkvdXaxzqmTySxYtamuhHuwE5nwjxuwHH0IKJ3EVFr9gJODUuYlFl8RMaCZFQ7rW7Ye6S2YAkI6ARXWElx7zG8fAokxcgdH5UU7gpabvtgm3+2N9WF+g009NchttTUT8IIsoCX3tOiKdGQF48M5TMnbXTV9/cDUi4tp3ikDYuS9k8nU/iSoepJZ0Gd3xt27IA8wNGR1n7oDd3rEKitOOY3CEgNxBm/MviMnqYZtmWA4G7NlXFGZqT5I8HqPfsUub5vCYclx5z1Zru1ay5sQ5a2vYhpGqYJcLk0OZCgM/qlZmfVGhFrkWLGOnjWlqal7U9z4bVKP8X8lc2uA0dUisxczdaKqKNQ0P66ByVzTEmNiNIOBgvIcZ3KnQrNK5nqna4OdjrygczbPKuartSsmgM503GnLAwXtMshewdukQstasl8ZR/XOsR+wCX4MKOmrZoOyklgSay6LIUv4D29TTUEzT1SMTl7yKM4cwgpBcS2UwXsvWKGNZxGoYxqqEdBj6+DxzLafXSdyfh38KAQekvpOwNAHOfo4r54Ep1Bln+5CDehGiBTqVW2")
    print(a)
    t = {'venTypeId': '8dc0e52c-564a-4d9a-9cb2-08477f1a18d4', 'venueId': '3b10ff47-7e83-4c21-816c-5edc257168c1',
         'fieldType': '篮球', 'returnUrl': 'https://sports.sjtu.edu.cn/#/paymentResult/1', 'scheduleDate': '2022-02-23',
         'week': '3', 'spaces': [
            {'venuePrice': '15', 'count': 1, 'status': 1, 'scheduleTime': '12:00-13:00', 'subSitename': '场地1-2',
             'subSiteId': '391cff6c-b950-453b-ae80-7a1afa6ac7f1', 'tensity': '1', 'venueNum': 1}], 'tenSity': '紧张'}
    t_1 = str(t)
    print(str_to_hex_x("篮球"))
    t = json.dumps(t, separators=(',', ':'))
    need_replace_wrod_list = get_chinese(t_1)
    print(encrypt_2(keyStr, t, need_replace_wrod_list))
    print(
        "Ui2PiLP14MUkvdXaxzqmTySxYtamuhHuwE5nwjxuwHH0IKJ3EVFr9gJODUuYlFl8RMaCZFQ7rW7Ye6S2YAkI6ARXWElx7zG8fAokxcgdH5UU7gpabvtgm3+2N9WF+g009NchttTUT8IIsoCX3tOiKdGQF48M5TMnbXTV9/cDUi4tp3ikDYuS9k8nU/iSoepJZ0Gd3xt27IA8wNGR1n7oDd3rEKitOOY3CEgNxBm/MviMnqYZtmWA4G7NlXFGZqT5I8HqPfsUub5vCYclx5z1Zru1ay5sQ5a2vYhpGqYJcLk0OZCgM/qlZmfVGhFrkWLGOnjWlqal7U9z4bVKP8X8lc2uA0dUisxczdaKqKNQ0P66ByVzTEmNiNIOBgvIcZ3KnQrNK5nqna4OdjrygczbPKuartSsmgM503GnLAwXtMshewdukQstasl8ZR/XOsR+wCX4MKOmrZoOyklgSay6LIUv4D29TTUEzT1SMTl7yKM4cwgpBcS2UwXsvWKGNZxGoYxqqEdBj6+DxzLafXSdyfh38KAQekvpOwNAHOfo4r54Ep1Bln+5CDehGiBTqVW2")

```

### 5.识别是AES_128\192\256怎么识别

````python
根据key的长度进行识别
128 16位
192 24位
256 32位
#基本上不足的部分都是以0进行填充
````

### 6.ECB和CBC在代码实现上的区别

```python
CBC相比ECB多一个偏移量,至于其他地方代码区别不大
```

### 7.gzip输出解密

```python
# -*- coding: utf-8 -*-
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import modes
from cryptography.hazmat.backends import default_backend

class AES_GZIP:
    @staticmethod
    def gzip_decode(content):
        buf = io.BytesIO(content)
        gf = gzip.GzipFile(fileobj=buf)
        content = gf.read()
        return content

    def pwd_decrypt(self, content):
        key = b'XXXX'
        iv = b'XXXXX'
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        data = decryptor.update(content)
        return self.gzip_decode(data)
```

## 六.SM2/SM4

### GMSSL模块介绍

GmSSL是一个开源的加密包的python实现，支持SM2/SM3/SM4等国密(国家商用密码)算法、项目采用对商业应用友好的类BSD开源许可证，开源且可以用于闭源的商业应用。

### 安装模块

```
pip install gmssl
#https://github.com/duanhongyi/gmssl/blob/master/README.md官方文档
```

### SM2算法

RSA算法的危机在于其存在亚指数算法，对ECC算法而言一般没有亚指数攻击算法 SM2椭圆曲线公钥密码算法：我国自主知识产权的商用密码算法，是ECC（Elliptic Curve Cryptosystem）算法的一种，基于椭圆曲线离散对数问题，计算复杂度是指数级，求解难度较大，同等安全程度要求下，椭圆曲线密码较其他公钥算法所需密钥长度小很多。

gmssl是包含国密SM2算法的Python实现， 提供了 `encrypt`、 `decrypt`等函数用于加密解密， 用法如下：

 #### 1. 初始化`CryptSM2`

```
import base64
import binascii
from gmssl import sm2, func
#16进制的公钥和私钥
private_key = '00B9AB0B828FF68872F21A837FC303668428DEA11DCD1B24429D0C99E24EED83D5'
public_key = 'B9C9A6E04E9C91F7BA880429273747D7EF5DDEB0BB2FF6317EB00BEF331A83081A6994B8993F3F5D6EADDDB81872266C87C018FB4162F5AF347B483E24620207'
sm2_crypt = sm2.CryptSM2(
    public_key=public_key, private_key=private_key)
```

####  2. `encrypt`和`decrypt`

```
#数据和加密后数据为bytes类型
data = b"111"
enc_data = sm2_crypt.encrypt(data)
dec_data =sm2_crypt.decrypt(enc_data)
assert dec_data == data
```

 ####  3.`sign`和`verify`

```
data = b"111" # bytes类型
random_hex_str = func.random_hex(sm2_crypt.para_len)
sign = sm2_crypt.sign(data, random_hex_str) #  16进制
assert sm2_crypt.verify(sign, data) #  16进制
```

### SM4算法

国密SM4(无线局域网SMS4)算法， 一个分组算法， 分组长度为128bit， 密钥长度为128bit， 算法具体内容参照[SM4算法](https://drive.google.com/file/d/0B0o25hRlUdXcbzdjT0hrYkkwUjg/view?usp=sharing)。

gmssl是包含国密SM4算法的Python实现， 提供了 `encrypt_ecb`、 `decrypt_ecb`、 `encrypt_cbc`、 `decrypt_cbc`等函数用于加密解密， 用法如下：

#### 1. 初始化`CryptSM4`

```
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT

key = b'3l5butlj26hvv313'
value = b'111' #  bytes类型
iv = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' #  bytes类型
crypt_sm4 = CryptSM4()
```

#### 2. `encrypt_ecb`和`decrypt_ecb`

```
crypt_sm4.set_key(key, SM4_ENCRYPT)
encrypt_value = crypt_sm4.crypt_ecb(value) #  bytes类型
crypt_sm4.set_key(key, SM4_DECRYPT)
decrypt_value = crypt_sm4.crypt_ecb(encrypt_value) #  bytes类型
assert value == decrypt_value
```

#### 3. `encrypt_cbc`和`decrypt_cbc`

```
crypt_sm4.set_key(key, SM4_ENCRYPT)
encrypt_value = crypt_sm4.crypt_cbc(iv , value) #  bytes类型
crypt_sm4.set_key(key, SM4_DECRYPT)
decrypt_value = crypt_sm4.crypt_cbc(iv , encrypt_value) #  bytes类型
assert value == decrypt_value
```

## 七.其他不怎么需要模板的加密

### 1.base64加密

```python
import base64   #base64也是用来加密的，但是这个是可以解密的
s = "password"
print(base64.b64encode(s.encode()) )  #加密
```

### 2.uuid

```python
#有时候你会看到一些比如xxxx-xxxx-xxx-xxx误以为是加密其实很多是uuid模块自动生成的
随机数格式为:xxxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxx

python的uuid模块提供UUID类和函数uuid1(), uuid3(), uuid4(), uuid5()

1.uuid.uuid1([node[, clock_seq]])
基于时间戳

使用主机ID, 序列号, 和当前时间来生成UUID, 可保证全球范围的唯一性. 但由于使用该方法生成的UUID中包含有主机的网络地址, 因此可能危及隐私. 该函数有两个参数, 如果 node 参数未指定, 系统将会自动调用 getnode() 函数来获取主机的硬件地址. 如果 clock_seq 参数未指定系统会使用一个随机产生的14位序列号来代替.

2.uuid.uuid3(namespace, name)
基于名字的MD5散列值

通过计算命名空间和名字的MD5散列值来生成UUID, 可以保证同一命名空间中不同名字的唯一性和不同命名空间的唯一性, 但同一命名空间的同一名字生成的UUID相同.

3.uuid.uuid4()
基于随机数

通过随机数来生成UUID. 使用的是伪随机数有一定的重复概率.

4.uuid.uuid5(namespace, name)
基于名字的SHA-1散列值
```

### 3.md5加盐

```python
import hashlib

#注意加密顺序 
m=hashlib.md5('加密内容'.encode('utf8'))
m.update(b"盐")
sign = m.hexdigest()
```

### 4.字符串和16进制字符串之间转换

```python
import binascii

binascii.b2a_hex('字符串'.encode())  输出b'e5ad97e7aca6e4b8b2'
binascii.a2b_hex('e5ad97e7aca6e4b8b2').decode()   输出 '字符串'


def str_to_hex_x(s):   #输入篮球,输出
    '''
    字符串转b'\xe7\xaf\xae\xe7\x90\x83'
    :param s:
    :return:
    '''

    s = binascii.hexlify(s.encode()).decode()
    s_list = []
    for index in range(2,len(s)+2,2):
        ss = f"x{s[index-2:index]}"
        s_list.append(ss)

    s_1 = "\\".join(s_list)
    s_2 = f'b"\\{s_1}"'
    return eval(s_2)
  
```



### 5.HmacSHA256加密算法

```python
from hashlib import sha256
import hmac

def get_sign(data, key):
    key = key.encode('utf-8')
    message = data.encode('utf-8')
    sign = base64.b64encode(hmac.new(key, message, digestmod=sha256).digest())
    sign = str(sign, 'utf-8')
    print(sign)
    return sign
```

## 6.字节数组转字符串

```python
a = bytearray(l2)
b = a.decode('utf8')
print(b)
```

## 7.java字节数组转python字节数组

```python
def jb2pb(byte_arr):

 """
 java 字节数组转python字节数组
 :return:
 """

 return [i + 256 if i < 0 else i for i in byte_arr]
```
