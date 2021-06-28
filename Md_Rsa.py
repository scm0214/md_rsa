# python3.6
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import MD5
import base64
import json
import time
import calendar
import requests

def rsa_sign(data):
    
    #测试环境私钥
    # privatekey='''MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAM8WblrosGzrRPSo+xBiL1zMCimpq64nqw66Wh4Z3lG1WIAfe+mes3oFzLsiOuPALCUZHbaMQ9fC7gcgQIL8PtlPRnuqxO1VrKDPE1hCN2cy+7HuSgWMrhnkgP11eVrDFEV4c9ugA1pl9e/4s2F3QCuCKCCrDh+lFTcwLOB+/jqbAgMBAAECgYEAme0ZX9c/c+Y4XgbQfvAMNlSvZSJpqsxveEYJwAAIYQGDY9CDITZGP3faImqiDTGFXpnZnRuLPe/1TzSo3vOxniuW2Bdyu7gn39b6/bmwveIUVzHG3K5VUMV5r8uGiFoPkbl9jQmBBluAWhPsEdMMibdW+WGXsMiLigVdocCDF9ECQQD7SQMY4op0UuaUjFY3oPs5zTXzupopMFxMFxIn4WnZYTruRXFnJnzS2r+Cm6t+TdjXES0kHjky2ml5FSVfVLMjAkEA0vkgZTh/jGFSQ619Fa3TYzSa8TNGw309pXnXWQRKJO6USmWKOfdONp1u0aN/QlsFCGi8OmjTxeL8KsNWAEHuKQJAHqWr/Af9LOzDdJCdH1HB8i3GC8DRdn6QczNJIpYKa9nA7ziG+TaneKv3OX2078Wc0bYllEcfYMVkocDjevoAkwJBAIuVCDnwB3N5cFQWlIujVhhs1ZZ/tnHgisjQtAnRLL0CnFoclDeFx9maj5dj9O6SCeJmaSK7+GEUrIIeeufwtwECQQCq5yGYqnuXHQSra6qSpoC+65AyROVdDhXWRPdroFFbtTdE9EdaKImgac4B2ARKMGsKSXNXSXStHneN1R7n+iX/
    # '''
    privatekey = '''MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAJxWwMnINorV9PtF6UJQbGDsdrOZDYGRPqq6b7W0qWvqVlqMTlB9cvTrMPARzWLT5yLcRHW75kLi04IYuEQ2CAj8DS4EGHBGOxfQ0TubyyfAFqA9Orj+RGVTjdC5I69vuvAT+CUa/8yVbZawmz1rnpBcvQr9j6dp2A+wiuIKr9HZAgMBAAECgYEAmWb+kIAmFKDQW2ZD9U/YqFoeNyfs+r+8D+YUCuWUgFFWHk8h4RTXIb9NK6MsNtbaK3iarDONQwAyrar30+Z4hlZkcL6SWvqD64Qk+PjIcxj2JE+S+Cja7PdQWOr3tY0dGI6KSVnOGkM3WUWbiPmLnpu5VbY+WNk+hPK01ZzztAECQQD4xsT6ixZHyCKbdKMeb2DUTeu4dvUMn4SIYGw+YvpA2x2PDefeBfjHK93PjWMAe2Ks/msAtug7eSY4dCvd3InBAkEAoODeBJhvs+HJrih/DWJapB8mlyC2zKoeJbkfnIx1oLADIt5QCz1ocRZ2i2FpTpduFdEbWf46K7S9qFze8vHeGQJACp0QUlAUx0M2lsNHIklGLEiWwevxUHSNxvO2KoM2ggXXIP9K4SIIFxc8A1rY2nBpKVBBaGplRgRJKSdrp699AQJACmpklWGVIc1FdGwUxbYPbj7CDdjFXPzKlOCmZklFuFCM8233OrMQFvpAVIfK/JabPvhZz/rAo2HBQaw5lvsHyQJACVHkn503++LP6Wmp1uAhGYRmwI/y6mUlYhkKsTmTyGDosn8rgVWmZvisp6yAwQ35s9Hx+pwc2Nm0m19F7P+zZg=='''
    private_keyBytes = base64.b64decode(privatekey)
    prikey = RSA.importKey(private_keyBytes)
    signer = PKCS1_v1_5.new(prikey)
    hash_obj = my_hash(data)
    signature = base64.b64encode(signer.sign(hash_obj))
    return signature

def rsa_verify(signature, data):
    #公钥
    pubilckey = '''MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAKhn4zt9oBxiSCbY7cxke0DAk0AUBJUDHYe5zfdK5/Cc+HX9kIsfHawPtPrGJ+dESuWF/+pNb+dU3EY/hCo5rv2EGQu15pzYGzjiJ/j00zlQrzQqpCvQxIKPoUDJ8X53ct8t7gP0qRNwvVQRQi3XsKRl26TJf4uKAtyfUFiFPY4VAgMBAAECgYAyYVHzfDOoCib3qDIL0Yul5Xan1tVAFvyAnC9n6brVmsAh3EeftyFTVieYViud3iph2+Khn6T4mcSEJ4BMeZFFvCQEMOel6Ek4pPmOTU85zHTgK2ByujXn/C/P/MFKCu/ZFgwytVBXE6yVpfdq4dqcCikBiJ/uFOrfUs1n+WrZiQJBAPmklkeeWFSvRP1sqKwKxc8uKSLzWfZCHrontu4IHwn1mNOA+UpvwucehenMrYkSzoqabsgKdEIfpieZ8qhWNTcCQQCssbgJZ31q6V5H/XiRTxvlYhAr2eV7p0LS8b23BXYk8eAkgkn5Bgv8qK92Y5oKEp7gH93mfPfhUtlSVUtR4r0TAkEAruFDfUxJqJlXhQiXaF3rkGVP3/IFtWNATzv/A+SgicOImbGh8Sk1qd5SBSSi9IE+Ow5QSMY6BxBQvzEzMgWiJQJAC6b6KfhHqB0S9XyO1A8obLPPL4ZGS6+ffKg/CshdjmSboRsBbsIPsP6YyD40OJXFDo5X5KNt/lAexcVnjaDk7QJBAIlpA0YGdae2U+JlHZvsqetktAwTVGBUNhiO54DAinswkzXEF/cMq3oNanySc643Tj2kWfbp2vt7WrsWTCjgUac=
    '''
    private_keyBytes = base64.b64decode(pubilckey)
    pubkey = RSA.importKey(private_keyBytes)
    hash_obj = my_hash(data)
    verifier = PKCS1_v1_5.new(pubkey)
    # public_key_file.close()
    # print(signature)
    # print(base64.b64decode(signature))

    return verifier.verify(hash_obj, base64.b64decode(signature))

def my_hash(data):
    return MD5.new(data.encode('utf-8'))

def json_file(data):
    key_file = open('data1.json', 'r')
    key_dict = json.load(key_file)

    pri_key = RSA.importKey(base64.b64decode(key_dict["RSAPrivateKey"]))
    signer = PKCS1_v1_5.new(pri_key)
    hash_obj = my_hash(data)
    signature = base64.b64encode(signer.sign(hash_obj))
    key_file.close()
    return signature

if __name__ == '__main__':
    time = calendar.timegm(time.gmtime())
    hao = str(int(round(time*1000)))
    print(hao)
    zhang = "test0414dan08"
    data = "{'subAccountName':'%s','coin':'eth'}|%s" % (zhang, hao)
    print(data)
    sign = rsa_sign(data)
    print(rsa_sign(data))
    # print(json_file())
    print(rsa_verify(sign,data))
