# encoding=utf-8


import rsa
import json
import random
import string
import hashlib
from .models import Precious
from django.shortcuts import render
from django.http import HttpResponse
from django.http import HttpResponseBadRequest
from django.views.decorators.csrf import csrf_exempt

RC4_KEY = "Oops...."


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


@csrf_exempt
def distribute_public_key(request):
    if request.method == "POST":
        uuid_data = request.POST.get('uuid', '')
        hash_uuid = request.POST.get('hash', '')
        print(request.POST)

        try:
            existed = Precious.objects.get(hash=hash_uuid)
            return HttpResponse(existed.public_key)
        except Exception as err:
            existed = None
            print(err)

        if not existed:     # if not existed

            dict_uuid_data = json.loads(rc4(uuid_data, RC4_KEY))

            if hashlib.sha1(str(sorted(dict_uuid_data.items())).encode('utf-8')).hexdigest() == hash_uuid:

                mac = dict_uuid_data.get('mac', '')
                platform = dict_uuid_data.get('platform', '')
                hostname = dict_uuid_data.get('hostname', '')
                print('dict data', dict_uuid_data)
                if mac and platform and hostname:
                    # try:
                    (public_key, private_key) = rsa.newkeys(1024)
                    aes_key = ''
                    for i in range(8):
                        aes_key += random.choice(string.hexdigits)

                    Precious(hash=hash_uuid, mac=mac, platform=platform, hostname=hostname,
                             public_key=public_key.save_pkcs1(), private_key=private_key.save_pkcs1(),
                             aes_key=aes_key).save()

                    return HttpResponse(public_key.save_pkcs1())

                    # except Exception as err:
                    #     print(err)

    return HttpResponseBadRequest()


@csrf_exempt
def distribute_aes_pwd(request):
    if request.method == "POST":

        print(request.POST)

        public_key = request.POST.get('public_key', '')

        try:
            exist = Precious.objects.get(public_key=public_key)
        except Exception as err:
            exist = None
            print(err)

        if exist:
            return HttpResponse(exist.aes_key)

    return HttpResponseBadRequest()
