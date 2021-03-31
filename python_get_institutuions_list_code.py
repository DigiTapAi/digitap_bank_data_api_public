import json

import requests
from django.http import JsonResponse
from binascii import hexlify, unhexlify
import hashlib

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


def get_sign(payload):
    print(payload)
    digest_1 = hashlib.sha256(payload.encode('utf-8')).hexdigest()
    recipient_key = RSA.import_key(open("red_carpet_demo.pem").read())
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    _report_sign = hexlify(cipher_rsa.encrypt(digest_1.encode(encoding='UTF-8')))
    return _report_sign.decode('utf-8')


def call_digitap_api(api_url, json_string, signature, token=None, call_type="post"):
    try:

        req = {"payload": json_string, "signature": signature}

        if token:
            # Content type must be included in the header
            header = {"content-type": "application/json"}
        else:
            header = {"content-type": "application/json"}

        # Performs a POST on the specified url to get the service ticket
        if call_type == "get":
            json_string = json.dumps(json_string)
            req = {"payload": json_string, "signature": signature}
            print(req)
            response = requests.get(api_url, params=req)

        else:
            response = requests.post(api_url, json=req, headers=header, verify=False)
        print(response)
        if 'filename' in response.headers:
            filename = response.headers['filename']
            print(filename)
            with open(filename, mode='wb') as localfile:
                localfile.write(response.content)
        else:

            # convert response to json format
            r_json = response.json()
            print(r_json)

    except Exception as e:
        print(e)


request_params = {
    "client_name": "given client name",
    "type": "NetBanking"}

url = 'Digitap Institution LIST API endpoint'

report_payload = json.dumps(request_params)
report_sign = get_sign(report_payload)
print(report_sign)

call_digitap_api(url, request_params, report_sign, '', 'get')
