import json

import os
import hashlib
from urllib.parse import unquote
import boto3

import xmltodict

from wechat_work.WXBizMsgCrypt3 import WXBizMsgCrypt

# 企业微信回调信息的验证和解密 (替换 YOUR_APP_TOKEN 和 YOUR_ENCODING_AES_KEY)
YOUR_APP_TOKEN = os.environ['APP_TOKEN']
YOUR_ENCODING_AES_KEY = os.environ['ENCODING_AES_KEY']
YOU_CORP_ID = os.environ['CORP_ID']
YOU_CORP_SECRET = os.environ['CORP_SECRET']
QUEUE_URL = os.environ["QUEUE_URL"]


def send_to_sqs(message):
    sqs = boto3.client("sqs")

    response = sqs.send_message(
        QueueUrl=QUEUE_URL,
        MessageBody=json.dumps(message),
    )


def check_signature(token, signature, timestamp, nonce, echostr):
    # 检查企业微信回调信息的签名
    array = sorted([token, timestamp, nonce, echostr])
    temp_str = ''.join(array)
    temp_signature = hashlib.sha1(temp_str.encode('utf-8')).hexdigest()

    return temp_signature == signature


def decrypt_msg(signature, timestamp, nonce, echostr):
    # 解密企业微信回调信息
    # 在这里，你需要实现企业微信回调信息的解密逻辑
    # 参考企业微信官方文档：https://work.weixin.qq.com/api/doc/90000/90139/90968
    wxcpt = WXBizMsgCrypt(YOUR_APP_TOKEN, YOUR_ENCODING_AES_KEY, YOU_CORP_ID)
    ret, sEchoStr = wxcpt.VerifyURL(signature, timestamp, nonce, echostr)
    return sEchoStr


def lambda_handler(event, context):
    # 解析企业微信回调信息
    print(json.dumps(event))
    routeKey = event['routeKey']
    body = event.get('body')
    params = event['queryStringParameters']
    signature = params['msg_signature']
    timestamp = params['timestamp']
    nonce = params['nonce']
    wxcpt = WXBizMsgCrypt(YOUR_APP_TOKEN, YOUR_ENCODING_AES_KEY, YOU_CORP_ID)

    if routeKey.startswith('GET'):
        # 验证回调URL
        echostr = unquote(params['echostr'])

        if not check_signature(YOUR_APP_TOKEN, signature, timestamp, nonce, echostr):
            resp = {
                'statusCode': 403,
                'body': json.dumps('Invalid signature.')
            }
        else:
            ret, decrypted_msg = wxcpt.VerifyURL(signature, timestamp, nonce, echostr)
            resp = {
                'statusCode': 200,
                'body': decrypted_msg.decode()
            }

    elif routeKey.startswith('POST'):
        # 处理回调消息
        ret, decrypted_msg = wxcpt.DecryptMsg(body, signature, timestamp, nonce)
        parsed_dict = xmltodict.parse(decrypted_msg)['xml']

        # 检查消息合法性
        if 'Content' in parsed_dict:
            send_to_sqs(parsed_dict)

        resp_text = "success"
        resp = {
            'statusCode': 200,
            'body': resp_text
        }

    else:
        resp = {
            'statusCode': 500,
            'body': "Invalid request method"
        }

    print(resp)
    return resp
