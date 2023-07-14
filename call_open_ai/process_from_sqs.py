import json
import os
import time

import boto3
import openai
import requests
from botocore.exceptions import ClientError

openai.organization = os.environ['OPEN_AI_ORG']
openai.api_key = os.environ['OPEN_AI_API_KEY']
PROXY_IP = os.environ['PROXY_IP']
YOU_CORP_ID = os.environ['CORP_ID']
YOU_CORP_SECRET = os.environ['CORP_SECRET']
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table(os.environ['TABLE_NAME'])
IDLE_TIMEOUT = 1800  # 30 minutes in seconds


def handle_text_message(msg):
    # 处理文本消息
    # todo 需要处理接口超时的问题
    print(msg)
    resp = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages=msg
    )
    return resp


def get_access_token(corp_id, corp_secret):
    url = f"https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid={corp_id}&corpsecret={corp_secret}"
    response = requests.get(url)
    if response.status_code == 200:
        result = response.json()
        return result["access_token"]
    else:
        print(f"获取访问令牌失败: {response.content}")
        return None


def send_wechat_user_message(access_token, user_id, message, agent_id):
    url = f"https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token={access_token}"
    data = {
        "touser": user_id,
        "msgtype": "text",
        "agentid": agent_id,
        "text": {
            "content": message
        }
    }
    proxies = {
        'http': f'http://{PROXY_IP}:3628',  # 用您的代理 IP 和端口替换
        'https': f'http://{PROXY_IP}:3628',  # 用您的代理 IP 和端口替换
    }
    print(url)
    print(json.dumps(data))
    response = requests.post(url, proxies=proxies, json=data, timeout=5)
    if response.status_code == 200:
        result = response.json()
        if result["errcode"] == 0:
            # print(f"成功发送消息: {message}")
            pass
        else:
            print(f"发送消息失败: {result['errmsg']}")
    else:
        print(f"发送消息失败: {response.content}")


def send_wechat_bot_message(user_id, agent_id, message):
    access_token = get_access_token(YOU_CORP_ID, YOU_CORP_SECRET)

    if access_token:
        # 替换成实际的用户ID和应用的AgentID
        send_wechat_user_message(access_token, user_id, message, agent_id)
    else:
        print("无法获取访问令牌.")


def process_msg(parsed_dict):
    print(parsed_dict)

    user_msg = parsed_dict.get('Content')
    if not user_msg:
        return None
    ddb_event = {"userId": parsed_dict['FromUserName'], "action": 'retrieve'}
    session_data = handle_event_message(ddb_event)
    if session_data:
        new_sesson_data = session_data
        new_sesson_data.append({"role": "user", "content": user_msg})
        ddb_event = {"userId": parsed_dict['FromUserName'], "action": 'create_or_update',
                     "sessionData": new_sesson_data}
    else:
        new_sesson_data = [{"role": "system", "content": "You are a helpful assistant."},
                           {"role": "user", "content": user_msg}]
        ddb_event = {"userId": parsed_dict['FromUserName'], "action": 'create_or_update',
                     "sessionData": new_sesson_data}

    gpt_resp = handle_text_message(new_sesson_data)
    handle_event_message(ddb_event)  # 只有请求成功问题才写数据库
    print(json.dumps(gpt_resp, ensure_ascii=False))
    gpt_text = gpt_resp['choices'][0]['message']['content']
    new_sesson_data.append({"role": "assistant", "content": gpt_text})
    ddb_event = {"userId": parsed_dict['FromUserName'], "action": 'create_or_update',
                 "sessionData": new_sesson_data}
    handle_event_message(ddb_event)  # 将回答写入数据库
    send_wechat_bot_message(parsed_dict['FromUserName'], parsed_dict['AgentID'], gpt_text)


def handle_event_message(event):
    user_id = event['userId']
    action = event['action']

    if action == 'create_or_update':
        session_data = event['sessionData']
        create_or_update_session(user_id, session_data)
    elif action == 'retrieve':
        session_data = retrieve_session(user_id)
        return session_data
    else:
        raise ValueError(f"Invalid action: {action}")


def create_or_update_session(user_id, session_data):
    current_time = int(time.time())
    expiration_time = current_time + IDLE_TIMEOUT
    try:
        table.put_item(
            Item={
                'userId': user_id,
                'lastInteraction': current_time,
                'sessionData': session_data,
                'expirationTime': expiration_time
            }
        )
    except ClientError as e:
        print(e.response['Error']['Message'])


def retrieve_session(user_id):
    try:
        response = table.get_item(Key={'userId': user_id})
        print(response)
        item = response.get('Item')
        if not item:
            return None
        current_time = int(time.time())

        if current_time - item['lastInteraction'] > IDLE_TIMEOUT:
            delete_session(user_id)
            return None

        return item['sessionData']
    except ClientError as e:
        print(e.response['Error']['Message'])
        return None


def delete_session(user_id):
    try:
        table.delete_item(Key={'userId': user_id})
    except ClientError as e:
        print(e.response['Error']['Message'])


def lambda_handler(event, context):
    for record in event["Records"]:
        message = json.loads(record["body"])
        process_msg(message)

    return {"statusCode": 200}
