# -*- coding:utf-8 -*-
import sys,os,getopt
import time
import frida
import requests
import hashlib
import struct
from http.server import HTTPServer, BaseHTTPRequestHandler
'''
@Author:ruo 
@Github:https://www.github.com/ru0
'''

md5 = lambda bs: hashlib.md5(bs).hexdigest()
# exports 服务端口
PORT = 2000
# 将数据原样返回的服务器ip:端口
FORWARD_SERVER_IP = '127.0.0.1'
FORWARD_SERVER_PORT = 27000
# proxies里面的配置为burp的地址
PROXIES = {"http": "http://127.0.0.1:8080"}
# 忘记这个参数是干嘛的了 -_-!
g_script = None 

class RequestHandler(BaseHTTPRequestHandler):

    def do_POST(self):
        # curl 127.0.0.1:8009/encryptdata -X POST -d "eeljfio2" -
        request_path = self.path
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        
        if request_path == "/encryptdata":
            response = api.contextcustom3(post_data.decode())
        elif request_path == "/decryptdata":
            response = api.contextcustom4(post_data.decode())
        else:
            return
        # fix中文bug
        content = response.encode('gbk')
        #print("[debug] " + response)
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        # body
        self.wfile.write(content)

    def do_GET(self):
        path = str(self.path)
        if path == "/":
            resdata = "worked!"
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.send_header("Content-length", len(resdata))
            self.end_headers()
            self.wfile.write(resdata.encode())
        else:
            return

def get_messages_from_js(message, data):
    #print("[debug] " + str(message))
    if message['type'] == 'send':
        try:
            resp = requests.request('FRIDA',
                'http://%s:%d/apiforward' % (FORWARD_SERVER_IP,FORWARD_SERVER_PORT),
                proxies = PROXIES,
                headers = {'content-type': 'text/plain'},
                # 请求数据.encode('unicode_escape')后登陆有问题 密码= -> \u003d 前面多加了个\
                data = message['payload'].encode()
            )
        except requests.RequestException as e:
            print(e)
        # 返回给js recv(),resp.content返回的是bytes型
        print('[debug] Proxy server Response status: ' + str(resp.status_code))
        if (resp.status_code == requests.codes.ok):
            g_script.post(resp.content.decode())
    elif message['type'] == 'error':
        print("[error] " + message['description'])

def hook_log_on_command():
    hook_code = """

        Java.perform(function () {
            console.log("[*] Hook data encrypt function");
            var hclass = Java.use("com.yitong.mbank.util.security.CryptoUtil");
            //var ByteString = Java.use("com.android.okhttp.okio.ByteString");

            // 固定密钥 com.yitong.mbank.util.security.CryptoUtil.genRandomKey()
            var rKey = Java.use("com.yitong.mbank.util.security.CryptoUtil");
            rKey.genRandomKey.overload().implementation = function () {
                return "abcdefghijklmnop";
            };

            hclass.encryptData.implementation = function (a, b, c) {
                // 输出第二个参数值
                //console.log(arguments[1]);
                console.log("[*] Key is: " + c);
                // 发送消息给web
                send(arguments[1])
                // 接收消息,可以做过滤
                var op = recv(function(value) {
                    console.log("[*] Rec from forward server content: " + value)
                    b =  value
                });
                op.wait();
                return this.encryptData(a, b, c);
            }
        });
    """
    return hook_code

def raise_error(msg):
    print(msg)

def dexdump(pkg_name, api, hashs=None):
    """
    脱壳方法,来自https://github.com/hluwa/FRIDA-DEXDump,原版有点问题使用当前连接脚本载入js。
    """
    if hashs is None:
        hashs = []
    matches = api.scandex()
    for info in matches:
        try:
            dex_bytes = api.memorydump(info['addr'], info['size'])
            # 防止重复读取内存
            md = md5(dex_bytes)
            if md in hashs:
                continue
            hashs.append(md)
            dex_size = len(dex_bytes)
            if dex_bytes[:4] != b"dex\n":
                dex_bytes = b"dex\n035\x00" + dex_bytes[8:]
            elif dex_size >= 0x24:
                dex_bytes = dex_bytes[:0x20] + struct.Struct("<I").pack(dex_size) + dex_bytes[0x24:]
            elif dex_size >= 0x28:
                dex_bytes = dex_bytes[:0x24] + struct.Struct("<I").pack(0x70) + dex_bytes[0x28:]
            elif dex_size >= 0x2C and dex_bytes[0x28:0x2C] not in [b'\x78\x56\x34\x12', b'\x12\x34\x56\x78']:
                dex_bytes = dex_bytes[:0x28] + b'\x78\x56\x34\x12' + dex_bytes[0x2C:]
            # 在当前脚本目录创建包名文件夹
            if not os.path.exists("./" + pkg_name + "/"):
                os.mkdir("./" + pkg_name + "/")
            with open(pkg_name + "/" + info['addr'] + ".dex", 'wb') as out:
                out.write(dex_bytes)
            print("[dexdump] %s" % hex(info['size']))
        except Exception as e:
            print("[Except] %s" % e)


def unpack():
    # 自己的手机要使用对应的libart.so函数名，来自frida-unpack。
    hook_code = """
    setImmediate(function() {
        Interceptor.attach(Module.findExportByName("libart.so", "_ZN3art7DexFile10OpenMemoryEPKhjRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPNS_6MemMapEPKNS_10OatDexFileEPS9_"), {
            onEnter: function (args) {
                var begin = args[1]
                console.log("magic : " + Memory.readUtf8String(begin))
                var address = parseInt(begin,16) + 0x20
                var dex_size = Memory.readInt(ptr(address))
                console.log("dex_size :" + dex_size)
                var file = new File("/sdcard/unpack/" + dex_size + ".dex", "wb")
                file.write(Memory.readByteArray(begin, dex_size))
                file.flush()
                file.close()
            },
            onLeave: function (retval) {
                if (retval.toInt32() > 0) {
                    /* do something */
                }
            }
        })
    });
    """
    return hook_code

def usage():
    readme = "-p 程序包名 #使用unpack方式脱壳\n" \
             "-p 程序包名 -d -f agent.js #使用dexdump方式脱壳\n" \
             "-p 程序包名 -h -f yourjsfile.js #hook数据包\n"
    print(readme)


def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "p:dhf:", ["--pkg", "--dump", "--hook", "--file"])
    except getopt.GetoptError as err:
        usage()
        sys.exit(2)
    action = None
    for o,a in opts:
        if o == "-d":
            action = "dump"
        elif o == "-h":
            action = "hook"
        elif o in ('-f','--file'):
            jsfile = a
        elif o in ('-p','--pkg'):
            package_name = a
        else:
            assert False, "unhandled option"

    server = HTTPServer(('', PORT), RequestHandler)
    print("[*] frida version: " + str(frida.__version__))
    try:
        device = frida.get_usb_device()
    except:
        device = frida.get_remote_device()
    if not device:
        print("[E] Unable to connect to device.")
        exit()
    resume = False
    '''
    1. attach包名
    2. create_script
    3. 加载js脚本
    '''
    try:
        #session = frida.get_device_manager().enumerate_devices()[-1].attach(package_name)
        #pid = device.get_process(package_name).pid
        session = device.attach(package_name)
   
    except frida.ProcessNotFoundError as e:
        raise_error('[E] Cannot find the target process, please check your application status. Details: '+repr(e))
        pid = device.spawn([package_name])
        session = device.attach(pid)
        resume = True
    
    time.sleep(1)
    if action == None:
        script = session.create_script(unpack())
        script.load()
    else:
        # 读取js脚本
        path = os.path.dirname(__file__)
        with open(os.path.join(path, jsfile),'r', encoding='utf-8') as f:
            script = session.create_script(f.read())
        if action == 'dump':
            script.load()
            dexdump(package_name, script.exports, hashs=[])
        elif action == 'hook':
            # 调用python脚本方法
            script.on('message', get_messages_from_js)
            global g_script
            global api
            g_script = script
            script.load()
            # 导出方法
            api = script.exports
            data = api.contextcustom3("aaaaa")
            print(data)
            # 这里启动web不辣么优雅
            server.serve_forever()
    if resume: device.resume(pid)
    sys.stdin.read()

if __name__ == '__main__':
    main()
