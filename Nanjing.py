import http.server
import socketserver
import os
import logging
import ssl
import base64
import argparse
from urllib.parse import urlparse
import random
import string
import threading
import time
import jwt
from datetime import datetime, timedelta
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

# 初始化 rich 控制台
console = Console()

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

JWT_SECRET = "your-256-bit-secret"
JWT_ALGORITHM = "HS256"
TOKEN_EXPIRE_MINUTES = 30

def 生成随机密码(长度=8):
    """生成随机密码"""
    字符集 = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(字符集) for _ in range(长度))

def 生成JWT(用户名):
    """生成JWT"""
    过期时间 = datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRE_MINUTES)
    载荷 = {
        "用户名": 用户名,
        "过期时间": 过期时间.timestamp()
    }
    return jwt.encode(载荷, JWT_SECRET, algorithm=JWT_ALGORITHM)

def 验证JWT(token):
    """验证JWT"""
    try:
        载荷 = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return 载荷["用户名"]
    except jwt.ExpiredSignatureError:
        logging.error("Token已过期")
        return None
    except jwt.InvalidTokenError:
        logging.error("无效的Token")
        return None

class 认证处理器(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.用户名 = kwargs.pop('用户名', 'admin')
        self.密码 = kwargs.pop('密码', 生成随机密码())
        super().__init__(*args, **kwargs)

    def do_AUTHHEAD(self):
        """发送认证请求头"""
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Bearer realm="Test"')
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_POST(self):
        """处理POST请求（登录或文件上传）"""
        if self.path == "/登录":
            self.处理登录()
        else:
            self.处理文件上传()

    def 处理登录(self):
        """处理登录请求"""
        内容长度 = int(self.headers['Content-Length'])
        请求数据 = self.rfile.read(内容长度).decode('utf-8')
        try:
            数据 = dict(项.split("=") for 项 in 请求数据.split("&"))
            用户名 = 数据.get("用户名", "")
            密码 = 数据.get("密码", "")
            if 用户名 == self.用户名 and 密码 == self.密码:
                token = 生成JWT(用户名)
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                响应 = {"token": token}
                self.wfile.write(str(响应).encode('utf-8'))
            else:
                self.send_error(401, "用户名或密码错误")
        except Exception as e:
            self.send_error(500, f"登录处理错误: {str(e)}")

    def 处理文件上传(self):
        """处理文件上传"""
        token = self.headers.get('Authorization', '').replace("Bearer ", "")
        用户名 = 验证JWT(token)
        if not 用户名:
            self.do_AUTHHEAD()
            self.wfile.write('无效或过期的Token'.encode('utf-8'))
            return

        try:
            内容长度 = int(self.headers['Content-Length'])
            文件数据 = self.rfile.read(内容长度)
            路径 = os.path.basename(urlparse(self.path).path.lstrip('/')) or '上传的文件'
            with open(路径, 'wb') as 文件:
                文件.write(文件数据)
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            成功信息 = f"文件接收并保存成功: {路径} ({内容长度} 字节)"
            self.wfile.write(成功信息.encode('utf-8'))
            logging.info(成功信息)
        except Exception as e:
            错误信息 = f"请求处理错误: {str(e)}"
            logging.error(错误信息)
            self.send_error(500, 错误信息)

    def do_GET(self):
        """处理GET请求"""
        token = self.headers.get('Authorization', '').replace("Bearer ", "")
        用户名 = 验证JWT(token)
        if not 用户名:
            self.do_AUTHHEAD()
            self.wfile.write('无效或过期的Token'.encode('utf-8'))
        else:
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(f"欢迎, {用户名}!".encode('utf-8'))

class 多线程HTTP服务器(socketserver.ThreadingMixIn, http.server.HTTPServer):
    pass

def 启动服务器(端口=9999, 使用HTTPS=False, 用户名='admin', 密码=None):
    """启动服务器"""
    if 密码 is None:
        密码 = 生成随机密码()
        console.print(Panel.fit(f"生成的密码: [bold green]{密码}[/bold green]", title="密码"))

    # 显示服务器信息
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("配置项", style="cyan")
    table.add_column("值", style="green")
    table.add_row("用户名", 用户名)
    table.add_row("密码", 密码)
    table.add_row("端口", str(端口))
    table.add_row("HTTPS", "启用" if 使用HTTPS else "禁用")
    console.print(Panel.fit(table, title="服务器配置"))

    处理器 = lambda *args, **kwargs: 认证处理器(*args, 用户名=用户名, 密码=密码, **kwargs)

    if 使用HTTPS:
        if not os.path.exists('server.pem'):
            os.system('openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes -subj "/CN=localhost"')
        httpd = 多线程HTTP服务器(("", 端口), 处理器)
        上下文 = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        上下文.load_cert_chain('server.pem')
        httpd.socket = 上下文.wrap_socket(httpd.socket, server_side=True)
        logging.info(f"Serving HTTPS on port {端口}")
    else:
        httpd = 多线程HTTP服务器(("", 端口), 处理器)
        logging.info(f"Serving HTTP on port {端口}")

    # 启动服务器线程
    服务器线程 = threading.Thread(target=httpd.serve_forever)
    服务器线程.daemon = True
    服务器线程.start()

    console.print(Panel.fit("按下 'Q' 停止服务器。", title="操作提示"))
    while True:
        if input().strip().lower() == 'q':
            console.print(Panel.fit("正在停止服务器...", title="操作提示"))
            httpd.shutdown()
            break
        time.sleep(0.1)

    httpd.server_close()
    console.print(Panel.fit("服务器已停止。", title="操作提示"))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="安全Web服务器，支持JWT认证和文件上传",
        epilog="示例:\n"
               "  python server.py -p 8080 --https\n"
               "  python server.py -p 8080 --username myuser --password mypass\n"
               "  python server.py -p 8080 --https --username admin --password 123456\n\n"
               "Token 使用说明:\n"
               "  1. 使用 /login 接口登录获取 Token:\n"
               "     curl -X POST http://localhost:8080/login -d 'username=admin&password=<密码>'\n"
               "  2. 使用 Token 访问受保护资源:\n"
               "     curl -H 'Authorization: Bearer <Token>' http://localhost:8080/\n"
               "  3. 使用 Token 上传文件:\n"
               "     curl -X POST -H 'Authorization: Bearer <Token>' -F 'file=@/path/to/file' http://localhost:8080/upload",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('-p', '--端口', type=int, default=9999, help="服务器端口 (默认: 9999)")
    parser.add_argument('--https', action='store_true', help="启用HTTPS")
    parser.add_argument('-u', '--用户名', type=str, default='admin', help="认证用户名 (默认: admin)")
    parser.add_argument('--密码', type=str, help="认证密码 (默认: 随机生成)")
    args = parser.parse_args()

    启动服务器(端口=args.端口, 使用HTTPS=args.https, 用户名=args.用户名, 密码=args.密码)
