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
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
import re

# 初始化 rich 控制台
console = Console()

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def generate_random_password(length=8):
    """生成随机密码"""
    charset = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(charset) for _ in range(length))

def sanitize_filename(filename):
    """确保文件名只包含字母、数字、下划线和点"""
    return re.sub(r'[^\w\.]', '', filename)

class AuthHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.username = kwargs.pop('username', 'admin')
        self.password = kwargs.pop('password', generate_random_password())
        super().__init__(*args, **kwargs)

    def send_auth_header(self):
        """发送认证请求头"""
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="Test"')
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def authenticate(self):
        """验证用户名和密码"""
        auth_header = self.headers.get('Authorization')
        if auth_header:
            auth_type, auth_string = auth_header.split(' ', 1)
            if auth_type.lower() == 'basic':
                decoded_auth = base64.b64decode(auth_string).decode('utf-8')
                username, password = decoded_auth.split(':', 1)
                if username == self.username and password == self.password:
                    return True
        return False

    def do_POST(self):
        """处理POST请求（登录或文件上传）"""
        if not self.authenticate():
            self.send_auth_header()
            self.wfile.write('认证失败：用户名或密码错误'.encode('utf-8'))
            return

        if self.path == "/login":
            self.handle_login()
        else:
            self.handle_file_upload()

    def handle_login(self):
        """处理登录请求"""
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        response = {"message": "登录成功"}
        self.wfile.write(str(response).encode('utf-8'))

    def handle_file_upload(self):
        """处理文件上传"""
        try:
            content_length = int(self.headers['Content-Length'])
            file_data = self.rfile.read(content_length)
            filename = sanitize_filename(os.path.basename(urlparse(self.path).path.lstrip('/'))) or '上传的文件'
            with open(filename, 'wb') as file:
                file.write(file_data)
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            success_message = f"文件接收并保存成功: {filename} ({content_length} 字节) - 客户端: {self.client_address[0]}"
            self.wfile.write(success_message.encode('utf-8'))
            logging.info(success_message)
        except Exception as e:
            error_message = f"请求处理错误: {str(e)}"
            logging.error(error_message)
            self.send_error(500, error_message)

    def do_GET(self):
        """处理GET请求"""
        if not self.authenticate():
            self.send_auth_header()
            self.wfile.write('认证失败：用户名或密码错误'.encode('utf-8'))
            return

        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(f"欢迎, {self.username}!".encode('utf-8'))

class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    pass

def start_server(port=9999, use_https=False, username='admin', password=None, cert_file=None, key_file=None):
    """启动服务器"""
    if password is None:
        password = generate_random_password()
        console.print(Panel.fit(f"生成的密码: [bold green]{password}[/bold green]", title="密码"))

    # 显示服务器信息
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("配置项", style="cyan")
    table.add_column("值", style="green")
    table.add_row("用户名", username)
    table.add_row("密码", password)
    table.add_row("端口", str(port))
    table.add_row("HTTPS", "启用" if use_https else "禁用")
    console.print(Panel.fit(table, title="服务器配置"))

    handler = lambda *args, **kwargs: AuthHandler(*args, username=username, password=password, **kwargs)

    if use_https:
        if not cert_file or not key_file:
            if not os.path.exists('server.pem'):
                os.system('openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes -subj "/CN=localhost"')
            cert_file = key_file = 'server.pem'
        httpd = ThreadedHTTPServer(("", port), handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_file, key_file)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        logging.info(f"Serving HTTPS on port {port}")
    else:
        httpd = ThreadedHTTPServer(("", port), handler)
        logging.info(f"Serving HTTP on port {port}")

    # 启动服务器线程
    server_thread = threading.Thread(target=httpd.serve_forever)
    server_thread.daemon = True
    server_thread.start()

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
        description="安全Web服务器，支持密码认证和文件上传",
        epilog="示例:\n"
               "  python server.py -p 8080 --https\n"
               "  python server.py -p 8080 --username myuser --password mypass\n"
               "  python server.py -p 8080 --https --username admin --password 123456\n\n"
               "使用说明:\n"
               "  1. 使用 Basic Auth 认证:\n"
               "     curl -u 用户名:密码 http://localhost:8080/\n"
               "  2. 上传文件:\n"
               "     curl -u 用户名:密码 -X POST -F 'file=@/path/to/file' http://localhost:8080/upload",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('-p', '--port', type=int, default=9999, help="服务器端口 (默认: 9999)")
    parser.add_argument('--https', action='store_true', help="启用HTTPS")
    parser.add_argument('-u', '--username', type=str, default='admin', help="认证用户名 (默认: admin)")
    parser.add_argument('--password', type=str, help="认证密码 (默认: 随机生成)")
    parser.add_argument('--cert', type=str, help="HTTPS 证书文件")
    parser.add_argument('--key', type=str, help="HTTPS 私钥文件")
    args = parser.parse_args()

    start_server(port=args.port, use_https=args.https, username=args.username, password=args.password, cert_file=args.cert, key_file=args.key)
