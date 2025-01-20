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
from rich.logging import RichHandler

# 设置 rich 终端输出
console = Console()

# Configure logging to track server activities with rich handler
logging.basicConfig(level=logging.INFO, format='%(message)s', handlers=[RichHandler()])
logger = logging.getLogger("rich")

def generate_password(length=8):
    """Generate a random password of specified length"""
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))

class AuthHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        # Extract username and password from kwargs, or use defaults
        self.username = kwargs.pop('username', 'admin')
        self.password = kwargs.pop('password', generate_password())
        super().__init__(*args, **kwargs)

    def do_AUTHHEAD(self):
        """Send authentication request header"""
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="Test"')
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_POST(self):
        """Handle POST requests (file uploads)"""
        # Check for authentication
        auth = self.headers.get('Authorization')
        if auth is None:
            self.do_AUTHHEAD()
            self.wfile.write(b'No auth header received')
            return
        elif not self.authenticate(auth):
            self.do_AUTHHEAD()
            self.wfile.write(b'Invalid credentials')
            return

        try:
            # Read and process the uploaded file
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            
            parsed_path = urlparse(self.path)
            path = parsed_path.path.lstrip('/')
            
            if not path:
                path = 'uploaded_file'  # Default filename if none provided
            
            # Ensure the path is safe (prevent directory traversal)
            path = os.path.basename(path)
            
            # Save the uploaded file
            with open(path, 'wb') as file:
                file.write(post_data)
            
            # Send success response
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            success_message = f"File received and saved successfully: {path} ({content_length} bytes)"
            self.wfile.write(success_message.encode('utf-8'))
            
            # Log the successful upload
            logger.info(success_message)
            console.print(f"[bold green]{success_message}[/bold green]")
        except Exception as e:
            # Handle and log any errors
            error_message = f"Error processing request: {str(e)}"
            logger.error(error_message)
            console.print(f"[bold red]Error: {error_message}[/bold red]")
            self.send_error(500, error_message)

    def do_GET(self):
        """Handle GET requests"""
        # Check for authentication
        auth = self.headers.get('Authorization')
        if auth is None:
            self.do_AUTHHEAD()
            self.wfile.write(b'No auth header received')
        elif self.authenticate(auth):
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b"Server is running")
        else:
            self.do_AUTHHEAD()
            self.wfile.write(b'Invalid credentials')

    def authenticate(self, auth_header):
        """Authenticate the user"""
        auth_decoded = base64.b64decode(auth_header.split()[1]).decode('ascii')
        username, password = auth_decoded.split(':')
        return username == self.username and password == self.password

class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """Handle requests in a separate thread."""

def run_server(port=9999, use_https=False, username='admin', password=None):
    """Run the server with specified configuration"""
    global httpd
    if password is None:
        password = generate_password()
        console.print(f"Generated password: [bold green]{password}[/bold green]")
    
    console.print(f"[bold cyan]Username: {username}[/bold cyan]")
    console.print(f"[bold cyan]Password: {password}[/bold cyan]")

    handler = lambda *args, **kwargs: AuthHandler(*args, username=username, password=password, **kwargs)

    if use_https:
        # Set up HTTPS server
        if not os.path.exists('server.pem'):
            os.system('openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes -subj "/CN=localhost"')
        
        httpd = ThreadedHTTPServer(("", port), handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain('server.pem')
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        logger.info(f"Serving HTTPS on port {port}")
        console.print(f"[bold green]Serving HTTPS on port {port}[/bold green]")
    else:
        # Set up HTTP server
        httpd = ThreadedHTTPServer(("", port), handler)
        logger.info(f"Serving HTTP on port {port}")
        console.print(f"[bold yellow]Serving HTTP on port {port}[/bold yellow]")

    # Start the server in a separate thread
    server_thread = threading.Thread(target=httpd.serve_forever)
    server_thread.daemon = True
    server_thread.start()

    console.print("[bold blue]Press 'Q' to stop the server.[/bold blue]")
    while True:
        if input().strip().lower() == 'q':
            console.print("[bold red]Stopping the server...[/bold red]")
            httpd.shutdown()
            break
        time.sleep(0.1)

    httpd.server_close()
    console.print("[bold green]Server stopped.[/bold green]")

if __name__ == "__main__":
    # Set up command-line argument parsing
    parser = argparse.ArgumentParser(description="Simple secure web server")
    parser.add_argument('-p', '--port', type=int, default=9999, help="Port to run the server on (default: 9999)")
    parser.add_argument('--https', action='store_true', help="Enable HTTPS")
    parser.add_argument('-u', '--username', type=str, default='admin', help="Username for authentication")
    parser.add_argument('--password', type=str, help="Password for authentication")
    args = parser.parse_args()

    # Run the server with provided arguments
    run_server(port=args.port, use_https=args.https, username=args.username, password=args.password)
