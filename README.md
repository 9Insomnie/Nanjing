# 🔒 Secure Web Server

欢迎来到 **Secure Web Server**，一个既安全又有趣的 Web 服务器！🚀  
无论是上传文件、验证身份，还是简单地打个招呼，这个服务器都能搞定！  

---

## 🌟 功能特性

- **JWT 认证**：用 Token 保护你的资源，安全又方便！🔑
- **文件上传**：上传文件就像发朋友圈一样简单！📁
- **多线程支持**：同时处理多个请求，效率杠杠的！⚡
- **HTTPS 支持**：让你的数据传输更安全！🔐
- **美观输出**：终端输出美得像一幅画！🎨

---

## 🚀 快速开始

### 1. 安装依赖
确保你已经安装了 Python 3.7+，然后运行以下命令安装依赖：
```bash
pip install -r requirements.txt
```

### 2. 启动服务器
```bash
python server.py -p 8080
```

### 3. 开始使用
- **登录获取 Token**：
  ```bash
  curl -X POST http://localhost:8080/login -d 'username=admin&password=<密码>'
  ```
- **使用 Token 访问资源**：
  ```bash
  curl -H 'Authorization: Bearer <Token>' http://localhost:8080/
  ```
- **上传文件**：
  ```bash
  curl -X POST -H 'Authorization: Bearer <Token>' -F 'file=@/path/to/file' http://localhost:8080/upload
  ```

---

## 🛠️ 命令行参数

```bash
python server.py -h
```

| 参数         | 描述                          | 默认值   |
|--------------|-------------------------------|----------|
| `-p`, `--port` | 服务器端口                    | `9999`   |
| `--https`    | 启用 HTTPS                    | `False`  |
| `-u`, `--username` | 认证用户名            | `admin`  |
| `--password` | 认证密码（默认随机生成）      | `None`   |

---

## 🎨 终端输出示例

启动服务器后，你会看到这样的漂亮输出：

```plaintext
╭──────────────────────────────╮
│          服务器配置           │
├───────────────┬──────────────┤
│ 配置项        │ 值           │
├───────────────┼──────────────┤
│ 用户名        │ admin        │
│ 密码          │ 随机生成     │
│ 端口          │ 8080         │
│ HTTPS         │ 禁用         │
╰───────────────┴──────────────╯
╭──────────────────────────────╮
│        按下 'Q' 停止服务器。        │
╰──────────────────────────────╯
```

---

## 🤔 常见问题

### 1. 如何启用 HTTPS？
启动服务器时加上 `--https` 参数即可：
```bash
python server.py -p 8443 --https
```

### 2. 如何停止服务器？
在终端按下 `Q` 并回车即可。

### 3. 为什么我的 Token 无效？
Token 默认有效期为 30 分钟，过期后需要重新登录获取。
