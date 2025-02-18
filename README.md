---

# Nanjing 🌐🔒

欢迎来到这个令人兴奋的迷你安全文件上传服务器！这是一个专为安全和简单而设计的小型 Web 服务器，支持文件上传，并且在每次上传文件时都会进行身份验证。你可以通过 HTTP 或 HTTPS 安全地上传文件，并且会收到详细的反馈信息。

## 🎯 功能

- **认证机制**：通过基本认证确保只有授权用户可以上传文件。
- **文件上传**：支持文件上传并且保存到服务器。上传时会显示文件的大小和保存路径。
- **HTTPS 支持**：为增强安全性，你可以启用 HTTPS，保证传输加密。
- **日志输出**：集成 `rich` 库，使得日志输出更加丰富美观。

## 🚀 快速开始

### 1. 克隆项目
首先，你需要将这个项目克隆到本地：

```bash
git clone https://github.com/yourusername/secure-upload-server.git
cd secure-upload-server
```

### 2. 安装依赖
确保你已经安装了 Python（推荐版本 3.x）。然后使用以下命令安装必需的依赖：

```bash
pip install -r requirements.txt
```

### 3. 启动服务器
启动服务器非常简单。你可以选择使用 HTTP 或 HTTPS，命令行参数允许你设置端口、用户名和密码。

#### 启动 HTTP 服务器：
```bash
python server.py -p 9999 -u admin -password yourpassword
```

#### 启动 HTTPS 服务器：
```bash
python server.py -p 9999 --https -u admin -password yourpassword
```

> **注意**: 如果启用 HTTPS，服务器将自动生成一个自签名证书（`server.pem`），你可以在需要时替换为正式证书。

### 4. 上传文件
现在你可以使用 `curl` 或任何支持 HTTP 请求的工具上传文件。

#### 使用 `curl` 上传文件：
```bash
curl -u "admin:yourpassword" -X POST -F "file=@/path/to/your/file" http://localhost:9999/uploads
```

### 5. 观察日志
每当你上传文件时，终端会美观地显示上传结果，包括文件大小、保存路径等。上传成功的消息会以绿色显示，错误则会以红色警告。

---

## 🔒 安全性

- **认证机制**：每个上传请求都需要通过基本认证进行身份验证。
- **防止目录遍历**：通过对文件路径的严格限制，避免文件上传过程中的安全隐患。
- **HTTPS 支持**：开启 HTTPS 后，所有上传的文件和敏感信息都将通过加密通道传输，保障安全。

## 💡 自定义

- 如果你想改变认证的用户名或密码，可以在启动服务器时通过命令行传入。
- 默认的文件保存路径为当前工作目录，但你可以修改代码来改变保存目录。
- 如果你希望记录更多的活动或错误日志，可以自定义 `logging` 设置。

---

## 👨‍💻 贡献

我们欢迎任何形式的贡献！如果你发现了 bug 或有任何改进建议，请提交 issue 或直接提交 PR。

---

## 🤔 FAQ

### 1. **如何检查上传文件是否成功？**
成功上传后，终端会显示“文件上传成功”以及文件的保存路径和大小信息。如果出错，会显示错误消息。

### 2. **服务器默认端口是什么？**
默认端口为 `9999`，你可以通过 `-p` 参数修改。

### 3. **是否支持大文件上传？**
是的，支持大文件上传。但要注意，上传文件大小受到服务器设置和操作系统限制。

---

**享受安全且有趣的文件上传体验！** 🎉
