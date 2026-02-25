#!/usr/bin/env python3
"""
HTTP服务器应用 - 内网地址功能版
支持内网地址配置和重定向
支持记住我功能
"""

import http.server
import sqlite3
import urllib.parse
import json
import secrets
import os
import hashlib
import time
from typing import Dict, Optional, List
import threading
import tempfile
import io
from datetime import datetime, timedelta
import socket

# ========== 图片类型检测兼容性 ==========
try:
    # 尝试导入filetype（推荐）
    import filetype
    HAS_FILETYPE = True
    print("✓ 使用 filetype 库进行图片类型检测")
except ImportError:
    # 尝试使用imghdr（Python < 3.11）
    try:
        import imghdr
        HAS_FILETYPE = False
        print("✓ 使用 imghdr 库进行图片类型检测")
    except ImportError:
        # Python 3.13+ 需要安装filetype
        print("✗ 错误: 需要安装 filetype 库")
        print("请运行: pip install filetype")
        exit(1)

def detect_image_type(filepath: str) -> Optional[str]:
    """
    检测图片类型，兼容不同Python版本
    返回MIME类型，如 'image/jpeg'
    """
    try:
        if HAS_FILETYPE:
            # 使用filetype库
            kind = filetype.guess(filepath)
            if kind is None or not kind.mime.startswith('image/'):
                return None
            return kind.mime
        else:
            # 使用imghdr库
            with open(filepath, 'rb') as f:
                img_type = imghdr.what(f)
            
            if img_type is None:
                return None
            
            # 将imghdr返回的类型转换为MIME类型
            mime_map = {
                'jpeg': 'image/jpeg',
                'jpg': 'image/jpeg',
                'png': 'image/png',
                'gif': 'image/gif',
                'bmp': 'image/bmp',
                'webp': 'image/webp',
                'tiff': 'image/tiff',
                'ppm': 'image/x-portable-pixmap'
            }
            return mime_map.get(img_type.lower(), None)
    except Exception as e:
        print(f"检测图片类型时出错: {e}")
        return None

# ========== multipart/form-data 解析器 ==========
def parse_multipart_form_data(headers, body):
    """解析multipart/form-data请求体"""
    # 从Content-Type获取boundary
    content_type = headers.get('Content-Type', '')
    if 'boundary=' not in content_type:
        return None, None
    
    boundary = content_type.split('boundary=')[1].strip()
    if boundary.startswith('"') and boundary.endswith('"'):
        boundary = boundary[1:-1]
    
    # 使用boundary分割请求体
    parts = body.split(b'--' + boundary.encode())
    
    data = {}
    files = {}
    
    for part in parts:
        if not part or part == b'--\r\n':
            continue
        
        # 分割头部和内容
        if b'\r\n\r\n' in part:
            header_part, content_part = part.split(b'\r\n\r\n', 1)
            headers_text = header_part.decode('utf-8', errors='ignore')
            
            # 解析头部
            content_disposition = None
            for line in headers_text.split('\r\n'):
                if line.lower().startswith('content-disposition:'):
                    content_disposition = line
                    break
            
            if content_disposition:
                # 提取字段名和文件名
                field_name = None
                filename = None
                
                # 解析Content-Disposition
                if 'name="' in content_disposition:
                    name_start = content_disposition.index('name="') + 6
                    name_end = content_disposition.index('"', name_start)
                    field_name = content_disposition[name_start:name_end]
                
                if 'filename="' in content_disposition:
                    file_start = content_disposition.index('filename="') + 10
                    file_end = content_disposition.index('"', file_start)
                    filename = content_disposition[file_start:file_end]
                
                # 去除内容末尾的\r\n
                if content_part.endswith(b'\r\n'):
                    content_part = content_part[:-2]
                
                # 存储数据
                if filename:
                    # 文件字段
                    files[field_name] = {
                        'filename': filename,
                        'data': content_part
                    }
                else:
                    # 普通字段
                    data[field_name] = content_part.decode('utf-8', errors='ignore')
    
    return data, files

# ========== 会话管理 ==========
class SessionManager:
    """会话管理器"""
    def __init__(self):
        self.sessions = {}  # token -> {username, expiry, client_ip, last_activity}
        self.session_timeout = 3600  # 1小时
        self.lock = threading.Lock()
    
    def create_session(self, username: str, client_ip: str = '') -> str:
        """创建新会话"""
        with self.lock:
            # 首先检查是否存在相同用户和IP的会话
            for token, session in self.sessions.items():
                if (session.get('username') == username and 
                    session.get('client_ip') == client_ip and
                    time.time() < session['expiry']):
                    # 更新现有会话的过期时间
                    session['expiry'] = time.time() + self.session_timeout
                    session['last_activity'] = time.time()
                    return token
            
            # 没有找到现有会话，创建新会话
            token = secrets.token_hex(32)
            expiry = time.time() + self.session_timeout
            
            self.sessions[token] = {
                'username': username,
                'expiry': expiry,
                'client_ip': client_ip,
                'last_activity': time.time(),
                'created_at': time.time()
            }
            
            return token
    
    def validate_session(self, token: str, client_ip: str = '') -> Optional[Dict]:
        """验证会话token，可选检查IP地址"""
        with self.lock:
            if token not in self.sessions:
                return None
            
            session = self.sessions[token]
            
            # 检查是否过期
            if time.time() > session['expiry']:
                del self.sessions[token]
                return None
            
            # 可选检查客户端IP是否匹配
            if client_ip and session.get('client_ip') and session['client_ip'] != client_ip:
                # IP不匹配，但仍然可以认为是有效会话（例如用户切换了网络）
                # 我们只是更新IP地址
                session['client_ip'] = client_ip
            
            # 更新最后活动时间和过期时间
            session['last_activity'] = time.time()
            session['expiry'] = time.time() + self.session_timeout
            
            return session
    
    def destroy_session(self, token: str):
        """销毁会话"""
        with self.lock:
            if token in self.sessions:
                del self.sessions[token]
    
    def cleanup_expired(self):
        """清理过期会话"""
        with self.lock:
            current_time = time.time()
            expired_tokens = [
                token for token, session in self.sessions.items()
                if current_time > session['expiry']
            ]
            for token in expired_tokens:
                del self.sessions[token]
    
    def get_session_count(self) -> int:
        """获取活跃会话数量（基于唯一用户-IP对）"""
        with self.lock:
            # 创建用户-IP组合的集合
            user_ip_pairs = set()
            current_time = time.time()
            
            for session in self.sessions.values():
                if current_time <= session['expiry']:
                    user_ip_pair = f"{session.get('username', '')}-{session.get('client_ip', '')}"
                    user_ip_pairs.add(user_ip_pair)
            
            return len(user_ip_pairs)
    
    def get_active_sessions_info(self) -> List[Dict]:
        """获取活跃会话信息"""
        with self.lock:
            sessions_info = []
            current_time = time.time()
            
            for token, session in self.sessions.items():
                if current_time <= session['expiry']:
                    sessions_info.append({
                        'username': session.get('username', ''),
                        'client_ip': session.get('client_ip', ''),
                        'last_activity': datetime.fromtimestamp(session.get('last_activity', 0)).strftime('%Y-%m-%d %H:%M:%S'),
                        'expires_in': int(session['expiry'] - current_time),
                        'token_prefix': token[:8] + '...'
                    })
            
            return sessions_info

# ========== 密码加密 ==========
def generate_salt() -> str:
    """生成随机盐值"""
    return secrets.token_hex(16)

def hash_password(password: str, salt: str) -> str:
    """哈希密码（使用盐值）"""
    salted_password = password + salt
    for _ in range(1000):
        salted_password = hashlib.sha256(salted_password.encode()).hexdigest()
    return salted_password

def verify_password(password: str, salt: str, hashed_password: str) -> bool:
    """验证密码"""
    return hash_password(password, salt) == hashed_password

# ========== 数据库配置 ==========
def get_db_path():
    """获取数据库文件路径"""
    db_path = os.getenv('DB_PATH', 'app_config.db')
    return db_path

def init_database():
    """初始化SQLite数据库"""
    db_path = get_db_path()
    print(f"数据库文件路径: {os.path.abspath(db_path)}")
    
    # 确保目录存在
    db_dir = os.path.dirname(db_path)
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir)
    
    # 确保背景图片目录存在
    bg_dir = 'backgrounds'
    if not os.path.exists(bg_dir):
        os.makedirs(bg_dir)
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # 修改应用配置表，添加lan_addr字段
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS app_config (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            app_name TEXT UNIQUE NOT NULL,
            ip TEXT NOT NULL,
            port INTEGER NOT NULL,
            lan_addr TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # 创建背景图片配置表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS background_config (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            original_name TEXT NOT NULL,
            mime_type TEXT,
            file_size INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT 1
        )
    ''')
    
    # 创建用户表，添加remember_token字段
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            is_admin BOOLEAN DEFAULT 0,
            remember_token TEXT,
            remember_token_expiry TIMESTAMP
        )
    ''')
    
    # 创建索引
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_app_name ON app_config(app_name)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_bg_active ON background_config(is_active)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_username ON users(username)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_remember_token ON users(remember_token)')
    
    conn.commit()
    conn.close()
    print(f"✓ 数据库初始化完成")

# ========== 认证配置 ==========
class AuthConfig:
    """认证配置类"""
    def __init__(self):
        # 从环境变量读取配置，或使用默认值
        self.api_keys = self.load_api_keys()
        self.enable_auth = os.getenv('ENABLE_AUTH', 'true').lower() == 'true'
        
    def load_api_keys(self) -> Dict[str, Dict]:
        """加载API密钥"""
        # 从环境变量读取API密钥
        api_key_env = os.getenv('API_KEY', '')
        keys = {}
        
        if api_key_env:
            # 支持多个API密钥，用逗号分隔
            for key in api_key_env.split(','):
                if key.strip():
                    keys[key.strip()] = {
                        'name': 'admin',
                        'permissions': 'write,delete',
                        'created_at': 'from_env'
                    }
        else:
            # 如果没有配置，生成一个默认的API密钥（仅用于开发）
            default_key = secrets.token_hex(16)
            keys[default_key] = {
                'name': 'default_admin',
                'permissions': 'write,delete',
                'created_at': 'generated'
            }
            print(f"\n⚠️  警告: 使用默认API密钥（仅用于开发环境）")
            print(f"API密钥: {default_key}")
            print(f"请通过环境变量API_KEY配置您的密钥\n")
        
        return keys
    
    def validate_api_key(self, api_key: str) -> bool:
        """验证API密钥"""
        if not self.enable_auth:
            return True
            
        if not api_key:
            return False
            
        return api_key in self.api_keys

# ========== 记住我令牌管理 ==========
class RememberMeTokenManager:
    """记住我令牌管理器"""
    
    @staticmethod
    def generate_remember_token() -> str:
        """生成记住我令牌"""
        return secrets.token_hex(32)
    
    @staticmethod
    def get_remember_token_expiry(days: int = 30):
        """获取记住我令牌过期时间"""
        return datetime.now() + timedelta(days=days)
    
    @staticmethod
    def is_token_expired(expiry_str: str) -> bool:
        """检查令牌是否过期"""
        try:
            expiry = datetime.fromisoformat(expiry_str)
            return datetime.now() > expiry
        except:
            return True

# ========== 请求处理器 ==========
class AppConfigHandler(http.server.BaseHTTPRequestHandler):
    """自定义HTTP请求处理器"""
    
    # 认证配置实例
    auth_config = AuthConfig()
    
    # 会话管理器
    session_manager = SessionManager()
    
    # 令牌管理器
    token_manager = RememberMeTokenManager()
    
    # 允许的文件类型
    ALLOWED_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'}
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
    
    def get_client_ip(self):
        """获取客户端IP地址"""
        # 尝试从X-Forwarded-For获取（如果使用反向代理）
        forwarded_for = self.headers.get('X-Forwarded-For')
        if forwarded_for:
            # 取第一个IP
            return forwarded_for.split(',')[0].strip()
        
        # 否则使用连接IP
        return self.client_address[0]
    
    def get_db_connection(self):
        """获取数据库连接"""
        db_path = get_db_path()
        return sqlite3.connect(db_path)
    
    def do_GET(self):
        """处理GET请求"""
        try:
            # 解析URL
            parsed_url = urllib.parse.urlparse(self.path)
            path = parsed_url.path
            query_params = urllib.parse.parse_qs(parsed_url.query)
            
            # 路由处理
            if path == '/setAppIpAndPort':
                self.handle_set_app_ip_port(query_params)
            elif path == '/getAppIpAndPort':
                self.handle_get_app_ip_port(query_params)
            elif path == '/deleteAppIpAndPort':
                self.handle_delete_app_ip_port(query_params)
            elif path == '/setUsernameAndPasswd':
                self.handle_set_username_password(query_params)
            elif path == '/login':
                self.handle_login_page()
            elif path == '/logout':
                self.handle_logout()
            elif path == '/background':
                self.handle_get_background(query_params)
            elif path == '/upload-background':
                self.handle_upload_page()
            elif path == '/api-docs':
                self.handle_api_docs()
            elif path == '/validate-token':
                self.handle_validate_token()
            elif path == '/session-stats':
                self.handle_session_stats()
            elif path == '/':
                self.handle_root(query_params)
            else:
                self.send_response(404)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.end_headers()
                self.wfile.write(b"<h1>404 Not Found</h1>")
        except Exception as e:
            print(f"处理GET请求时出错: {e}")
            self.send_response(500)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(f"<h1>500 Internal Server Error</h1><p>{str(e)}</p>".encode('utf-8'))
    
    def do_POST(self):
        """处理POST请求"""
        try:
            # 解析URL
            parsed_url = urllib.parse.urlparse(self.path)
            path = parsed_url.path
            
            # 路由处理
            if path == '/login':
                self.handle_login_submit()
            elif path == '/upload-background':
                self.handle_upload_background()
            else:
                self.send_response(404)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.end_headers()
                self.wfile.write(b"<h1>404 Not Found</h1>")
        except Exception as e:
            print(f"处理POST请求时出错: {e}")
            self.send_response(500)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(f"<h1>500 Internal Server Error</h1><p>{str(e)}</p>".encode('utf-8'))
    
    def get_session(self):
        """从cookie获取会话"""
        cookie_header = self.headers.get('Cookie', '')
        cookies = {}
        
        if cookie_header:
            for cookie in cookie_header.split(';'):
                cookie = cookie.strip()
                if '=' in cookie:
                    key, value = cookie.split('=', 1)
                    cookies[key] = value
        
        session_token = cookies.get('session_token', '')
        client_ip = self.get_client_ip()
        
        if session_token:
            # 验证会话时传入客户端IP
            session = self.session_manager.validate_session(session_token, client_ip)
            if session:
                session['token'] = session_token
                return session
        
        # 如果没有有效的session，检查remember_me_token
        remember_token = cookies.get('remember_me_token', '')
        if remember_token:
            user = self.validate_remember_token(remember_token)
            if user:
                # 创建新的会话，传入客户端IP
                new_session_token = self.session_manager.create_session(user['username'], client_ip)
                session = self.session_manager.validate_session(new_session_token, client_ip)
                if session:
                    session['token'] = new_session_token
                    return session
        
        return None
    
    def validate_remember_token(self, token: str) -> Optional[Dict]:
        """验证记住我令牌"""
        try:
            conn = self.get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT username, remember_token_expiry 
                FROM users WHERE remember_token = ?
            ''', (token,))
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                username, expiry_str = row
                
                # 检查令牌是否过期
                if not self.token_manager.is_token_expired(expiry_str):
                    return {
                        "username": username,
                        "remember_token": token
                    }
            
            return None
            
        except sqlite3.Error as e:
            print(f"数据库查询错误: {e}")
            return None
    
    def set_session_cookie(self, token: str, remember_me: bool = False):
        """设置会话cookie"""
        if remember_me:
            # 记住我：设置30天过期
            expires = datetime.now() + timedelta(days=30)
            expires_str = expires.strftime('%a, %d %b %Y %H:%M:%S GMT')
            self.send_header('Set-Cookie', 
                           f'session_token={token}; HttpOnly; Path=/; Expires={expires_str}; Max-Age=2592000; SameSite=Lax')
        else:
            # 普通会话：会话级别（浏览器关闭后失效）
            self.send_header('Set-Cookie', 
                           f'session_token={token}; HttpOnly; Path=/; SameSite=Lax')
    
    def set_remember_me_cookie(self, token: str):
        """设置记住我cookie"""
        expires = datetime.now() + timedelta(days=30)
        expires_str = expires.strftime('%a, %d %b %Y %H:%M:%S GMT')
        self.send_header('Set-Cookie', 
                       f'remember_me_token={token}; HttpOnly; Path=/; Expires={expires_str}; Max-Age=2592000; SameSite=Lax')
    
    def clear_session_cookies(self):
        """清除所有会话相关的cookie"""
        # 清除session_token
        self.send_header('Set-Cookie', 
                       'session_token=; HttpOnly; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; SameSite=Lax')
        # 清除remember_me_token
        self.send_header('Set-Cookie', 
                       'remember_me_token=; HttpOnly; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; SameSite=Lax')
    
    def authenticate_request(self, query_params: Dict) -> Optional[Dict]:
        """认证请求，返回错误响应或None"""
        # 从查询参数获取API密钥
        api_key = query_params.get('apiKey', [None])[0]
        
        # 如果没有API密钥，检查请求头
        if not api_key:
            api_key = self.headers.get('X-API-Key')
        
        # 检查认证是否启用
        if not self.auth_config.enable_auth:
            return None
        
        # 验证API密钥
        if not api_key:
            return {
                "status": "error",
                "message": "缺少API密钥。请提供apiKey参数或X-API-Key请求头",
                "error_code": "MISSING_API_KEY"
            }
        
        if not self.auth_config.validate_api_key(api_key):
            return {
                "status": "error",
                "message": "API密钥无效",
                "error_code": "INVALID_API_KEY"
            }
        
        return None
    
    def handle_session_stats(self):
        """处理会话统计接口"""
        try:
            active_sessions = self.session_manager.get_session_count()
            sessions_info = self.session_manager.get_active_sessions_info()
            
            response = {
                "status": "success",
                "data": {
                    "active_sessions": active_sessions,
                    "sessions": sessions_info,
                    "total_tokens": len(self.session_manager.sessions)
                }
            }
            
            self.send_json_response(200, response)
            
        except Exception as e:
            print(f"获取会话统计时发生错误: {e}")
            self.send_json_response(500, {
                "status": "error",
                "message": f"服务器内部错误: {str(e)}"
            })
    
    def handle_validate_token(self):
        """处理令牌验证接口"""
        try:
            # 从cookie获取令牌
            cookie_header = self.headers.get('Cookie', '')
            cookies = {}
            
            if cookie_header:
                for cookie in cookie_header.split(';'):
                    cookie = cookie.strip()
                    if '=' in cookie:
                        key, value = cookie.split('=', 1)
                        cookies[key] = value
            
            session_token = cookies.get('session_token', '')
            remember_token = cookies.get('remember_me_token', '')
            client_ip = self.get_client_ip()
            
            # 验证session token
            if session_token:
                session = self.session_manager.validate_session(session_token, client_ip)
                if session:
                    self.send_json_response(200, {
                        "status": "success",
                        "message": "会话有效",
                        "data": {
                            "username": session['username'],
                            "token_type": "session",
                            "client_ip": client_ip
                        }
                    })
                    return
            
            # 验证remember me token
            if remember_token:
                user = self.validate_remember_token(remember_token)
                if user:
                    # 创建新会话
                    new_session_token = self.session_manager.create_session(user['username'], client_ip)
                    
                    # 返回成功响应
                    response = {
                        "status": "success",
                        "message": "记住我令牌有效，已创建新会话",
                        "data": {
                            "username": user['username'],
                            "token_type": "remember_me",
                            "session_token": new_session_token,
                            "client_ip": client_ip
                        }
                    }
                    
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json; charset=utf-8')
                    self.set_session_cookie(new_session_token)
                    self.end_headers()
                    
                    self.wfile.write(json.dumps(response).encode('utf-8'))
                    return
            
            # 没有有效的令牌
            self.send_json_response(401, {
                "status": "error",
                "message": "令牌无效或已过期",
                "error_code": "INVALID_TOKEN"
            })
            
        except Exception as e:
            print(f"令牌验证时发生错误: {e}")
            self.send_json_response(500, {
                "status": "error",
                "message": f"服务器内部错误: {str(e)}"
            })
    
    def handle_set_username_password(self, params: Dict[str, list]):
        """处理setUsernameAndPasswd接口 - 需要API密钥认证"""
        # 首先进行API密钥认证
        auth_error = self.authenticate_request(params)
        if auth_error:
            self.send_json_response(401, auth_error)
            return
        
        try:
            # 验证参数
            if not all(key in params for key in ['username', 'passwd']):
                raise ValueError("缺少必要参数：username, passwd")
            
            username = params['username'][0]
            password = params['passwd'][0]
            
            # 验证用户名和密码
            if not username or len(username) < 3:
                raise ValueError("用户名至少需要3个字符")
            
            if not password or len(password) < 6:
                raise ValueError("密码至少需要6个字符")
            
            # 检查用户是否已存在
            existing_user = self.get_user(username)
            if existing_user:
                response = {
                    "status": "error",
                    "message": f"用户 {username} 已存在"
                }
                self.send_json_response(400, response)
                return
            
            # 生成盐值并哈希密码
            salt = generate_salt()
            password_hash = hash_password(password, salt)
            
            # 保存到数据库
            result = self.save_user(username, password_hash, salt)
            
            if result:
                response = {
                    "status": "success",
                    "message": f"用户 {username} 创建成功",
                    "data": {
                        "username": username,
                        "created_at": time.strftime('%Y-%m-%d %H:%M:%S')
                    }
                }
                self.send_json_response(200, response)
            else:
                response = {
                    "status": "error",
                    "message": f"创建用户 {username} 失败"
                }
                self.send_json_response(500, response)
                
        except ValueError as e:
            response = {
                "status": "error",
                "message": str(e)
            }
            self.send_json_response(400, response)
        except Exception as e:
            response = {
                "status": "error",
                "message": f"服务器内部错误: {str(e)}"
            }
            self.send_json_response(500, response)
    
    def handle_login_page(self):
        """显示登录页面"""
        html_content = '''
        <!DOCTYPE html>
        <html lang="zh-CN">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>登录 - My Apps Panel</title>
            <style>
                * {
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                }
                
                body {
                    font-family: -apple-system, BlinkMacSystemFont, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    padding: 20px;
                }
                
                .login-container {
                    background: rgba(255, 255, 255, 0.95);
                    border-radius: 15px;
                    box-shadow: 0 10px 30px rgba(0,0,0,0.2);
                    padding: 40px;
                    width: 100%;
                    max-width: 400px;
                    backdrop-filter: blur(10px);
                }
                
                h1 {
                    color: #333;
                    margin-bottom: 10px;
                    text-align: center;
                }
                
                .subtitle {
                    color: #666;
                    text-align: center;
                    margin-bottom: 30px;
                }
                
                .form-group {
                    margin-bottom: 20px;
                }
                
                label {
                    display: block;
                    margin-bottom: 8px;
                    color: #555;
                    font-weight: 500;
                }
                
                input[type="text"],
                input[type="password"] {
                    width: 100%;
                    padding: 12px;
                    border: 2px solid #e2e8f0;
                    border-radius: 8px;
                    font-size: 16px;
                    transition: all 0.3s;
                }
                
                input[type="text"]:focus,
                input[type="password"]:focus {
                    outline: none;
                    border-color: #667eea;
                    box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
                }
                
                .remember-me {
                    display: flex;
                    align-items: center;
                    margin-bottom: 20px;
                }
                
                .remember-me input[type="checkbox"] {
                    margin-right: 8px;
                    width: 16px;
                    height: 16px;
                }
                
                .remember-me label {
                    margin-bottom: 0;
                    cursor: pointer;
                }
                
                .btn {
                    width: 100%;
                    padding: 14px;
                    background: #667eea;
                    color: white;
                    border: none;
                    border-radius: 8px;
                    font-size: 16px;
                    font-weight: 600;
                    cursor: pointer;
                    transition: all 0.3s;
                    margin-top: 10px;
                }
                
                .btn:hover {
                    background: #5a67d8;
                    transform: translateY(-2px);
                    box-shadow: 0 5px 15px rgba(0,0,0,0.1);
                }
                
                .error-message {
                    background: #fed7d7;
                    color: #e53e3e;
                    padding: 10px;
                    border-radius: 8px;
                    margin-bottom: 20px;
                    display: none;
                }
                
                .success-message {
                    background: #c6f6d5;
                    color: #38a169;
                    padding: 10px;
                    border-radius: 8px;
                    margin-bottom: 20px;
                    display: none;
                }
                
                .login-footer {
                    text-align: center;
                    margin-top: 20px;
                    color: #718096;
                    font-size: 14px;
                }
                
                .logo {
                    text-align: center;
                    margin-bottom: 20px;
                    font-size: 48px;
                }
                
                .info-tip {
                    font-size: 12px;
                    color: #718096;
                    margin-top: 5px;
                }
            </style>
        </head>
        <body>
            <div class="login-container">
                <div class="logo">🔐</div>
                <h1>My Apps Panel</h1>
                <p class="subtitle">请输入用户名和密码登录</p>
                
                <div class="error-message" id="errorMessage"></div>
                <div class="success-message" id="successMessage"></div>
                
                <form id="loginForm">
                    <div class="form-group">
                        <label for="username">用户名</label>
                        <input type="text" id="username" name="username" 
                               placeholder="请输入用户名" required autofocus>
                    </div>
                    
                    <div class="form-group">
                        <label for="password">密码</label>
                        <input type="password" id="password" name="password" 
                               placeholder="请输入密码" required>
                    </div>
                    
                    <div class="remember-me">
                        <input type="checkbox" id="remember" name="remember" value="1">
                        <label for="remember">记住我</label>
                    </div>
                    <div class="info-tip">勾选后30天内无需重新登录</div>
                    
                    <button type="submit" class="btn">登录</button>
                </form>
                
                <div class="login-footer">
                    <p>没有账户？请联系管理员创建</p>
                </div>
            </div>
            
            <script>
                // 检查是否已有记住我令牌
                document.addEventListener('DOMContentLoaded', function() {
                    checkRememberMeToken();
                });
                
                async function checkRememberMeToken() {
                    try {
                        const response = await fetch('/validate-token', {
                            method: 'GET',
                            credentials: 'same-origin'
                        });
                        
                        if (response.ok) {
                            const data = await response.json();
                            if (data.status === 'success') {
                                // 令牌有效，跳转到首页
                                window.location.href = '/';
                            }
                        }
                    } catch (error) {
                        // 忽略错误，继续显示登录页面
                        console.log('未找到有效令牌，显示登录页面');
                    }
                }
                
                document.getElementById('loginForm').addEventListener('submit', async function(e) {
                    e.preventDefault();
                    
                    const username = document.getElementById('username').value.trim();
                    const password = document.getElementById('password').value;
                    const rememberMe = document.getElementById('remember').checked;
                    const errorDiv = document.getElementById('errorMessage');
                    const successDiv = document.getElementById('successMessage');
                    
                    // 隐藏消息
                    errorDiv.style.display = 'none';
                    successDiv.style.display = 'none';
                    
                    // 验证输入
                    if (!username || !password) {
                        showError('请输入用户名和密码');
                        return;
                    }
                    
                    try {
                        // 显示加载状态
                        const submitBtn = this.querySelector('button[type="submit"]');
                        const originalText = submitBtn.textContent;
                        submitBtn.textContent = '登录中...';
                        submitBtn.disabled = true;
                        
                        // 发送登录请求
                        const response = await fetch('/login', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                            },
                            body: JSON.stringify({
                                username: username,
                                password: password,
                                remember_me: rememberMe
                            })
                        });
                        
                        const data = await response.json();
                        
                        if (response.ok) {
                            showSuccess('登录成功！正在跳转...');
                            // 跳转到主页
                            setTimeout(() => {
                                window.location.href = '/';
                            }, 1000);
                        } else {
                            showError(data.message || '登录失败');
                        }
                    } catch (error) {
                        showError('网络错误，请重试');
                        console.error('登录错误:', error);
                    } finally {
                        // 恢复按钮状态
                        const submitBtn = document.querySelector('button[type="submit"]');
                        submitBtn.textContent = originalText;
                        submitBtn.disabled = false;
                    }
                });
                
                function showError(message) {
                    const errorDiv = document.getElementById('errorMessage');
                    errorDiv.textContent = message;
                    errorDiv.style.display = 'block';
                }
                
                function showSuccess(message) {
                    const successDiv = document.getElementById('successMessage');
                    successDiv.textContent = message;
                    successDiv.style.display = 'block';
                }
                
                // 按Enter键提交
                document.addEventListener('keypress', function(e) {
                    if (e.key === 'Enter' && e.target.type !== 'submit') {
                        document.getElementById('loginForm').requestSubmit();
                    }
                });
            </script>
        </body>
        </html>
        '''
        
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(html_content.encode('utf-8'))))
        self.end_headers()
        self.wfile.write(html_content.encode('utf-8'))
    
    def handle_login_submit(self):
        """处理登录提交"""
        try:
            # 读取请求体
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            
            # 解析JSON
            data = json.loads(post_data.decode('utf-8'))
            username = data.get('username', '')
            password = data.get('password', '')
            remember_me = data.get('remember_me', False)
            
            # 验证用户
            user = self.get_user(username)
            if not user:
                self.send_json_response(401, {
                    "status": "error",
                    "message": "用户名或密码错误"
                })
                return
            
            # 验证密码
            if not verify_password(password, user['salt'], user['password_hash']):
                self.send_json_response(401, {
                    "status": "error",
                    "message": "用户名或密码错误"
                })
                return
            
            # 更新最后登录时间
            self.update_last_login(username)
            
            # 如果选择了记住我，生成记住我令牌
            if remember_me:
                remember_token = self.token_manager.generate_remember_token()
                remember_expiry = self.token_manager.get_remember_token_expiry()
                
                # 保存令牌到数据库
                self.save_remember_token(username, remember_token, remember_expiry)
            else:
                remember_token = None
            
            # 创建会话，传入客户端IP
            client_ip = self.get_client_ip()
            session_token = self.session_manager.create_session(username, client_ip)
            
            # 返回成功响应
            response = {
                "status": "success",
                "message": "登录成功",
                "data": {
                    "username": username,
                    "remember_me": remember_me,
                    "client_ip": client_ip
                }
            }
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.set_session_cookie(session_token, remember_me)
            if remember_me and remember_token:
                self.set_remember_me_cookie(remember_token)
            self.end_headers()
            self.wfile.write(json.dumps(response).encode('utf-8'))
            
        except json.JSONDecodeError:
            self.send_json_response(400, {
                "status": "error",
                "message": "无效的JSON数据"
            })
        except Exception as e:
            print(f"登录处理时发生错误: {e}")
            self.send_json_response(500, {
                "status": "error",
                "message": f"服务器内部错误: {str(e)}"
            })
    
    def handle_logout(self):
        """处理登出"""
        session = self.get_session()
        if session:
            self.session_manager.destroy_session(session.get('token', ''))
            
            # 清除数据库中的记住我令牌
            username = session.get('username', '')
            if username:
                self.clear_remember_token(username)
        
        # 重定向到登录页面
        self.send_response(302)
        self.clear_session_cookies()
        self.send_header('Location', '/login')
        self.end_headers()
    
    def get_user(self, username: str) -> Optional[Dict]:
        """获取用户信息"""
        try:
            conn = self.get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT username, password_hash, salt, created_at, is_admin, 
                       remember_token, remember_token_expiry
                FROM users WHERE username = ?
            ''', (username,))
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return {
                    "username": row[0],
                    "password_hash": row[1],
                    "salt": row[2],
                    "created_at": row[3],
                    "is_admin": bool(row[4]),
                    "remember_token": row[5],
                    "remember_token_expiry": row[6]
                }
            return None
            
        except sqlite3.Error as e:
            print(f"数据库查询错误: {e}")
            return None
    
    def save_user(self, username: str, password_hash: str, salt: str) -> bool:
        """保存用户到数据库"""
        try:
            conn = self.get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO users (username, password_hash, salt)
                VALUES (?, ?, ?)
            ''', (username, password_hash, salt))
            
            conn.commit()
            conn.close()
            return True
            
        except sqlite3.Error as e:
            print(f"数据库错误: {e}")
            return False
    
    def update_last_login(self, username: str):
        """更新用户最后登录时间"""
        try:
            conn = self.get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE users SET last_login = CURRENT_TIMESTAMP
                WHERE username = ?
            ''', (username,))
            
            conn.commit()
            conn.close()
            
        except sqlite3.Error as e:
            print(f"更新最后登录时间失败: {e}")
    
    def save_remember_token(self, username: str, token: str, expiry: datetime):
        """保存记住我令牌到数据库"""
        try:
            conn = self.get_db_connection()
            cursor = conn.cursor()
            
            expiry_str = expiry.isoformat()
            
            cursor.execute('''
                UPDATE users 
                SET remember_token = ?, remember_token_expiry = ?
                WHERE username = ?
            ''', (token, expiry_str, username))
            
            conn.commit()
            conn.close()
            
        except sqlite3.Error as e:
            print(f"保存记住我令牌失败: {e}")
    
    def clear_remember_token(self, username: str):
        """清除用户的记住我令牌"""
        try:
            conn = self.get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE users 
                SET remember_token = NULL, remember_token_expiry = NULL
                WHERE username = ?
            ''', (username,))
            
            conn.commit()
            conn.close()
            
        except sqlite3.Error as e:
            print(f"清除记住我令牌失败: {e}")
    
    def handle_root(self, params: Dict[str, list]):
        """处理根路径请求 - 需要登录"""
        # 检查用户是否已登录
        session = self.get_session()
        
        if not session:
            # 未登录，重定向到登录页面
            self.send_response(302)
            self.send_header('Location', '/login')
            self.end_headers()
            return
        
        # 用户已登录，继续处理
        try:
            # 检查是否请求JSON格式（API调用）
            accept_header = self.headers.get('Accept', '')
            if 'application/json' in accept_header or params.get('format', [''])[0] == 'json':
                # 对于JSON请求，仍然需要API密钥认证
                auth_error = self.authenticate_request(params)
                if auth_error:
                    self.send_json_response(401, auth_error)
                    return
                
                # 返回JSON格式
                all_apps = self.get_all_apps()
                response = {
                    "status": "success",
                    "message": "App Config HTTP Server",
                    "user": session['username'],
                    "client_ip": self.get_client_ip(),
                    "database_path": os.path.abspath(get_db_path()),
                    "apis": {
                        "setAppIpAndPort": "GET /setAppIpAndPort?appName=xxx&ip=xxx&port=xxx&lanAddr=xxx&apiKey=xxx",
                        "deleteAppIpAndPort": "GET /deleteAppIpAndPort?appName=xxx&apiKey=xxx",
                        "getAppIpAndPort": "GET /getAppIpAndPort?appName=xxx&type=lan/wan",
                        "setUsernameAndPasswd": "GET /setUsernameAndPasswd?username=xxx&passwd=xxx&apiKey=xxx"
                    },
                    "apps": all_apps,
                    "total_apps": len(all_apps)
                }
                self.send_json_response(200, response)
                return
            
            # 返回HTML页面
            all_apps = self.get_all_apps()
            bg_info = self.get_active_background()
            
            html_content = self.generate_html_page(all_apps, bg_info, session['username'])
            
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(html_content.encode('utf-8'))))
            self.end_headers()
            
            self.wfile.write(html_content.encode('utf-8'))
            
        except Exception as e:
            print(f"处理根路径请求时发生错误: {e}")
            self.send_response(500)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(f"<h1>500 Internal Server Error</h1><p>{str(e)}</p>".encode('utf-8'))
    
    def get_all_apps(self) -> List[Dict]:
        """获取所有应用配置"""
        try:
            conn = self.get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT app_name, ip, port, lan_addr FROM app_config
                ORDER BY app_name ASC
            ''')
            
            rows = cursor.fetchall()
            conn.close()
            
            apps = []
            for row in rows:
                app = {
                    "appName": row[0],
                    "ip": row[1],
                    "port": row[2],
                    "url": f"http://{row[1]}:{row[2]}"
                }
                # 如果有内网地址，则添加内网地址字段
                if row[3]:
                    app["lan_addr"] = row[3]
                    app["lan_url"] = f"http://{row[3]}"
                apps.append(app)
            return apps
            
        except sqlite3.Error as e:
            print(f"数据库查询错误: {e}")
            return []
    
    def get_active_background(self) -> Optional[Dict]:
        """获取当前活跃的背景图片"""
        try:
            conn = self.get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT filename, original_name, created_at 
                FROM background_config 
                WHERE is_active = 1 
                ORDER BY created_at DESC 
                LIMIT 1
            ''')
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return {
                    "filename": row[0],
                    "original_name": row[1],
                    "created_at": row[2]
                }
            return None
            
        except sqlite3.Error as e:
            print(f"数据库查询错误: {e}")
            return None
    
    def handle_upload_page(self):
        """显示上传页面 - 需要登录"""
        # 检查用户是否已登录
        session = self.get_session()
        
        if not session:
            # 未登录，重定向到登录页面
            self.send_response(302)
            self.send_header('Location', '/login')
            self.end_headers()
            return
        
        # 获取当前用户名
        username = session['username']
        
        # 显示上传页面
        html_content = f'''
        <!DOCTYPE html>
        <html lang="zh-CN">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>上传背景图片</title>
            <style>
                * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                body {{ 
                    font-family: -apple-system, BlinkMacSystemFont, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    padding: 20px;
                }}
                .container {{
                    background: white;
                    border-radius: 15px;
                    box-shadow: 0 10px 30px rgba(0,0,0,0.2);
                    padding: 40px;
                    width: 100%;
                    max-width: 500px;
                }}
                h1 {{ 
                    color: #333; 
                    margin-bottom: 20px;
                    text-align: center;
                }}
                .form-group {{
                    margin-bottom: 20px;
                }}
                label {{
                    display: block;
                    margin-bottom: 8px;
                    color: #555;
                    font-weight: 500;
                }}
                input[type="file"] {{
                    width: 100%;
                    padding: 12px;
                    border: 2px dashed #ddd;
                    border-radius: 8px;
                    background: #f9f9f9;
                    cursor: pointer;
                    transition: all 0.3s;
                }}
                input[type="file"]:hover {{
                    border-color: #667eea;
                    background: #f0f4ff;
                }}
                .btn {{
                    width: 100%;
                    padding: 14px;
                    background: #667eea;
                    color: white;
                    border: none;
                    border-radius: 8px;
                    font-size: 16px;
                    font-weight: 600;
                    cursor: pointer;
                    transition: all 0.3s;
                    margin-top: 10px;
                }}
                .btn:hover {{
                    background: #5a67d8;
                    transform: translateY(-2px);
                    box-shadow: 0 5px 15px rgba(0,0,0,0.1);
                }}
                .btn-secondary {{
                    background: #718096;
                }}
                .btn-secondary:hover {{
                    background: #4a5568;
                }}
                .preview {{
                    margin-top: 20px;
                    text-align: center;
                }}
                .preview img {{
                    max-width: 100%;
                    max-height: 200px;
                    border-radius: 8px;
                    border: 2px solid #ddd;
                    margin-top: 10px;
                }}
                .error {{
                    color: #e53e3e;
                    background: #fed7d7;
                    padding: 10px;
                    border-radius: 8px;
                    margin-top: 10px;
                    display: none;
                }}
                .success {{
                    color: #38a169;
                    background: #c6f6d5;
                    padding: 10px;
                    border-radius: 8byte;
                    margin-top: 10px;
                    display: none;
                }}
                .file-info {{
                    background: #f7fafc;
                    padding: 10px;
                    border-radius: 8px;
                    margin-top: 10px;
                    font-size: 14px;
                    color: #4a5568;
                }}
                .back-link {{
                    display: inline-block;
                    margin-top: 20px;
                    color: #667eea;
                    text-decoration: none;
                }}
                .back-link:hover {{
                    text-decoration: underline;
                }}
                .user-info {{
                    text-align: center;
                    margin-bottom: 20px;
                    padding: 10px;
                    background: #f0f4ff;
                    border-radius: 8px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="user-info">
                    <strong>当前用户:</strong> {username}
                </div>
                
                <h1>🎨 上传背景图片</h1>
                <p style="text-align: center; color: #666; margin-bottom: 20px;">
                    上传自定义壁纸作为页面背景
                </p>
                
                <div class="error" id="errorMessage"></div>
                <div class="success" id="successMessage"></div>
                
                <form id="uploadForm">
                    <div class="form-group">
                        <label for="backgroundFile">选择背景图片:</label>
                        <input type="file" id="backgroundFile" name="file" 
                               accept=".jpg,.jpeg,.png,.gif,.bmp,.webp" required>
                        <div class="file-info">
                            支持格式: JPG, PNG, GIF, BMP, WebP<br>
                            最大大小: 10MB
                        </div>
                    </div>
                    
                    <div class="preview" id="previewContainer">
                        <div id="imagePreview"></div>
                    </div>
                    
                    <button type="submit" class="btn" id="uploadBtn">📤 上传背景</button>
                    <a href="/" class="btn btn-secondary">← 返回主页</a>
                </form>
                
                <div class="current-bg" style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #e2e8f0;">
                    <h3>当前背景:</h3>
                    <div id="currentBackground" style="margin-top: 10px;">
                        加载中...
                    </div>
                </div>
            </div>
            
            <script>
                // 图片预览
                document.getElementById('backgroundFile').addEventListener('change', function(e) {{
                    const file = e.target.files[0];
                    const preview = document.getElementById('imagePreview');
                    
                    if (file) {{
                        const reader = new FileReader();
                        reader.onload = function(e) {{
                            preview.innerHTML = `<img src="${{e.target.result}}" alt="预览">`;
                        }}
                        reader.readAsDataURL(file);
                    }} else {{
                        preview.innerHTML = '';
                    }}
                }});
                
                // 获取当前背景
                async function loadCurrentBackground() {{
                    try {{
                        const response = await fetch('/background?info=1&t=' + Date.now());
                        if (response.ok) {{
                            const data = await response.json();
                            const container = document.getElementById('currentBackground');
                            if (data.has_background) {{
                                container.innerHTML = `
                                    <div style="display: flex; align-items: center; gap: 15px;">
                                        <img src="/background?t=${{Date.now()}}" style="width: 100px; height: 60px; object-fit: cover; border-radius: 5px;">
                                        <div>
                                            <strong>${{data.original_name}}</strong><br>
                                            <small>上传时间: ${{new Date(data.created_at).toLocaleString()}}</small>
                                        </div>
                                    </div>
                                `;
                            }} else {{
                                container.innerHTML = '<em>未设置自定义背景</em>';
                            }}
                        }}
                    }} catch (error) {{
                        console.error('加载背景信息失败:', error);
                    }}
                }}
                
                // 表单提交
                document.getElementById('uploadForm').addEventListener('submit', async function(e) {{
                    e.preventDefault();
                    
                    const fileInput = document.getElementById('backgroundFile');
                    const errorDiv = document.getElementById('errorMessage');
                    const successDiv = document.getElementById('successMessage');
                    const uploadBtn = document.getElementById('uploadBtn');
                    
                    // 隐藏消息
                    errorDiv.style.display = 'none';
                    successDiv.style.display = 'none';
                    
                    // 验证文件
                    const file = fileInput.files[0];
                    if (!file) {{
                        showError('请选择文件');
                        return;
                    }}
                    
                    // 验证文件大小
                    if (file.size > 10 * 1024 * 1024) {{
                        showError('文件大小不能超过10MB');
                        return;
                    }}
                    
                    // 创建FormData
                    const formData = new FormData();
                    formData.append('file', file);
                    
                    try {{
                        // 显示加载状态
                        const originalText = uploadBtn.textContent;
                        uploadBtn.textContent = '上传中...';
                        uploadBtn.disabled = true;
                        
                        // 发送请求
                        const response = await fetch('/upload-background', {{
                            method: 'POST',
                            body: formData
                        }});
                        
                        // 检查是否重定向到登录页
                        if (response.redirected) {{
                            window.location.href = '/login';
                            return;
                        }}
                        
                        const data = await response.json();
                        
                        if (response.ok) {{
                            showSuccess('背景图片上传成功！');
                            // 清除文件输入
                            fileInput.value = '';
                            // 清除预览
                            document.getElementById('imagePreview').innerHTML = '';
                            // 重新加载背景信息
                            loadCurrentBackground();
                            // 延迟1秒后刷新页面以确保更新
                            setTimeout(() => {{
                                location.reload();
                            }}, 1000);
                        }} else {{
                            if (data.status === "error" && data.message.includes("需要登录")) {{
                                // 未登录，跳转到登录页
                                window.location.href = '/login';
                            }} else {{
                                showError(data.message || '上传失败');
                            }}
                        }}
                    }} catch (error) {{
                        showError('网络错误，请重试');
                        console.error('上传错误:', error);
                    }} finally {{
                        // 确保按钮状态被恢复
                        uploadBtn.textContent = '📤 上传背景';
                        uploadBtn.disabled = false;
                    }}
                }});
                
                function showError(message) {{
                    const errorDiv = document.getElementById('errorMessage');
                    errorDiv.textContent = message;
                    errorDiv.style.display = 'block';
                }}
                
                function showSuccess(message) {{
                    const successDiv = document.getElementById('successMessage');
                    successDiv.textContent = message;
                    successDiv.style.display = 'block';
                }}
                
                // 页面加载时获取当前背景
                window.onload = loadCurrentBackground;
            </script>
        </body>
        </html>
        '''
        
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(html_content.encode('utf-8'))))
        self.end_headers()
        self.wfile.write(html_content.encode('utf-8'))
    
    def handle_api_docs(self):
        """显示API文档页面"""
        html_content = '''
        <!DOCTYPE html>
        <html lang="zh-CN">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>API文档 - My Apps Panel</title>
            <style>
                * {
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                }
                
                body {
                    font-family: -apple-system, BlinkMacSystemFont, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    padding: 20px;
                }
                
                .container {
                    background: rgba(255, 255, 255, 0.95);
                    border-radius: 15px;
                    box-shadow: 0 10px 30px rgba(0,0,0,0.2);
                    padding: 40px;
                    width: 100%;
                    max-width: 900px;
                    backdrop-filter: blur(10px);
                }
                
                h1 {
                    color: #333;
                    margin-bottom: 10px;
                    text-align: center;
                }
                
                .subtitle {
                    color: #666;
                    text-align: center;
                    margin-bottom: 30px;
                }
                
                .back-btn {
                    display: inline-block;
                    padding: 10px 20px;
                    background: #667eea;
                    color: white;
                    text-decoration: none;
                    border-radius: 8px;
                    font-weight: 500;
                    transition: all 0.3s;
                    margin-bottom: 20px;
                }
                
                .back-btn:hover {
                    background: #5a67d8;
                    transform: translateY(-2px);
                    box-shadow: 0 5px 15px rgba(0,0,0,0.1);
                }
                
                .api-section {
                    margin-bottom: 30px;
                    padding: 20px;
                    background: rgba(248, 249, 250, 0.8);
                    border-radius: 12px;
                    border: 1px solid rgba(0,0,0,0.05);
                }
                
                .api-section h2 {
                    color: #3498db;
                    margin-bottom: 15px;
                    border-bottom: 2px solid #3498db;
                    padding-bottom: 10px;
                }
                
                .api-list {
                    list-style: none;
                }
                
                .api-list li {
                    background: rgba(255, 255, 255, 0.9);
                    margin: 8px 0;
                    padding: 15px;
                    border-left: 4px solid rgba(52, 152, 219, 0.8);
                    border-radius: 8px;
                    backdrop-filter: blur(5px);
                    transition: transform 0.2s;
                }
                
                .api-list li:hover {
                    transform: translateX(5px);
                    box-shadow: 0 4px 12px rgba(0,0,0,0.1);
                }
                
                .api-method {
                    display: inline-block;
                    background: rgba(52, 152, 219, 0.9);
                    color: white;
                    padding: 6px 12px;
                    border-radius: 6px;
                    font-size: 14px;
                    margin-right: 10px;
                    font-weight: bold;
                    backdrop-filter: blur(5px);
                }
                
                .api-endpoint {
                    font-family: 'Courier New', monospace;
                    background: rgba(248, 249, 250, 0.8);
                    padding: 6px 10px;
                    border-radius: 6px;
                    font-size: 15px;
                    margin-right: 10px;
                    color: #2c3e50;
                }
                
                .api-auth {
                    display: inline-block;
                    background: rgba(231, 76, 60, 0.9);
                    color: white;
                    padding: 4px 8px;
                    border-radius: 4px;
                    font-size: 12px;
                    font-weight: bold;
                    margin-left: 10px;
                }
                
                .api-auth.green {
                    background: rgba(46, 204, 113, 0.9);
                }
                
                .api-params {
                    margin-top: 10px;
                    padding: 10px;
                    background: rgba(240, 240, 240, 0.8);
                    border-radius: 6px;
                    font-size: 14px;
                }
                
                .api-params h4 {
                    margin-bottom: 8px;
                    color: #555;
                }
                
                .param-table {
                    width: 100%;
                    border-collapse: collapse;
                    margin-top: 5px;
                }
                
                .param-table th {
                    background: rgba(52, 152, 219, 0.8);
                    color: white;
                    padding: 8px;
                    text-align: left;
                }
                
                .param-table td {
                    padding: 8px;
                    border-bottom: 1px solid #ddd;
                    background: rgba(255, 255, 255, 0.9);
                }
                
                .param-table tr:hover td {
                    background: rgba(240, 247, 255, 0.9);
                }
                
                .note {
                    background: rgba(255, 243, 205, 0.8);
                    border-left: 4px solid #ffc107;
                    padding: 10px;
                    margin-top: 15px;
                    border-radius: 6px;
                    font-size: 14px;
                }
                
                @media (max-width: 768px) {
                    .container {
                        padding: 20px;
                    }
                    
                    .api-list li {
                        padding: 10px;
                    }
                    
                    .param-table {
                        display: block;
                        overflow-x: auto;
                    }
                }
            </style>
        </head>
        <body>
            <div class="container">
                <a href="/" class="back-btn">← 返回主页</a>
                <h1>📚 API文档</h1>
                <p class="subtitle">My Apps Panel接口说明</p>
                
                <div class="api-section">
                    <h2>🔐 认证说明</h2>
                    <p style="margin-bottom: 15px; color: #7f8c8d;">
                        <strong>认证方式：</strong>支持API密钥认证和用户会话认证两种方式
                    </p>
                    <div class="note">
                        <strong>注意：</strong>API密钥认证需要在请求中添加apiKey参数或X-API-Key请求头。
                        用户会话认证需要在浏览器中登录系统，会自动设置session cookie。
                    </div>
                </div>
                
                <div class="api-section">
                    <h2>🔧 API接口列表</h2>
                    <ul class="api-list">
                        <li>
                            <span class="api-method">GET</span>
                            <span class="api-endpoint">/setAppIpAndPort?appName=xxx&ip=xxx&port=xxx&lanAddr=xxx&apiKey=xxx</span>
                            <span class="api-auth">需要API密钥</span>
                            <div class="api-params">
                                <h4>参数说明:</h4>
                                <table class="param-table">
                                    <tr>
                                        <th>参数名</th>
                                        <th>类型</th>
                                        <th>必填</th>
                                        <th>说明</th>
                                    </tr>
                                    <tr>
                                        <td>appName</td>
                                        <td>字符串</td>
                                        <td>是</td>
                                        <td>应用名称</td>
                                    </tr>
                                    <tr>
                                        <td>ip</td>
                                        <td>字符串</td>
                                        <td>是</td>
                                        <td>应用外网IP地址</td>
                                    </tr>
                                    <tr>
                                        <td>port</td>
                                        <td>整数</td>
                                        <td>是</td>
                                        <td>应用端口号 (1-65535)</td>
                                    </tr>
                                    <tr>
                                        <td>lanAddr</td>
                                        <td>字符串</td>
                                        <td>否</td>
                                        <td>应用内网地址 (如: 192.168.1.100:8080)</td>
                                    </tr>
                                    <tr>
                                        <td>apiKey</td>
                                        <td>字符串</td>
                                        <td>是</td>
                                        <td>API密钥</td>
                                    </tr>
                                </table>
                            </div>
                            <p style="margin-top: 10px; color: #666;">设置或更新应用配置，包含外网地址和内网地址</p>
                        </li>
                        
                        <li>
                            <span class="api-method">GET</span>
                            <span class="api-endpoint">/getAppIpAndPort?appName=xxx&type=lan/wan</span>
                            <span class="api-auth green">允许匿名</span>
                            <div class="api-params">
                                <h4>参数说明:</h4>
                                <table class="param-table">
                                    <tr>
                                        <th>参数名</th>
                                        <th>类型</th>
                                        <th>必填</th>
                                        <th>说明</th>
                                    </tr>
                                    <tr>
                                        <td>appName</td>
                                        <td>字符串</td>
                                        <td>是</td>
                                        <td>应用名称</td>
                                    </tr>
                                    <tr>
                                        <td>type</td>
                                        <td>字符串</td>
                                        <td>否</td>
                                        <td>重定向类型: lan(内网) 或 wan(外网)，默认wan</td>
                                    </tr>
                                </table>
                            </div>
                            <p style="margin-top: 10px; color: #666;">获取应用配置并重定向到对应地址。type=lan时重定向到内网地址，type=wan或不传时重定向到外网地址</p>
                        </li>
                        
                        <li>
                            <span class="api-method">GET</span>
                            <span class="api-endpoint">/deleteAppIpAndPort?appName=xxx&apiKey=xxx</span>
                            <span class="api-auth">需要API密钥</span>
                            <div class="api-params">
                                <h4>参数说明:</h4>
                                <table class="param-table">
                                    <tr>
                                        <th>参数名</th>
                                        <th>类型</th>
                                        <th>必填</th>
                                        <th>说明</th>
                                    </tr>
                                    <tr>
                                        <td>appName</td>
                                        <td>字符串</td>
                                        <td>是</td>
                                        <td>应用名称</td>
                                    </tr>
                                    <tr>
                                        <td>apiKey</td>
                                        <td>字符串</td>
                                        <td>是</td>
                                        <td>API密钥</td>
                                    </tr>
                                </table>
                            </div>
                            <p style="margin-top: 10px; color: #666;">删除应用配置</p>
                        </li>
                        
                        <li>
                            <span class="api-method">GET</span>
                            <span class="api-endpoint">/setUsernameAndPasswd?username=xxx&passwd=xxx&apiKey=xxx</span>
                            <span class="api-auth">需要API密钥</span>
                            <div class="api-params">
                                <h4>参数说明:</h4>
                                <table class="param-table">
                                    <tr>
                                        <th>参数名</th>
                                        <th>类型</th>
                                        <th>必填</th>
                                        <th>说明</th>
                                    </tr>
                                    <tr>
                                        <td>username</td>
                                        <td>字符串</td>
                                        <td>是</td>
                                        <td>用户名（至少3个字符）</td>
                                    </tr>
                                    <tr>
                                        <td>passwd</td>
                                        <td>字符串</td>
                                        <td>是</td>
                                        <td>密码（至少6个字符）</td>
                                    </tr>
                                    <tr>
                                        <td>apiKey</td>
                                        <td>字符串</td>
                                        <td>是</td>
                                        <td>API密钥</td>
                                    </tr>
                                </table>
                            </div>
                            <p style="margin-top: 10px; color: #666;">创建新用户</p>
                        </li>
                        
                        <li>
                            <span class="api-method">GET</span>
                            <span class="api-endpoint">/background</span>
                            <span class="api-auth green">允许匿名</span>
                            <p style="margin-top: 10px; color: #666;">获取当前设置的背景图片</p>
                        </li>
                    </ul>
                </div>
                
                <div class="api-section">
                    <h2>👤 用户接口</h2>
                    <ul class="api-list">
                        <li>
                            <span class="api-method">GET</span>
                            <span class="api-endpoint">/login</span>
                            <span class="api-auth green">允许匿名</span>
                            <p style="margin-top: 10px; color: #666;">显示登录页面</p>
                        </li>
                        
                        <li>
                            <span class="api-method">POST</span>
                            <span class="api-endpoint">/login</span>
                            <span class="api-auth green">允许匿名</span>
                            <div class="api-params">
                                <h4>请求体 (JSON):</h4>
                                <pre style="background: rgba(240, 240, 240, 0.8); padding: 10px; border-radius: 6px; font-family: monospace;">
{
    "username": "用户名",
    "password": "密码",
    "remember_me": true/false
}</pre>
                            </div>
                            <p style="margin-top: 10px; color: #666;">用户登录，支持"记住我"功能</p>
                        </li>
                        
                        <li>
                            <span class="api-method">GET</span>
                            <span class="api-endpoint">/validate-token</span>
                            <span class="api-auth green">允许匿名</span>
                            <p style="margin-top: 10px; color: #666;">验证会话令牌和记住我令牌</p>
                        </li>
                        
                        <li>
                            <span class="api-method">GET</span>
                            <span class="api-endpoint">/logout</span>
                            <span class="api-auth">需要登录</span>
                            <p style="margin-top: 10px; color: #666;">用户登出，清除所有会话cookie</p>
                        </li>
                    </ul>
                </div>
                
                <div class="api-section">
                    <h2>🎨 背景图片接口</h2>
                    <ul class="api-list">
                        <li>
                            <span class="api-method">GET</span>
                            <span class="api-endpoint">/upload-background</span>
                            <span class="api-auth">需要登录</span>
                            <p style="margin-top: 10px; color: #666;">显示背景图片上传页面</p>
                        </li>
                        
                        <li>
                            <span class="api-method">POST</span>
                            <span class="api-endpoint">/upload-background</span>
                            <span class="api-auth">需要登录</span>
                            <div class="api-params">
                                <h4>请求体 (multipart/form-data):</h4>
                                <table class="param-table">
                                    <tr>
                                        <th>参数名</th>
                                        <th>类型</th>
                                        <th>必填</th>
                                        <th>说明</th>
                                    </tr>
                                    <tr>
                                        <td>file</td>
                                        <td>文件</td>
                                        <td>是</td>
                                        <td>图片文件 (支持JPG, PNG, GIF, BMP, WebP, 最大10MB)</td>
                                    </tr>
                                </table>
                            </div>
                            <p style="margin-top: 10px; color: #666;">上传新的背景图片</p>
                        </li>
                    </ul>
                </div>
                
                <div class="api-section">
                    <h2>⚙️ 配置说明</h2>
                    <div class="api-params">
                        <table class="param-table">
                            <tr>
                                <th>环境变量</th>
                                <th>默认值</th>
                                <th>说明</th>
                            </tr>
                            <tr>
                                <td>DB_PATH</td>
                                <td>app_config.db</td>
                                <td>数据库文件路径</td>
                            </tr>
                            <tr>
                                <td>API_KEY</td>
                                <td>自动生成</td>
                                <td>API密钥，多个密钥用逗号分隔</td>
                            </tr>
                            <tr>
                                <td>ENABLE_AUTH</td>
                                <td>true</td>
                                <td>是否启用API密钥认证</td>
                            </tr>
                        </table>
                    </div>
                </div>
            </div>
        </body>
        </html>
        '''
        
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(html_content.encode('utf-8'))))
        self.end_headers()
        self.wfile.write(html_content.encode('utf-8'))
    
    def handle_upload_background(self):
        """处理背景图片上传 - 需要用户登录"""
        try:
            # 检查用户是否已登录
            session = self.get_session()
            if not session:
                self.send_json_response(401, {
                    "status": "error",
                    "message": "需要登录，请先登录系统",
                    "error_code": "NOT_LOGGED_IN"
                })
                return
            
            # 解析multipart/form-data
            content_type = self.headers.get('Content-Type', '')
            if not content_type.startswith('multipart/form-data'):
                self.send_json_response(400, {
                    "status": "error",
                    "message": "不支持的Content-Type"
                })
                return
            
            # 读取请求体
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)
            
            # 解析multipart数据
            data, files = parse_multipart_form_data(self.headers, body)
            
            if not files or 'file' not in files:
                self.send_json_response(400, {
                    "status": "error",
                    "message": "没有选择文件"
                })
                return
            
            file_info = files['file']
            file_data = file_info['data']
            filename = file_info['filename']
            
            # 验证文件类型
            file_ext = os.path.splitext(filename)[1].lower()
            if file_ext not in self.ALLOWED_EXTENSIONS:
                self.send_json_response(400, {
                    "status": "error",
                    "message": f"不支持的文件类型。支持的类型: {', '.join(self.ALLOWED_EXTENSIONS)}"
                })
                return
            
            # 验证文件大小
            if len(file_data) > self.MAX_FILE_SIZE:
                self.send_json_response(400, {
                    "status": "error",
                    "message": f"文件太大。最大允许: {self.MAX_FILE_SIZE // 1024 // 1024}MB"
                })
                return
            
            # 验证文件内容是否为图片
            temp_file_path = None
            try:
                # 创建临时文件
                with tempfile.NamedTemporaryFile(delete=False, suffix=file_ext) as tmp:
                    tmp.write(file_data)
                    temp_file_path = tmp.name
                
                # 使用兼容的图片类型检测
                detected_type = detect_image_type(temp_file_path)
                if not detected_type:
                    self.send_json_response(400, {
                        "status": "error",
                        "message": "文件不是有效的图片文件"
                    })
                    # 删除临时文件
                    try:
                        os.unlink(temp_file_path)
                    except:
                        pass
                    return
            except Exception as e:
                print(f"验证图片失败: {e}")
                self.send_json_response(400, {
                    "status": "error",
                    "message": "图片验证失败"
                })
                # 确保删除临时文件
                if temp_file_path and os.path.exists(temp_file_path):
                    try:
                        os.unlink(temp_file_path)
                    except:
                        pass
                return
            finally:
                # 确保删除临时文件
                if temp_file_path and os.path.exists(temp_file_path):
                    try:
                        os.unlink(temp_file_path)
                    except:
                        pass
            
            # 生成唯一文件名
            timestamp = int(time.time())
            file_hash = hashlib.md5(file_data).hexdigest()[:8]
            new_filename = f"{timestamp}_{file_hash}{file_ext}"
            filepath = os.path.join('backgrounds', new_filename)
            
            # 确保背景目录存在
            if not os.path.exists('backgrounds'):
                os.makedirs('backgrounds')
            
            # 保存文件
            with open(filepath, 'wb') as f:
                f.write(file_data)
            
            # 保存到数据库
            conn = self.get_db_connection()
            cursor = conn.cursor()
            
            # 将所有背景标记为非活跃
            cursor.execute('UPDATE background_config SET is_active = 0')
            
            # 插入新的背景记录
            cursor.execute('''
                INSERT INTO background_config 
                (filename, original_name, file_size, is_active)
                VALUES (?, ?, ?, 1)
            ''', (new_filename, filename, len(file_data)))
            
            conn.commit()
            conn.close()
            
            self.send_json_response(200, {
                "status": "success",
                "message": "背景图片上传成功",
                "data": {
                    "filename": new_filename,
                    "original_name": filename,
                    "file_size": len(file_data),
                    "url": f"/background?t={timestamp}",
                    "uploaded_by": session['username']
                }
            })
            
        except Exception as e:
            print(f"上传背景图片时发生错误: {e}")
            self.send_json_response(500, {
                "status": "error",
                "message": f"服务器内部错误: {str(e)}"
            })
    
    def handle_get_background(self, params: Dict[str, list]):
        """获取背景图片 - 允许匿名访问"""
        try:
            bg_info = self.get_active_background()
            
            # 如果请求的是信息而不是图片
            if params.get('info', [''])[0] == '1':
                if bg_info:
                    self.send_json_response(200, {
                        "has_background": True,
                        "filename": bg_info['filename'],
                        "original_name": bg_info['original_name'],
                        "created_at": bg_info['created_at']
                    })
                else:
                    self.send_json_response(200, {
                        "has_background": False,
                        "message": "没有设置背景图片"
                    })
                return
            
            # 返回图片数据
            if not bg_info:
                # 返回404
                self.send_response(404)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.end_headers()
                self.wfile.write(b"<h1>404 No background image set</h1>")
                return
            
            filepath = os.path.join('backgrounds', bg_info['filename'])
            if not os.path.exists(filepath):
                self.send_response(404)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.end_headers()
                self.wfile.write(b"<h1>404 Background image not found</h1>")
                return
            
            # 读取图片文件
            with open(filepath, 'rb') as f:
                image_data = f.read()
            
            # 确定MIME类型
            import mimetypes
            mime_type, _ = mimetypes.guess_type(filepath)
            if not mime_type:
                mime_type = 'image/jpeg'  # 默认
            
            # 返回图片
            self.send_response(200)
            self.send_header('Content-Type', mime_type)
            self.send_header('Content-Length', str(len(image_data)))
            # 添加缓存控制头，但使用较短的时间
            self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
            self.send_header('Pragma', 'no-cache')
            self.send_header('Expires', '0')
            self.end_headers()
            self.wfile.write(image_data)
            
        except Exception as e:
            print(f"获取背景图片时发生错误: {e}")
            self.send_response(500)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(f"<h1>500 Internal Server Error</h1><p>{str(e)}</p>".encode('utf-8'))
    
    def generate_html_page(self, apps: List[Dict], bg_info: Optional[Dict], username: str) -> str:
        """生成HTML页面"""
        # 获取会话统计信息
        active_sessions = self.session_manager.get_session_count()
        
        # 生成应用列表HTML
        apps_html = ""
        if apps:
            for app in apps:
                app_name = app['appName']
                ip = app['ip']
                port = app['port']
                url = app['url']
                
                # 检查是否有内网地址
                has_lan = 'lan_addr' in app and app['lan_addr']
                lan_url = app.get('lan_url', '')
                
                apps_html += f'''
                <tr>
                    <td><strong>{app_name}</strong></td>
                    <td>
                        <span class="copyable" onclick="copyToClipboard('{ip}:{port}')" title="点击复制">
                            {ip}:{port}
                        </span>
                    </td>
                    <td>
                        <a href="{url}" target="_blank" class="app-link" title="访问应用(外网)">
                            {url}
                        </a>
                    </td>
                    <td>
                        {f'<a href="{lan_url}" target="_blank" class="lan-link" title="访问应用(内网)">http://{app["lan_addr"]}</a>' if has_lan else '<span class="no-lan">未设置内网地址</span>'}
                    </td>
                </tr>
                '''
        else:
            apps_html = '''
            <tr>
                <td colspan="5" style="text-align: center; padding: 20px;">
                    暂无应用配置，请使用API接口添加应用
                </td>
            </tr>
            '''
        
        # 背景图片URL - 添加时间戳防止缓存
        timestamp = int(time.time())
        bg_url = f"/background?t={timestamp}" if bg_info else ''
        bg_style = f"background-image: url('{bg_url}');" if bg_info else ""
        
        html = f'''
        <!DOCTYPE html>
        <html lang="zh-CN">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>My Apps Panel</title>
            <style>
                * {{
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                }}
                
                body {{
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    {bg_style}
                    background-size: cover;
                    background-position: center;
                    background-attachment: fixed;
                    background-repeat: no-repeat;
                    position: relative;
                    overflow: auto;
                }}
                
                body::before {{
                    content: '';
                    position: fixed;
                    top: 0;
                    left: 0;
                    right: 0;
                    bottom: 0;
                    z-index: -1;
                }}
                
                .container {{
                    max-width: 1200px;
                    margin: 40px auto;
                    background-color: rgba(255, 255, 255, 0.2);
                    border-radius: 15px;
                    box-shadow: 0 8px 32px rgba(0,0,0,0.1);
                    padding: 30px;
                    backdrop-filter: blur(10px);
                    border: 1px solid rgba(255, 255, 255, 0.2);
                }}
                
                header {{
                    text-align: center;
                    margin-bottom: 30px;
                    padding-bottom: 20px;
                    border-bottom: 2px solid rgba(234, 234, 234, 0.5);
                }}
                
                h1 {{
                    color: #2c3e50;
                    margin-bottom: 10px;
                }}
                
                .subtitle {{
                    color: #7f8c8d;
                    font-size: 18px;
                }}
                
                .section {{
                    margin-bottom: 30px;
                    padding: 20px;
                    background: rgba(248, 249, 250, 0.8);
                    border-radius: 12px;
                    border: 1px solid rgba(0,0,0,0.05);
                }}
                
                .section-title {{
                    color: #3498db;
                    margin-bottom: 15px;
                    display: flex;
                    align-items: center;
                    justify-content: space-between;
                }}
                
                .section-title i {{
                    font-size: 20px;
                }}
                
                .apps-table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin-top: 15px;
                    background: rgba(255, 255, 255, 0.9);
                    border-radius: 8px;
                    overflow: hidden;
                }}
                
                .apps-table th {{
                    background: rgba(52, 152, 219, 0.9);
                    color: white;
                    padding: 12px;
                    text-align: left;
                    backdrop-filter: blur(10px);
                }}
                
                .apps-table td {{
                    padding: 12px;
                    border-bottom: 1px solid rgba(221, 221, 221, 0.5);
                }}
                
                .apps-table tr:hover {{
                    background: rgba(240, 247, 255, 0.7);
                }}
                
                .copyable {{
                    cursor: pointer;
                    padding: 6px 12px;
                    background: rgba(241, 248, 255, 0.8);
                    border-radius: 6px;
                    border: 1px solid rgba(200, 225, 255, 0.6);
                    display: inline-block;
                    transition: all 0.2s;
                    backdrop-filter: blur(5px);
                }}
                
                .copyable:hover {{
                    background: rgba(224, 240, 255, 0.9);
                    border-color: rgba(52, 152, 219, 0.8);
                    transform: translateY(-1px);
                    box-shadow: 0 2px 8px rgba(52, 152, 219, 0.2);
                }}
                
                .copyable:active {{
                    transform: scale(0.98);
                }}
                
                .app-link {{
                    color: #2980b9;
                    text-decoration: none;
                    padding: 6px 12px;
                    background: rgba(232, 244, 252, 0.8);
                    border-radius: 6px;
                    display: inline-block;
                    transition: all 0.2s;
                    backdrop-filter: blur(5px);
                }}
                
                .app-link:hover {{
                    background: rgba(212, 233, 250, 0.9);
                    text-decoration: underline;
                    transform: translateY(-1px);
                }}
                
                .lan-link {{
                    color: #27ae60;
                    text-decoration: none;
                    padding: 6px 12px;
                    background: rgba(232, 252, 240, 0.8);
                    border-radius: 6px;
                    display: inline-block;
                    transition: all 0.2s;
                    backdrop-filter: blur(5px);
                    font-weight: 500;
                }}
                
                .lan-link:hover {{
                    background: rgba(212, 250, 223, 0.9);
                    text-decoration: underline;
                    transform: translateY(-1px);
                    box-shadow: 0 2px 8px rgba(39, 174, 96, 0.2);
                }}
                
                .no-lan {{
                    color: #95a5a6;
                    font-style: italic;
                    font-size: 14px;
                }}
                
                .copy-notification {{
                    position: fixed;
                    top: 20px;
                    right: 20px;
                    background: rgba(46, 204, 113, 0.95);
                    color: white;
                    padding: 12px 24px;
                    border-radius: 8px;
                    display: none;
                    z-index: 1000;
                    box-shadow: 0 4px 12px rgba(0,0,0,0.15);
                    backdrop-filter: blur(10px);
                    animation: slideIn 0.3s ease-out;
                }}
                
                @keyframes slideIn {{
                    from {{ transform: translateX(100%); opacity: 0; }}
                    to {{ transform: translateX(0); opacity: 1; }}
                }}
                
                footer {{
                    text-align: center;
                    margin-top: 40px;
                    padding-top: 20px;
                    border-top: 1px solid rgba(234, 234, 234, 0.5);
                    color: rgba(149, 165, 166, 0.9);
                    font-size: 14px;
                }}
                
                .upload-btn {{
                    display: inline-flex;
                    align-items: center;
                    gap: 8px;
                    background: rgba(155, 89, 182, 0.9);
                    color: white;
                    padding: 8px 16px;
                    border-radius: 6px;
                    text-decoration: none;
                    font-weight: 500;
                    transition: all 0.2s;
                    backdrop-filter: blur(5px);
                }}
                
                .upload-btn:hover {{
                    background: rgba(142, 68, 173, 0.9);
                    transform: translateY(-2px);
                    box-shadow: 0 4px 12px rgba(155, 89, 182, 0.3);
                }}
                
                .api-btn {{
                    display: inline-flex;
                    align-items: center;
                    gap: 8px;
                    background: rgba(241, 196, 15, 0.9);
                    color: white;
                    padding: 8px 16px;
                    border-radius: 6px;
                    text-decoration: none;
                    font-weight: 500;
                    transition: all 0.2s;
                    backdrop-filter: blur(5px);
                    margin-left: 10px;
                }}
                
                .api-btn:hover {{
                    background: rgba(243, 156, 18, 0.9);
                    transform: translateY(-2px);
                    box-shadow: 0 4px 12px rgba(241, 196, 15, 0.3);
                }}
                
                .user-info {{
                    display: flex;
                    align-items: center;
                    gap: 15px;
                    margin-bottom: 10px;
                }}
                
                .logout-btn {{
                    color: #e74c3c;
                    text-decoration: none;
                    padding: 5px 10px;
                    border: 1px solid #e74c3c;
                    border-radius: 4px;
                    transition: all 0.2s;
                }}
                
                .logout-btn:hover {{
                    background: #e74c3c;
                    color: white;
                }}
                
                .current-bg-info {{
                    display: flex;
                    align-items: center;
                    gap: 10px;
                    margin-top: 10px;
                    padding: 10px;
                    background: rgba(255, 255, 255, 0.8);
                    border-radius: 6px;
                    border: 1px solid rgba(0,0,0,0.05);
                }}
                
                .current-bg-info img {{
                    width: 60px;
                    height: 40px;
                    object-fit: cover;
                    border-radius: 4px;
                }}
                
                .stats-bar {{
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-top: 20px;
                    padding: 10px;
                    background: rgba(248, 249, 250, 0.8);
                    border-radius: 8px;
                    border: 1px solid rgba(0,0,0,0.05);
                }}
                
                .stat-item {{
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                }}
                
                .stat-value {{
                    font-size: 20px;
                    font-weight: bold;
                    color: #2c3e50;
                }}
                
                .stat-label {{
                    font-size: 12px;
                    color: #7f8c8d;
                }}
                
                .network-badge {{
                    display: inline-block;
                    padding: 2px 6px;
                    background: rgba(52, 152, 219, 0.2);
                    color: #FF8C00;
                    border-radius: 4px;
                    font-size: 11px;
                    margin-left: 5px;
                    font-weight: bold;
                }}
                
                @media (max-width: 768px) {{
                    .container {{
                        padding: 15px;
                    }}
                    
                    .apps-table {{
                        display: block;
                        overflow-x: auto;
                    }}
                    
                    .section {{
                        padding: 15px;
                    }}
                    
                    .stats-bar {{
                        flex-direction: column;
                        gap: 10px;
                    }}
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <header>
                    <div class="user-info">
                        <h1 style="margin: 0;">📱 My Apps Panel</h1>
                        <div style="margin-left: auto;">
                            <span style="color: #666; margin-right: 15px;">
                                {username}
                            </span>
                            <a href="/logout" class="logout-btn">退出登录</a>
                        </div>
                    </div>
                </header>
                
                <div class="section">
                    <h2 class="section-title"><i>🚀</i> 应用列表</h2>
                    <table class="apps-table">
                        <thead>
                            <tr>
                                <th>应用名称</th>
                                <th>ip:port<span class="network-badge">外网</span></th>
                                <th>访问地址<span class="network-badge">外网</span></th>
                                <th>内网地址</th>
                            </tr>
                        </thead>
                        <tbody>
                            {apps_html}
                        </tbody>
                    </table>
                </div>
                
                <div class="section">
                    <h2 class="section-title"><i>🔧</i> 快捷访问</h2>
                    <div style="display: flex; gap: 15px; flex-wrap: wrap;">
                        <a href="/getAppIpAndPort?appName=example&type=wan" class="api-btn" target="_blank" style="background: rgba(52, 152, 219, 0.9);">
                            🔗 外网重定向示例
                        </a>
                        <a href="/getAppIpAndPort?appName=example&type=lan" class="api-btn" target="_blank" style="background: rgba(39, 174, 96, 0.9);">
                            🏠 内网重定向示例
                        </a>
                        <a href="/setAppIpAndPort?appName=myapp&ip=example.com&port=8080&lanAddr=192.168.1.100:8080&apiKey=your_key" class="api-btn" target="_blank" style="background: rgba(155, 89, 182, 0.9);">
                            ➕ 设置应用示例
                        </a>
                        <a href="/upload-background" class="upload-btn">🎨 自定义背景</a>
                        <a href="/api-docs" class="api-btn" target="_blank">📚 API文档</a>
                        <a href="/session-stats" class="api-btn" target="_blank" style="background: rgba(46, 204, 113, 0.9);">📊 会话统计</a>
                    </div>
                </div>
                
                <footer>
                    <p>© 2026 明明版权所有 | 当前用户: {username} | 总应用数: {len(apps)} | 活跃会话: {active_sessions}</p>
                </footer>
            </div>
            
            <div class="copy-notification" id="copyNotification">已复制到剪贴板！</div>
            
            <script>
                // 复制文本到剪贴板
                function copyToClipboard(text) {{
                    const textarea = document.createElement('textarea');
                    textarea.value = text;
                    document.body.appendChild(textarea);
                    
                    textarea.select();
                    textarea.setSelectionRange(0, 99999);
                    
                    try {{
                        document.execCommand('copy');
                        showCopyNotification();
                    }} catch (err) {{
                        console.error('复制失败:', err);
                    }}
                    
                    document.body.removeChild(textarea);
                }}
                
                function showCopyNotification() {{
                    const notification = document.getElementById('copyNotification');
                    notification.style.display = 'block';
                    
                    setTimeout(() => {{
                        notification.style.display = 'none';
                    }}, 3000);
                }}
                
                document.addEventListener('DOMContentLoaded', function() {{
                    const copyables = document.querySelectorAll('.copyable');
                    copyables.forEach(element => {{
                        element.addEventListener('click', function() {{
                            this.style.transform = 'scale(0.95)';
                            this.style.backgroundColor = 'rgba(212, 233, 250, 0.9)';
                            
                            setTimeout(() => {{
                                this.style.transform = '';
                                this.style.backgroundColor = '';
                            }}, 200);
                        }});
                    }});
                }});
            </script>
        </body>
        </html>
        '''
        return html
    
    def handle_set_app_ip_port(self, params: Dict[str, list]):
        """处理setAppIpAndPort接口 - 需要API密钥认证"""
        # 首先进行API密钥认证
        auth_error = self.authenticate_request(params)
        if auth_error:
            self.send_json_response(401, auth_error)
            return
        
        try:
            # 认证通过，继续处理业务逻辑
            if not all(key in params for key in ['appName', 'ip', 'port']):
                raise ValueError("缺少必要参数：appName, ip, port")
            
            app_name = params['appName'][0]
            ip = params['ip'][0]
            port = int(params['port'][0])
            lan_addr = params.get('lanAddr', [None])[0]
            
            # 验证端口号
            if not 1 <= port <= 65535:
                raise ValueError("端口号必须在1-65535范围内")
            
            # 验证IP地址格式
            if not self.is_valid_ip(ip):
                raise ValueError("IP地址格式无效")
            
            # 验证内网地址格式（如果提供）
            if lan_addr:
                # 简单验证内网地址格式，可以是IP:端口或域名:端口
                if ':' not in lan_addr:
                    raise ValueError("内网地址格式无效，应为 IP:端口 或 域名:端口")
                
                lan_parts = lan_addr.split(':')
                if len(lan_parts) != 2:
                    raise ValueError("内网地址格式无效，应为 IP:端口 或 域名:端口")
                
                try:
                    lan_port = int(lan_parts[1])
                    if not 1 <= lan_port <= 65535:
                        raise ValueError("内网端口号必须在1-65535范围内")
                except ValueError:
                    raise ValueError("内网端口号必须是有效的整数")
            
            # 存储到数据库
            result = self.save_to_database(app_name, ip, port, lan_addr)
            
            if result:
                response_data = {
                    "appName": app_name,
                    "ip": ip,
                    "port": port,
                    "wan_url": f"http://{ip}:{port}"
                }
                
                if lan_addr:
                    response_data["lan_addr"] = lan_addr
                    response_data["lan_url"] = f"http://{lan_addr}"
                
                response = {
                    "status": "success",
                    "message": f"应用 {app_name} 的配置已保存",
                    "data": response_data
                }
                self.send_json_response(200, response)
            else:
                response = {
                    "status": "error",
                    "message": f"保存应用 {app_name} 配置失败"
                }
                self.send_json_response(500, response)
                
        except ValueError as e:
            response = {
                "status": "error",
                "message": str(e)
            }
            self.send_json_response(400, response)
        except Exception as e:
            response = {
                "status": "error",
                "message": f"服务器内部错误: {str(e)}"
            }
            self.send_json_response(500, response)
    
    def handle_delete_app_ip_port(self, params: Dict[str, list]):
        """处理deleteAppIpAndPort接口 - 需要API密钥认证"""
        # 首先进行API密钥认证
        auth_error = self.authenticate_request(params)
        if auth_error:
            self.send_json_response(401, auth_error)
            return
        
        try:
            # 认证通过，继续处理业务逻辑
            if 'appName' not in params:
                raise ValueError("缺少必要参数：appName")
            
            app_name = params['appName'][0]
            
            # 先检查应用是否存在
            existing_config = self.query_from_database(app_name)
            if not existing_config:
                response = {
                    "status": "error",
                    "message": f"应用 {app_name} 不存在，无法删除"
                }
                self.send_json_response(404, response)
                return
            
            # 从数据库删除
            result = self.delete_from_database(app_name)
            
            if result:
                response = {
                    "status": "success",
                    "message": f"应用 {app_name} 的配置已删除",
                    "deleted_config": existing_config
                }
                self.send_json_response(200, response)
            else:
                response = {
                    "status": "error",
                    "message": f"删除应用 {app_name} 配置失败"
                }
                self.send_json_response(500, response)
                
        except ValueError as e:
            response = {
                "status": "error",
                "message": str(e)
            }
            self.send_json_response(400, response)
        except Exception as e:
            response = {
                "status": "error",
                "message": f"服务器内部错误: {str(e)}"
            }
            self.send_json_response(500, response)
    
    def handle_get_app_ip_port(self, params: Dict[str, list]):
        """处理getAppIpAndPort接口 - 允许匿名访问"""
        try:
            # 验证参数
            if 'appName' not in params:
                raise ValueError("缺少必要参数：appName")
            
            app_name = params['appName'][0]
            redirect_type = params.get('type', ['wan'])[0].lower()
            
            # 从数据库查询
            app_config = self.query_from_database(app_name)
            
            if app_config:
                # 根据type参数决定重定向地址
                if redirect_type == 'lan' and app_config.get('lan_addr'):
                    # 重定向到内网地址
                    redirect_url = f"http://{app_config['lan_addr']}"
                    network_type = "内网"
                else:
                    # 重定向到外网地址（默认）
                    redirect_url = f"http://{app_config['ip']}:{app_config['port']}"
                    network_type = "外网"
                
                # 返回重定向响应
                self.send_response(302)  # 302 Found
                self.send_header('Location', redirect_url)
                self.send_header('Content-Type', 'text/html')
                self.end_headers()
                
                html_content = f"""
                <html>
                <head>
                    <title>重定向中...</title>
                    <meta http-equiv="refresh" content="0; url={redirect_url}">
                </head>
                <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
                    <h2>正在重定向到应用: {app_name}</h2>
                    <p>网络类型: {network_type}</p>
                    <p>目标地址: <a href="{redirect_url}">{redirect_url}</a></p>
                    <p>如果浏览器没有自动跳转，请点击上面的链接</p>
                </body>
                </html>
                """
                self.wfile.write(html_content.encode('utf-8'))
            else:
                response = {
                    "status": "error",
                    "message": f"未找到应用 {app_name} 的配置信息"
                }
                self.send_json_response(404, response)
                
        except ValueError as e:
            response = {
                "status": "error",
                "message": str(e)
            }
            self.send_json_response(400, response)
        except Exception as e:
            response = {
                "status": "error",
                "message": f"服务器内部错误: {str(e)}"
            }
            self.send_json_response(500, response)
    
    def is_valid_ip(self, ip: str) -> bool:
        """简单验证IP地址格式"""
        # 支持IPv4和域名
        if not ip or len(ip) > 255:
            return False
        
        # 如果是IPv4地址
        if '.' in ip:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            
            for part in parts:
                if not part.isdigit():
                    return False
                num = int(part)
                if num < 0 or num > 255:
                    return False
            return True
        
        # 允许域名（简单验证）
        return True
    
    def save_to_database(self, app_name: str, ip: str, port: int, lan_addr: Optional[str] = None) -> bool:
        """保存应用配置到数据库"""
        try:
            conn = self.get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO app_config (app_name, ip, port, lan_addr, updated_at)
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (app_name, ip, port, lan_addr))
            
            conn.commit()
            conn.close()
            return True
            
        except sqlite3.Error as e:
            print(f"数据库错误: {e}")
            return False
    
    def delete_from_database(self, app_name: str) -> bool:
        """从数据库删除应用配置"""
        try:
            conn = self.get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute('DELETE FROM app_config WHERE app_name = ?', (app_name,))
            
            affected_rows = cursor.rowcount
            conn.commit()
            conn.close()
            
            return affected_rows > 0
            
        except sqlite3.Error as e:
            print(f"数据库删除错误: {e}")
            return False
    
    def query_from_database(self, app_name: str) -> Optional[Dict]:
        """从数据库查询应用配置"""
        try:
            conn = self.get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT app_name, ip, port, lan_addr FROM app_config
                WHERE app_name = ?
            ''', (app_name,))
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                config = {
                    "appName": row[0],
                    "ip": row[1],
                    "port": row[2],
                    "wan_url": f"http://{row[1]}:{row[2]}"
                }
                if row[3]:
                    config["lan_addr"] = row[3]
                    config["lan_url"] = f"http://{row[3]}"
                return config
            return None
            
        except sqlite3.Error as e:
            print(f"数据库查询错误: {e}")
            return None
    
    def send_json_response(self, status_code: int, data: Dict):
        """发送JSON格式的响应"""
        json_data = json.dumps(data, ensure_ascii=False, indent=2)
        
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(json_data.encode('utf-8'))))
        self.end_headers()
        
        self.wfile.write(json_data.encode('utf-8'))
    
    def log_message(self, format, *args):
        """自定义日志输出格式"""
        client_ip = self.client_address[0]
        method = self.command
        path = self.path.split('?')[0]
        status_code = args[1] if len(args) > 1 else 200
        print(f"[HTTP] {client_ip} - {method} {path} - {status_code}")

def run_server(host='0.0.0.0', port=8080):
    """启动HTTP服务器"""
    # 初始化数据库
    init_database()
    
    # 检查是否至少有一个用户
    try:
        conn = sqlite3.connect(get_db_path())
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM users')
        user_count = cursor.fetchone()[0]
        conn.close()
        
        if user_count == 0:
            print(f"\n⚠️  警告: 数据库中没有用户")
            print(f"请使用以下API创建用户:")
            print(f"GET /setUsernameAndPasswd?username=admin&passwd=password123&apiKey=your_api_key")
            print(f"注意：您需要先获取或设置API_KEY环境变量\n")
    except Exception as e:
        print(f"检查用户时发生错误: {e}")
    
    server_address = (host, port)
    httpd = http.server.HTTPServer(server_address, AppConfigHandler)
    
    print(f"服务器启动在 http://{host}:{port}")
    print("=" * 80)
    print(f"数据库文件: {os.path.abspath(get_db_path())}")
    print("背景目录: ./backgrounds/")
    print("\n用户认证系统:")
    print("  - 首次访问需登录: 访问 /login")
    print("  - 创建用户: GET /setUsernameAndPasswd?username=xxx&passwd=xxx&apiKey=xxx")
    print("  - 退出登录: GET /logout")
    print("\n会话管理改进:")
    print("  - 基于IP和用户名的会话去重，避免重复计数")
    print("  - 查看会话统计: GET /session-stats")
    print("\n记住我功能:")
    print("  - 登录时勾选'记住我'，30天内无需重新登录")
    print("  - 令牌验证: GET /validate-token")
    print("\n自定义背景功能:")
    print("  - 上传背景: 访问 /upload-background (需要登录)")
    print("  - 查看背景: 访问 /background (匿名访问)")
    print("  - 主页背景: 自动应用上传的背景图片")
    print("\n内网地址功能:")
    print("  - setAppIpAndPort: 新增lanAddr参数，用于设置内网访问地址")
    print("  - getAppIpAndPort: 新增type参数，type=lan时重定向到内网地址")
    print("  - 主页应用列表: 显示内网地址列")
    print("\nAPI文档:")
    print("  - 访问 /api-docs 查看完整的API文档")
    print("\n认证配置:")
    print(f"  setAppIpAndPort: 需要API密钥认证")
    print(f"  deleteAppIpAndPort: 需要API密钥认证")
    print(f"  setUsernameAndPasswd: 需要API密钥认证")
    print(f"  upload-background: 需要用户登录")
    print(f"  getAppIpAndPort: 允许匿名访问")
    print(f"  background: 允许匿名访问")
    print(f"  Web访问: 需要用户登录或记住我令牌")
    print("\nAPI接口:")
    print("  1. GET /setAppIpAndPort?appName=xxx&ip=xxx&port=xxx&lanAddr=xxx&apiKey=xxx")
    print("  2. GET /getAppIpAndPort?appName=xxx&type=lan/wan")
    print("  3. GET /deleteAppIpAndPort?appName=xxx&apiKey=xxx")
    print("  4. GET /setUsernameAndPasswd?username=xxx&passwd=xxx&apiKey=xxx")
    print("  5. GET /login (登录页面)")
    print("  6. POST /login (登录提交)")
    print("  7. GET /logout (退出登录)")
    print("  8. GET /validate-token (验证令牌)")
    print("  9. GET /session-stats (会话统计)")
    print(" 10. GET / (主页，需要登录)")
    print(" 11. GET /upload-background (上传背景页面，需要登录)")
    print(" 12. POST /upload-background (上传背景图片，需要登录)")
    print(" 13. GET /background (获取背景图片)")
    print(" 14. GET /api-docs (API文档)")
    print("\n配置:")
    print("  数据库路径: export DB_PATH=/path/to/app_config.db")
    print("  API密钥: export API_KEY=your_secret_key")
    print("  多密钥: export API_KEY=key1,key2,key3")
    print("  禁用API认证: export ENABLE_AUTH=false")
    print("=" * 80)
    print("\n按 Ctrl+C 停止服务器")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n服务器正在关闭...")
        httpd.server_close()
        print("服务器已关闭")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == '--test':
        import time
        import requests
        
        print("测试模式启动...")
        print(f"当前工作目录: {os.getcwd()}")
        print(f"数据库将创建在: {os.path.abspath(get_db_path())}")
        
        # 在后台启动服务器
        server_thread = threading.Thread(
            target=run_server,
            kwargs={'host': '127.0.0.1', 'port': 8080},
            daemon=True
        )
        server_thread.start()
        
        # 等待服务器启动
        time.sleep(2)
        
        base_url = "http://127.0.0.1:8080"
        
        try:
            print("\n1. 测试登录页面:")
            response = requests.get(f"{base_url}/login")
            print(f"   状态码: {response.status_code}")
            print(f"   响应类型: {response.headers.get('Content-Type')}")
            
            print("\n2. 测试主页重定向（未登录）:")
            response = requests.get(base_url, allow_redirects=False)
            print(f"   状态码: {response.status_code}")
            print(f"   重定向到: {response.headers.get('Location', '无')}")
            
            print("\n3. 创建测试用户（需要API密钥）:")
            import os
            api_key = os.getenv('API_KEY', '')
            if not api_key:
                print("   请设置环境变量API_KEY或查看服务器启动时的默认密钥")
            else:
                set_user_params = {
                    'username': 'testuser',
                    'passwd': 'password123',
                    'apiKey': api_key
                }
                response = requests.get(f"{base_url}/setUsernameAndPasswd", params=set_user_params)
                print(f"   状态码: {response.status_code}")
                if response.status_code == 200:
                    print(f"   用户创建成功")
                else:
                    print(f"   响应: {response.json()}")
                    
                    print("\n4. 测试用户登录（带记住我）:")
                    login_data = {
                        'username': 'testuser',
                        'password': 'password123',
                        'remember_me': True
                    }
                    response = requests.post(f"{base_url}/login", json=login_data)
                    print(f"   状态码: {response.status_code}")
                    if response.status_code == 200:
                        print(f"   登录成功")
                        # 保存session cookie和remember me cookie
                        session_cookie = response.cookies.get('session_token')
                        remember_cookie = response.cookies.get('remember_me_token')
                        
                        print("\n5. 测试设置应用（包含内网地址）:")
                        set_app_params = {
                            'appName': 'testapp',
                            'ip': 'example.com',
                            'port': '8080',
                            'lanAddr': '192.168.1.100:8080',
                            'apiKey': api_key
                        }
                        response = requests.get(f"{base_url}/setAppIpAndPort", params=set_app_params)
                        print(f"   状态码: {response.status_code}")
                        if response.status_code == 200:
                            print(f"   应用创建成功")
                            print(f"   响应: {response.json()}")
                            
                            print("\n6. 测试外网重定向:")
                            response = requests.get(f"{base_url}/getAppIpAndPort?appName=testapp&type=wan", allow_redirects=False)
                            print(f"   状态码: {response.status_code}")
                            print(f"   重定向到: {response.headers.get('Location', '无')}")
                            
                            print("\n7. 测试内网重定向:")
                            response = requests.get(f"{base_url}/getAppIpAndPort?appName=testapp&type=lan", allow_redirects=False)
                            print(f"   状态码: {response.status_code}")
                            print(f"   重定向到: {response.headers.get('Location', '无')}")
                        
                        print("\n8. 测试令牌验证接口:")
                        response = requests.get(f"{base_url}/validate-token", cookies={'remember_me_token': remember_cookie})
                        print(f"   状态码: {response.status_code}")
                        if response.status_code == 200:
                            data = response.json()
                            print(f"   令牌验证成功: {data.get('message')}")
                        
                        print("\n9. 测试会话统计接口:")
                        response = requests.get(f"{base_url}/session-stats", cookies={'session_token': session_cookie})
                        print(f"   状态码: {response.status_code}")
                        if response.status_code == 200:
                            data = response.json()
                            print(f"   活跃会话数: {data['data']['active_sessions']}")
                            print(f"   总令牌数: {data['data']['total_tokens']}")
                        
                        print("\n10. 测试背景图片接口:")
                        response = requests.get(f"{base_url}/background?info=1")
                        print(f"   状态码: {response.status_code}")
                        if response.status_code == 200:
                            data = response.json()
                            print(f"   背景信息: {data}")
                        
                        print("\n11. 测试上传页面访问（已登录）:")
                        response = requests.get(f"{base_url}/upload-background", cookies={'session_token': session_cookie})
                        print(f"   状态码: {response.status_code}")
                        
                        print("\n12. 测试API文档页面:")
                        response = requests.get(f"{base_url}/api-docs")
                        print(f"   状态码: {response.status_code}")
                        print(f"   响应类型: {response.headers.get('Content-Type')}")
                        
                        print("\n13. 测试主页访问（已登录）:")
                        response = requests.get(base_url, cookies={'session_token': session_cookie})
                        print(f"   状态码: {response.status_code}")
                        if response.status_code == 200:
                            print(f"   主页访问成功，包含自定义背景功能")
                        
                        print("\n14. 测试登出:")
                        response = requests.get(f"{base_url}/logout", cookies={'session_token': session_cookie}, allow_redirects=False)
                        print(f"   状态码: {response.status_code}")
                        print(f"   重定向到: {response.headers.get('Location', '无')}")
                    
                    print("\n15. 测试记住我功能（清除session后）:")
                    # 清除session cookie，只保留remember me cookie
                    response = requests.get(base_url, cookies={'remember_me_token': remember_cookie}, allow_redirects=False)
                    print(f"   状态码: {response.status_code}")
                    if response.status_code == 200:
                        print(f"   记住我功能正常，自动登录成功")
                    else:
                        print(f"   记住我功能测试失败")
        
        except requests.exceptions.RequestException as e:
            print(f"请求错误: {e}")
        except Exception as e:
            print(f"测试过程中发生错误: {e}")
    else:
        # 正常启动服务器
        run_server(host='0.0.0.0', port=8080)