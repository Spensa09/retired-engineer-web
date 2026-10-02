"""TorchLab local server. Python 3.10+, standard library only."""
import argparse
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import urlparse, parse_qs

ROOT = Path(__file__).resolve().parent
DATA = ROOT / 'data'
DB = DATA / 'torchlab.sqlite3'

def connect():
    db = sqlite3.connect(DB, timeout=15)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    return db

def initialize():
    DATA.mkdir(exist_ok=True)
    with connect() as db:
        db.executescript('''
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY, email TEXT NOT NULL UNIQUE, password TEXT NOT NULL,
          salt TEXT NOT NULL, name TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('student','engineer')),
          specialty TEXT NOT NULL DEFAULT '机械工程', bio TEXT NOT NULL DEFAULT '',
          years INTEGER NOT NULL DEFAULT 0, fee TEXT NOT NULL DEFAULT '公益指导',
          available INTEGER NOT NULL DEFAULT 1, created INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions (
          token TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), expires INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS requests (
          id INTEGER PRIMARY KEY, student_id INTEGER NOT NULL REFERENCES users(id),
          engineer_id INTEGER NOT NULL REFERENCES users(id), title TEXT NOT NULL, question TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','active','completed','declined')),
          created INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS messages (
          id INTEGER PRIMARY KEY, request_id INTEGER NOT NULL REFERENCES requests(id),
          sender_id INTEGER NOT NULL REFERENCES users(id), body TEXT NOT NULL, created INTEGER NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_requests_student ON requests(student_id,status);
        CREATE INDEX IF NOT EXISTS idx_requests_engineer ON requests(engineer_id,status);
        CREATE INDEX IF NOT EXISTS idx_messages_request ON messages(request_id,id);
        CREATE TABLE IF NOT EXISTS login_attempts (key TEXT PRIMARY KEY, count INTEGER NOT NULL, expires INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS message_reads (user_id INTEGER NOT NULL REFERENCES users(id), request_id INTEGER NOT NULL REFERENCES requests(id), last_id INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(user_id,request_id));
        CREATE TABLE IF NOT EXISTS administrators (user_id INTEGER PRIMARY KEY REFERENCES users(id));
        ''')
    keyfile=DATA/'admin-setup-key.txt'
    if not keyfile.exists():
        keyfile.write_text(secrets.token_urlsafe(32),encoding='utf-8')

def public_user(row):
    return {**{k:row[k] for k in ('id','name','role','specialty','bio','years','fee','available')},'is_admin':bool(row['is_admin']) if 'is_admin' in row.keys() else False}

def account(db,uid):
    return db.execute('SELECT u.*,EXISTS(SELECT 1 FROM administrators a WHERE a.user_id=u.id) is_admin FROM users u WHERE u.id=?',(uid,)).fetchone()

def password_hash(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), 260000).hex()

class APIError(Exception):
    def __init__(self, message, status=400):
        self.message, self.status = message, status

class Handler(BaseHTTPRequestHandler):
    server_version = 'TorchLab'
    def log_message(self, fmt, *args):
        # Avoid logging query strings and credentials.
        print('%s %s' % (self.command, urlparse(self.path).path))

    def respond(self, value, status=200, cookie=None):
        body = json.dumps(value, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        if cookie: self.send_header('Set-Cookie', cookie)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def user(self, db, required=True):
        cookie = SimpleCookie()
        try: cookie.load(self.headers.get('Cookie',''))
        except Exception: pass
        token = cookie['session'].value if 'session' in cookie else ''
        row = db.execute('SELECT u.*,EXISTS(SELECT 1 FROM administrators a WHERE a.user_id=u.id) is_admin FROM users u JOIN sessions s ON u.id=s.user_id WHERE s.token=? AND s.expires>?', (token,int(time.time()))).fetchone()
        if not row and required: raise APIError('请先登录后继续。',401)
        return row

    def payload(self):
        length = int(self.headers.get('Content-Length','0'))
        if length > 20000: raise APIError('提交内容过长。',413)
        try:
            data = json.loads(self.rfile.read(length) or b'{}')
            if not isinstance(data,dict): raise ValueError()
            return data
        except (ValueError, UnicodeDecodeError): raise APIError('提交格式不正确。')

    def field(self, data, key, maximum=200, minimum=1):
        value = data.get(key,'')
        if not isinstance(value,str): raise APIError('请检查输入内容。')
        value = value.strip()
        if not minimum <= len(value) <= maximum: raise APIError('请完整填写信息，且不要超过长度限制。')
        return value

    def do_GET(self):
        path = urlparse(self.path).path
        if path.startswith('/api/'):
            return self.api('GET',path)
        files = {'/':'index.html','/app.js':'app.js','/style.css':'style.css','/favicon.svg':'favicon.svg'}
        if path not in files: return self.respond({'error':'页面不存在。'},404)
        filename = ROOT / files[path]
        body = filename.read_bytes()
        self.send_response(200)
        mime = {'.html':'text/html','.js':'text/javascript','.css':'text/css','.svg':'image/svg+xml'}
        self.send_header('Content-Type',mime[filename.suffix]+'; charset=utf-8')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Referrer-Policy','same-origin')
        self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        self.send_header('Content-Length',str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        self.api('POST',urlparse(self.path).path)

    def api(self, method, path):
        try:
            # Reject cross-origin writes, including requests from untrusted local web pages.
            host = self.headers.get('Host','')
            if host not in (f'127.0.0.1:{self.server.server_port}',f'localhost:{self.server.server_port}'):
                raise APIError('访问地址不受支持。',403)
            if method == 'POST':
                origin = self.headers.get('Origin')
                if origin and origin not in (f'http://127.0.0.1:{self.server.server_port}',f'http://localhost:{self.server.server_port}'):
                    raise APIError('请求来源不受支持。',403)
                if self.headers.get('Sec-Fetch-Site') == 'cross-site': raise APIError('请求来源不受支持。',403)
                if not self.headers.get('Content-Type','').startswith('application/json'): raise APIError('请使用网页提交。',415)
            with connect() as db:
                if method == 'GET':
                    if path == '/api/admin-setup-status':
                        return self.respond({'needed':not bool(db.execute('SELECT 1 FROM administrators LIMIT 1').fetchone())})
                    if path == '/api/me':
                        u = self.user(db,False)
                        return self.respond({'user':{**public_user(u),'email':u['email']} if u else None})
                    if path == '/api/engineers':
                        rows = db.execute("SELECT * FROM users WHERE role='engineer' AND available=1 ORDER BY created DESC").fetchall()
                        return self.respond({'engineers':[public_user(r) for r in rows]})
                    u = self.user(db)
                    if path.startswith('/api/admin/'):
                        if not u['is_admin']: raise APIError('只有管理员可以访问管理后台。',403)
                        if path == '/api/admin/overview':
                            users=db.execute('SELECT u.*,EXISTS(SELECT 1 FROM administrators a WHERE a.user_id=u.id) is_admin FROM users u ORDER BY created DESC,id DESC').fetchall()
                            rows=db.execute('''SELECT r.*,s.name student_name,e.name engineer_name,e.specialty,
                            (SELECT COUNT(*) FROM messages m WHERE m.request_id=r.id) message_count
                            FROM requests r JOIN users s ON s.id=r.student_id JOIN users e ON e.id=r.engineer_id ORDER BY r.created DESC,r.id DESC''').fetchall()
                            return self.respond({'users':[{**public_user(x),'email':x['email'],'created':x['created']} for x in users],'requests':[dict(x) for x in rows],'message_count':db.execute('SELECT COUNT(*) FROM messages').fetchone()[0]})
                        if path == '/api/admin/conversation':
                            rid=int(parse_qs(urlparse(self.path).query).get('request_id',['0'])[0])
                            r=db.execute('SELECT r.*,s.name student_name,e.name engineer_name FROM requests r JOIN users s ON s.id=r.student_id JOIN users e ON e.id=r.engineer_id WHERE r.id=?',(rid,)).fetchone()
                            if not r: raise APIError('咨询不存在。',404)
                            rows=db.execute('SELECT m.*,u.name sender_name FROM messages m JOIN users u ON u.id=m.sender_id WHERE request_id=? ORDER BY m.id',(rid,)).fetchall()
                            return self.respond({'request':dict(r),'messages':[dict(x) for x in rows]})
                        raise APIError('接口不存在。',404)
                    if path == '/api/requests':
                        rows = db.execute('''SELECT r.*, s.name student_name,e.name engineer_name,e.specialty,e.bio,e.years
                          FROM requests r JOIN users s ON s.id=r.student_id JOIN users e ON e.id=r.engineer_id
                          WHERE r.student_id=? OR r.engineer_id=? ORDER BY r.created DESC,r.id DESC''',(u['id'],u['id'])).fetchall()
                        result=[]
                        for r in rows:
                            unread=db.execute('SELECT COUNT(*) FROM messages WHERE request_id=? AND sender_id!=? AND id>COALESCE((SELECT last_id FROM message_reads WHERE user_id=? AND request_id=?),0)',(r['id'],u['id'],u['id'],r['id'])).fetchone()[0]
                            result.append({**dict(r),'unread':unread})
                        return self.respond({'requests':result})
                    if path == '/api/messages':
                        query = parse_qs(urlparse(self.path).query)
                        rid = int(query.get('request_id',['0'])[0])
                        request = db.execute('SELECT * FROM requests WHERE id=?',(rid,)).fetchone()
                        self.check_member(request,u)
                        if request['status'] not in ('active','completed'): raise APIError('申请通过后才能查看聊天。',403)
                        rows=db.execute('SELECT m.*,u.name sender_name FROM messages m JOIN users u ON u.id=m.sender_id WHERE request_id=? ORDER BY m.id',(rid,)).fetchall()
                        return self.respond({'messages':[dict(r) for r in rows]})
                    raise APIError('接口不存在。',404)
                data = self.payload()
                if path == '/api/admin-setup':
                    supplied=self.field(data,'setup_key',100)
                    expected=(DATA/'admin-setup-key.txt').read_text(encoding='utf-8').strip()
                    if not hmac.compare_digest(supplied,expected): raise APIError('管理员初始化密钥不正确。',403)
                    email=self.field(data,'email',254).lower()
                    password=self.field(data,'password',128,8)
                    name=self.field(data,'name',40)
                    if '@' not in email or '.' not in email.split('@')[-1] or ' ' in email: raise APIError('请输入有效邮箱。')
                    db.execute('BEGIN IMMEDIATE')
                    if db.execute('SELECT 1 FROM administrators LIMIT 1').fetchone(): raise APIError('管理员已创建，请使用管理员登录。',409)
                    existing=db.execute('SELECT * FROM users WHERE email=?',(email,)).fetchone()
                    if existing:
                        if not hmac.compare_digest(existing['password'],password_hash(password,existing['salt'])): raise APIError('该邮箱已注册，请输入该账号的正确密码。',403)
                        uid=existing['id']
                    else:
                        salt=secrets.token_hex(16)
                        uid=db.execute("INSERT INTO users(email,password,salt,name,role,created) VALUES(?,?,?,?,'student',?)",(email,password_hash(password,salt),salt,name,int(time.time()))).lastrowid
                    db.execute('INSERT INTO administrators(user_id) VALUES(?)',(uid,))
                    db.execute('DELETE FROM sessions WHERE user_id=?',(uid,))
                    db.commit()
                    return self.respond({'ok':True})
                if path in ('/api/register','/api/login'):
                    email = self.field(data,'email',254).lower()
                    password = self.field(data,'password',128,8)
                    if '@' not in email or '.' not in email.split('@')[-1] or ' ' in email: raise APIError('请输入有效的邮箱地址。')
                    key = hashlib.sha256((self.client_address[0]+email).encode()).hexdigest()
                    attempt = db.execute('SELECT * FROM login_attempts WHERE key=?',(key,)).fetchone()
                    if attempt and attempt['expires']>time.time() and attempt['count']>=10: raise APIError('尝试次数过多，请 15 分钟后再试。',429)
                    if path == '/api/register':
                        name=self.field(data,'name',40)
                        role=data.get('role')
                        if role not in ('student','engineer'): raise APIError('请选择账号身份。')
                        salt=secrets.token_hex(16)
                        try:
                            cur=db.execute('INSERT INTO users(email,password,salt,name,role,created) VALUES(?,?,?,?,?,?)',(email,password_hash(password,salt),salt,name,role,int(time.time())))
                        except sqlite3.IntegrityError: raise APIError('该邮箱已注册，请登录。',409)
                        uid=cur.lastrowid
                    else:
                        u=db.execute('SELECT * FROM users WHERE email=?',(email,)).fetchone()
                        if not u or not hmac.compare_digest(u['password'],password_hash(password,u['salt'])):
                            db.execute('INSERT INTO login_attempts(key,count,expires) VALUES(?,1,?) ON CONFLICT(key) DO UPDATE SET count=CASE WHEN expires>? THEN count+1 ELSE 1 END, expires=?',(key,int(time.time())+900,int(time.time()),int(time.time())+900))
                            db.commit()
                            raise APIError('邮箱或密码不正确。',401)
                        uid=u['id']
                        selected=data.get('role')
                        is_admin=bool(account(db,uid)['is_admin'])
                        if selected is not None and (selected not in ('student','engineer','admin') or (selected=='admin' and not is_admin) or (selected!='admin' and (u['role']!=selected or is_admin))):
                            raise APIError('账号身份与所选入口不一致，请选择正确身份登录。',403)
                        db.execute('DELETE FROM login_attempts WHERE key=?',(key,))
                    token=secrets.token_urlsafe(32)
                    db.execute('DELETE FROM sessions WHERE expires<?',(int(time.time()),))
                    db.execute('INSERT INTO sessions VALUES(?,?,?)',(token,uid,int(time.time())+7*86400))
                    db.commit()
                    u=account(db,uid)
                    return self.respond({'user':{**public_user(u),'email':u['email']}},cookie=f'session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=604800')
                u=self.user(db)
                if path == '/api/logout':
                    cookie=SimpleCookie(self.headers.get('Cookie',''))
                    if 'session' in cookie: db.execute('DELETE FROM sessions WHERE token=?',(cookie['session'].value,))
                    db.commit()
                    return self.respond({'ok':True},cookie='session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0')
                if path == '/api/profile':
                    name=self.field(data,'name',40)
                    bio=self.field(data,'bio',1500,0)
                    specialty=self.field(data,'specialty',40)
                    if specialty not in ('机械工程','电子工程','土木工程','环境工程','计算机工程','航空航天'): raise APIError('请选择有效专业。')
                    years=int(data.get('years',0))
                    if not 0<=years<=70: raise APIError('从业年限需在 0–70 年之间。')
                    fee=self.field(data,'fee',40)
                    if fee not in ('公益指导','低收费 · 面议'): raise APIError('请选择指导方式。')
                    available=1 if data.get('available') is True else 0
                    db.execute('UPDATE users SET name=?,bio=?,specialty=?,years=?,fee=?,available=? WHERE id=?',(name,bio,specialty,years,fee,available,u['id']))
                    db.commit()
                    return self.respond({'ok':True})
                if path == '/api/requests':
                    if u['role']!='student': raise APIError('学生账号可以申请指导。',403)
                    eid=int(data.get('engineer_id',0))
                    eng=db.execute("SELECT * FROM users WHERE id=? AND role='engineer' AND available=1",(eid,)).fetchone()
                    if not eng: raise APIError('这位工程师暂未开放预约。',404)
                    title=self.field(data,'title',100)
                    question=self.field(data,'question',3000,10)
                    cur=db.execute('INSERT INTO requests(student_id,engineer_id,title,question,created) VALUES(?,?,?,?,?)',(u['id'],eid,title,question,int(time.time())))
                    db.commit()
                    return self.respond({'id':cur.lastrowid},201)
                if path == '/api/request-status':
                    rid=int(data.get('id',0))
                    r=db.execute('SELECT * FROM requests WHERE id=?',(rid,)).fetchone()
                    self.check_member(r,u)
                    status=data.get('status')
                    if u['id']!=r['engineer_id']: raise APIError('只有对应工程师可以处理申请。',403)
                    if not ((r['status']=='pending' and status in ('active','declined')) or (r['status']=='active' and status=='completed')):
                        raise APIError('当前状态无法执行此操作。',409)
                    cur=db.execute('UPDATE requests SET status=? WHERE id=? AND status=?',(status,rid,r['status']))
                    if cur.rowcount!=1: raise APIError('申请状态已变化，请刷新。',409)
                    db.commit()
                    return self.respond({'ok':True})
                if path == '/api/messages':
                    rid=int(data.get('request_id',0))
                    r=db.execute('SELECT * FROM requests WHERE id=?',(rid,)).fetchone()
                    self.check_member(r,u)
                    if r['status']!='active': raise APIError('只有正在咨询的项目可以发送消息。',403)
                    body=self.field(data,'body',3000)
                    cur=db.execute("INSERT INTO messages(request_id,sender_id,body,created) SELECT id,?,?,? FROM requests WHERE id=? AND status='active'",(u['id'],body,int(time.time()),rid))
                    if cur.rowcount!=1: raise APIError('咨询状态已变化，请刷新。',409)
                    db.commit()
                    return self.respond({'id':cur.lastrowid},201)
                if path == '/api/message-read':
                    rid=int(data.get('request_id',0))
                    r=db.execute('SELECT * FROM requests WHERE id=?',(rid,)).fetchone()
                    self.check_member(r,u)
                    last_id=int(data.get('last_id',0))
                    maximum=db.execute('SELECT COALESCE(MAX(id),0) FROM messages WHERE request_id=?',(rid,)).fetchone()[0]
                    last_id=max(0,min(last_id,maximum))
                    db.execute('INSERT INTO message_reads(user_id,request_id,last_id) VALUES(?,?,?) ON CONFLICT(user_id,request_id) DO UPDATE SET last_id=MAX(last_id,excluded.last_id)',(u['id'],rid,last_id))
                    db.commit()
                    return self.respond({'ok':True})
                raise APIError('接口不存在。',404)
        except APIError as e: self.respond({'error':e.message},e.status)
        except (ValueError,TypeError): self.respond({'error':'请检查输入内容。'},400)
        except Exception as e:
            print('Server error:',type(e).__name__)
            self.respond({'error':'暂时无法完成操作，请稍后重试。'},500)

    def check_member(self,r,u):
        if not r or u['id'] not in (r['student_id'],r['engineer_id']): raise APIError('无法访问该咨询。',403)

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--port',type=int,default=8765)
    args=parser.parse_args()
    initialize()
    server=ThreadingHTTPServer(('127.0.0.1',args.port),Handler)
    print(f'TorchLab ready: http://127.0.0.1:{args.port}',flush=True)
    try: server.serve_forever()
    except KeyboardInterrupt: pass
    finally: server.server_close()
