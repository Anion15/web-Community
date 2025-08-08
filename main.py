# -*- coding: utf-8 -*-
from datetime import datetime, timedelta
import os
import ipaddress
import base64
import time

try:
    from flask import Flask, render_template, request, jsonify, redirect, url_for, session, g, make_response, Response, render_template_string
except ModuleNotFoundError:
    print("모듈을 찾을 수 없습니다. 'flask'가 설치되어 있는지 확인하세요.")
    while True:
        pass
try:
    from flask_sqlalchemy import SQLAlchemy
except ModuleNotFoundError:
    print("모듈을 찾을 수 없습니다. 'flask_sqlalchemy'가 설치되어 있는지 확인하세요.")
    while True:
        pass
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
except ModuleNotFoundError:
    print("모듈을 찾을 수 없습니다. 'flask_limiter'가 설치되어 있는지 확인하세요.")
    while True:
        pass
try:
    from flask_cors import CORS
except ModuleNotFoundError:
    print("모듈을 찾을 수 없습니다. 'flask_cors'가 설치되어 있는지 확인하세요.")
    while True:
        pass
try:
    from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
except ModuleNotFoundError:
    print("모듈을 찾을 수 없습니다. 'flask_login'가 설치되어 있는지 확인하세요.")
    while True:
        pass
try:
    from datetime import datetime, timedelta, timezone
except ModuleNotFoundError:
    print("모듈을 찾을 수 없습니다. 'datetime'가 설치되어 있는지 확인하세요.")
    while True:
        pass
try:
    import os
except ModuleNotFoundError:
    print("모듈을 찾을 수 없습니다. 'os'가 설치되어 있는지 확인하세요.")
    while True:
        pass
try:
    import uuid
except ModuleNotFoundError:
    print("모듈을 찾을 수 없습니다. 'uuid'가 설치되어 있는지 확인하세요.")
    while True:
        pass
try:
    from werkzeug.security import generate_password_hash, check_password_hash
except ModuleNotFoundError:
    print("모듈을 찾을 수 없습니다. 'werkzeug.security'가 설치되어 있는지 확인하세요.")
    while True:
        pass
try:
    import re
except ModuleNotFoundError:
    print("모듈을 찾을 수 없습니다. 're'가 설치되어 있는지 확인하세요.")
    while True:
        pass
try:
    from dotenv import load_dotenv
except ModuleNotFoundError:
    print("모듈을 찾을 수 없습니다. 'dotenv'가 설치되어 있는지 확인하세요.")
    while True:
        pass
try:
    import threading
except ModuleNotFoundError:
    print("모듈을 찾을 수 없습니다. 'threading'가 설치되어 있는지 확인하세요.")
    while True:
        pass

load_dotenv()
import requests
import logging
from logging.handlers import RotatingFileHandler


def setup_logging(app):
    # 기본 로거 설정
    logging.basicConfig(level=logging.INFO)

    # 인코딩 명시 (Python 3.9 이상에서 사용 가능)
    file_handler = RotatingFileHandler('flask.log', maxBytes=10*1024*1024, backupCount=5, encoding='utf-8')
    file_handler.setLevel(logging.INFO)

    # 로그 포맷 설정
    formatter = logging.Formatter('time: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    file_handler.setFormatter(formatter)

    # Flask 앱 로거에 핸들러 추가
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)





# 필수 환경변수 체크
SECRET_KEY = os.getenv('SECRET_KEY')
if not SECRET_KEY:
    raise ValueError("SECRET_KEY 환경변수가 설정되지 않았습니다.")

app = Flask(__name__)
CORS(app)

# load_dotenv() 다음에 추가
setup_logging(app)

app.secret_key = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///./posts.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True 
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'


total_bytes_lock = threading.Lock()
total_bytes_transferred = 0


# Database & Security
db = SQLAlchemy(app)
limiter = Limiter(app=app, key_func=get_remote_address)
login_manager = LoginManager(app)

# IP 변경 추적을 위한 딕셔너리 (세션 ID: [IP 주소, 타임스탬프])
SESSION_IP_HISTORY = {}
MAX_IP_CHANGES = 3  # 특정 시간 내 허용되는 최대 IP 변경 횟수
IP_CHANGE_TRACKING_WINDOW = timedelta(minutes=5) # IP 변경 추적 기간

# 현재 한국 시간을 얻는 함수 (offset-aware)
def get_korean_time():
    return datetime.now(timezone(timedelta(hours=9)))

def log_activity(action, status_code="", additional_info=""):
    """통합 활동 로그"""
    client_ip = get_real_ip()
    client_uuid = session.get('client_id', 'unknown')
    timestamp = get_korean_time().strftime('%Y-%m-%d %H:%M:%S')
    
    log_message = f"{timestamp} ip: {client_ip}, uuid: {client_uuid} -- {action}"
    if status_code:
        log_message += f" {status_code}"
    if additional_info:
        log_message += f" {additional_info}"
    
    app.logger.info(log_message)

# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    registered_at = db.Column(db.DateTime(timezone=True), default=get_korean_time)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    client_id = db.Column(db.String(36), nullable=False)
    date = db.Column(db.DateTime(timezone=True), default=get_korean_time)
    likes = db.Column(db.Integer, default=0)
    dislikes = db.Column(db.Integer, default=0)
    comments = db.relationship('Comment', backref='post', cascade='all, delete-orphan', lazy='dynamic')

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    client_id = db.Column(db.String(36), nullable=False)
    date = db.Column(db.DateTime(timezone=True), default=get_korean_time)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)


class BannedIP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False)
    reason = db.Column(db.String(200), nullable=True)
    banned_at = db.Column(db.DateTime(timezone=True), default=get_korean_time)


with app.app_context():
    db.create_all()

user_post_times = {}  # client_id: [timestamp, timestamp, timestamp ...]
user_comment_times = {}  # client_id: [timestamp, timestamp, timestamp ...]


ip_post_times = {}  # IP 주소: [timestamp, timestamp, timestamp ...]
ip_comment_times = {}  # IP 주소: [timestamp, timestamp, timestamp ...]



def get_real_ip():
    """
    X-Forwarded-For 헤더를 우선적으로 사용하여 실제 클라이언트 IP를 획득
    프록시/로드밸런서 환경에서 실제 클라이언트 IP를 정확히 가져오기 위함
    """
    # X-Forwarded-For 헤더 확인 (프록시/로드밸런서 환경)
    xff = request.headers.get('X-Forwarded-For')
    if xff:
        # X-Forwarded-For는 "client, proxy1, proxy2" 형태이므로 첫 번째 IP가 실제 클라이언트 IP
        real_ip = xff.split(',')[0].strip()
        return real_ip

    # CF-Connecting-IP 헤더 확인 (Cloudflare 사용시)
    cf_ip = request.headers.get('CF-Connecting-IP')
    if cf_ip:
        return cf_ip.strip()

    # 위 헤더들이 없으면 기본 remote_addr 사용
    return request.remote_addr


#tor 감지 리스트 업데이트
def update_tor_exit_nodes():
    global tor_exit_nodes
    try:
        url = "https://check.torproject.org/torbulkexitlist"
        response = requests.get(url, timeout=5)
        lines = response.text.splitlines()
        tor_exit_nodes = set(line.strip() for line in lines if line and not line.startswith("#"))
        print(f"[TOR] Exit Node 갱신 완료: {len(tor_exit_nodes)}개")
    except Exception as e:
        print(f"[TOR] 업데이트 실패: {e}")

# 최초 1회 실행
update_tor_exit_nodes()

# 1시간마다 TOR Exit Node 리스트 갱신
def schedule_tor_update():
    while True:
        time.sleep(60 * 60)  # 1시간마다
        update_tor_exit_nodes()

threading.Thread(target=schedule_tor_update, daemon=True).start()


# 전역 변수로 VPN/차단된 IP 목록 관리
vpn_list = []
passed_list = []  # 통과한 IP 목록도 추가

def is_valid_ipv4(ip):
    # try:
    #     ip_obj = ipaddress.ip_address(ip)
    #     # IPv4 또는 IPv4-mapped IPv6인지 확인
    #     if ip_obj.version == 4:
    #         return True
    #     if ip_obj.version == 6 and ip_obj.ipv4_mapped:
    #         return True
    #     return False
    # except ValueError:
        return True

def is_vpn(ip):
    # IPv4가 아닌 경우 차단
    # if not is_valid_ipv4(ip):
    #     return True

    # 이미 VPN으로 확인된 IP인지 체크
    if ip in vpn_list:
        return True
    
    # TOR Exit Node 여부 확인
    if ip in tor_exit_nodes:
        log_activity("TOR 브라우저 감지", "403")
        return True
    
    # 이미 통과한 IP인지 체크
    if ip in passed_list:
        return False
    
    # 새로운 IP - API로 검사
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,message,query,proxy,hosting,mobile"
        response = requests.get(url, timeout=3)
        data = response.json()
        
        if data['status'] == 'success':
            is_vpn_result = data.get('proxy', False) or data.get('hosting', False)
            
            if is_vpn_result:
                # VPN/프록시/호스팅 IP
                vpn_list.append(ip)
                return True
            else:
                # 일반 IP
                passed_list.append(ip)
                return False
        else:
            return False
            
    except requests.exceptions.RequestException as e:
        return False



def is_content_spam(title, content):
    # 내용의 반복성 검사
    recent_posts = Post.query.filter_by(client_id=get_session_client_id()).order_by(Post.date.desc()).limit(3).all()
    
    for post in recent_posts:
        # 유사도 계산 (간단한 예)
        title_similarity = len(set(title.split()) & set(post.title.split())) / max(len(set(title.split())), 1)
        content_similarity = len(set(content.split()) & set(post.content.split())) / max(len(set(content.split())), 1)
        
        if title_similarity >= 0.9 or content_similarity >= 0.9:
            return True
    
    return False

# IP 기반 레이트 리미팅 강화
def is_spam_by_ip():
    ip_address = get_real_ip()
    now = datetime.now(timezone.utc)
    # 시간 윈도우를 15초에서 2분으로 늘림
    times = ip_post_times.get(ip_address, [])
    times = [t for t in times if (now - t) < timedelta(seconds=100)]
    times.append(now)
    ip_post_times[ip_address] = times
    # 임계값을 3에서 5로 늘림
    return len(times) >= 5

def is_comment_spam_by_ip():
    ip_address = get_real_ip()
    now = datetime.now(timezone.utc)
    times = ip_comment_times.get(ip_address, [])
    times = [t for t in times if (now - t) < timedelta(seconds=60)]
    times.append(now)
    ip_comment_times[ip_address] = times
    return len(times) >= 10

def check_session_ip_consistency():
    current_ip = get_real_ip()
    if 'ip_history' in session and session['ip_history']:
        latest_ip, _ = session['ip_history'][-1]
        return current_ip == latest_ip
    return True # 세션에 IP 기록이 없으면 일치하는 것으로 간주

def is_valid_client():
    from flask import request

    # 허용된 Origin과 Referer 접두사
    allowed_origin_prefix = 'https://grounds-remark-atomic-dealtime.trycloudflare.com/'
    allowed_referer_prefix = 'https://grounds-remark-atomic-dealtime.trycloudflare.com/'

    # 요청 헤더에서 정보 추출
    origin = request.headers.get('Origin')
    referer = request.headers.get('Referer')
    user_agent = request.headers.get('User-Agent', '')


    # 브라우저 허용 검사
    if not user_agent:
       return False, 'Missing User-Agent'

    user_agent_lower = user_agent.lower()

    # Safari는 크롬과 동일하게 WebKit을 사용하므로 구별 주의
    is_chrome = 'chrome' in user_agent_lower and 'edg' not in user_agent_lower and 'opr' not in user_agent_lower
    is_edge = 'edg' in user_agent_lower
    is_safari = 'safari' in user_agent_lower and 'chrome' not in user_agent_lower and 'chromium' not in user_agent_lower

    if not (is_chrome or is_edge or is_safari):
        return 10, '허용되지 않는 브라우저입니다.\n크롬, 엣지, 사파리로 접속해 주세요.'

    return True, 'Valid Client'

def generate_client_id():
    return str(uuid.uuid4())

def get_session_client_id():
    current_ip = get_real_ip()
    if 'client_id' not in session:
        session['client_id'] = generate_client_id()
        session['ip_history'] = [(current_ip, datetime.now(timezone.utc))] # IP 기록 초기화
        log_activity("클라이언트 uuid 생성")
    elif 'ip_history' in session:
        session['ip_history'].append((current_ip, datetime.now(timezone.utc))) # 현재 IP 기록
    else:
        session['ip_history'] = [(current_ip, datetime.now(timezone.utc))] # 이전 버전 호환

    # 오래된 IP 기록 정리 (선택 사항)
    session['ip_history'] = [(ip, ts) for ip, ts in session['ip_history'] if (datetime.now(timezone.utc) - ts) < timedelta(minutes=10)]
    return session['client_id']

def check_ip_change_frequency():
    client_id = session.get('client_id')
    if not client_id:
        return True  # 세션이 없으면 검사 안함

    ip_history = session.get('ip_history', [])
    current_ip = get_real_ip()
    now_utc = datetime.now(timezone.utc)

    # 오래된 기록 삭제
    ip_history = [(ip, ts) for ip, ts in ip_history if (now_utc - ts) < IP_CHANGE_TRACKING_WINDOW]
    session['ip_history'] = ip_history

    # 현재 IP 추가
    ip_history.append((current_ip, now_utc))

    # 동일 IP가 아니면 변경 횟수 확인
    if ip_history and len(ip_history) > 1 and ip_history[-1][0] != ip_history[-2][0]:
        changed_ips = set(ip for ip, _ in ip_history)
        if len(changed_ips) > MAX_IP_CHANGES:
            return False  # IP 변경 횟수 초과

    return True

def validate_client_id(client_id):
    if not client_id or not isinstance(client_id, str):
        return None

    # UUID 형식에 대한 정규 표현식 검사
    UUID_REGEX = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
    if not UUID_REGEX.match(client_id):
        return None  # 형식이 유효하지 않음

    try:
        # UUID 타입으로 변환 시도 및 값 일치 확인
        val = uuid.UUID(client_id, version=4)
        if str(val) == client_id:
            return client_id
        else:
            return None  # UUID 객체로 변환되었지만 원래 문자열과 다름
    except ValueError:
        # UUID 타입 변환 실패 (형식은 맞지만 UUID 의미 규칙에 위배될 수 있음)
        return None
    

# 비정상 유니코드 포함 여부 검사 (강화 버전)
def contains_invalid_unicode(text):
    if not text:
        return False

    # 다음 비정상 문자들을 막는다:
    # - 방향 제어 문자 (U+202A ~ U+202E)
    # - 추가 제어 문자 (U+2066 ~ U+2069)
    # - 한글 채움 문자 (U+3164)
    # - Zero Width Space (U+200B), Zero Width Non-Joiner (U+200C), Zero Width Joiner (U+200D)
    # - Word Joiner (U+2060), Soft Hyphen (U+00AD), No-Break Space (U+00A0)
    # - Right-to-Left Mark (U+200F), Left-to-Right Mark (U+200E)
    pattern = r'[\u202A-\u202E\u2066-\u2069\u3164\u200B\u200C\u200D\u2060\u00AD\u00A0\u200E\u200F]'
    
    return re.search(pattern, text) is not None


CF_TURNSTILE_SECRET = ""

def verify_turnstile_token(token, remote_ip=None):
    url = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
    data = {
        'secret': CF_TURNSTILE_SECRET,
        'response': token,
    }
    if remote_ip:
        data['remoteip'] = remote_ip
    resp = requests.post(url, data=data)
    if resp.status_code != 200:
        return False
    result = resp.json()
    return result.get("success", False)

def is_ip_banned(ip):
    return BannedIP.query.filter_by(ip_address=ip).first() is not None

@app.before_request
def before_request_func():
    g.request_size = len(request.get_data())

    client_ip = get_real_ip()
    if is_ip_banned(client_ip):
        log_activity("밴된 IP 접속 시도", "403", f"IP: {client_ip}")
        return render_template_string("""
            <!DOCTYPE html>
            <html lang="ko">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <link rel='icon' type="image/png" href="https://raw.githubusercontent.com/Anion15/anion15.github.io/refs/heads/main/Preview.png">
                <title>접근 제한</title>
            </head>
            <body>
                <div style="display: flex; flex-direction: column; justify-content: center; align-items: center; height: 100vh; background-color: #f8f9fa; color: #333; font-family: Arial, sans-serif;">
                    <h1 style="font-size: 72px; margin-bottom: 0; text-align: center;">접근이 제한되었습니다.</h1>
                    <p style="font-size: 18px; margin-top: 10px;">죄송합니다. 현재 이 서비스에 대한 접근 권한이 제한되어 있습니다.</p>
                    <p style="font-size: 18px;">자세한 사항은 관리자에게 문의해 주세요. (Discord ID: coding_09)</p>
                </div>
            </body>
            </html>
        """), 403

@app.after_request
def after_request_func(response):
    global total_bytes_transferred
    response.direct_passthrough = False
    response_data = response.get_data()
    response_size = len(response_data)

    total = g.request_size + response_size

    with total_bytes_lock:
        total_bytes_transferred += total

    # 로그 출력이나 실시간 전송용
    # print(f"총 전송량: {total_bytes_transferred} bytes")
    return response



# 로그인 관리자
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Abuse 체크용 데코레이터 (IP 변경 빈도 체크 추가)
def check_abuse(func):
    def wrapper(*args, **kwargs):
        if not check_ip_change_frequency():
            log_activity("IP 변경횟수 초과 감지", "403")
            return jsonify({'success': False, 'message': '잦은 IP 변경으로 인해 요청이 차단되었습니다.'}), 403
        if not check_session_ip_consistency():
            log_activity("세션 IP 불일치 감지", "403")
            return jsonify({'success': False, 'message': '세션 IP가 일치하지 않습니다. 보안 위험으로 인해 요청이 차단되었습니다.'}), 403
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper

# Routes
@app.route('/')
@check_abuse
def index():
    ip = get_real_ip()
    vpn_used = is_vpn(ip)
    if vpn_used:
        log_activity("VPN 사용 감지", "403")
        return render_template_string("""
            <!DOCTYPE html>
            <html lang="ko">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <link rel='icon' type="image/png" href="https://raw.githubusercontent.com/Anion15/anion15.github.io/refs/heads/main/Preview.png">
                <title>VPN 감지됨</title>
            </head>
            <body>
                <div style="display: flex; flex-direction: column; justify-content: center; align-items: center; height: 100vh; background-color: #f8f9fa; color: #333; font-family: Arial, sans-serif;">
                    <h1 style="font-size: 72px; margin-bottom: 0; text-align: center;">VPN 감지됨</h1>
                    <p style="font-size: 18px; margin-top: 10px;">VPN 또는 프록시가 활성화되어 있습니다.</p>
                    <p style="font-size: 18px;">사이트 이용을 위해 VPN을 해제해 주세요.</p>
                </div>
            </body>
            </html>
        """)
    else:
        valid, message = is_valid_client()
        if valid == 10:
            return render_template_string("""
                <!DOCTYPE html>
                <html lang="ko">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <link rel='icon' type="image/png" href="https://raw.githubusercontent.com/Anion15/anion15.github.io/refs/heads/main/Preview.png">
                    <title>허용되지 않는 브라우저입니다.</title>
                </head>
                <body>
                    <div style="display: flex; flex-direction: column; justify-content: center; align-items: center; height: 100vh; background-color: #f8f9fa; color: #333; font-family: Arial, sans-serif;">
                        <h1 style="font-size: 72px; margin-bottom: 0; text-align: center;">허용되지 않는 브라우저입니다.</h1>
                        <p style="font-size: 18px; margin-top: 10px;">크롬, 엣지, 사파리로 접속해 주세요.</p>
                    </div>
                </body>
                </html>
            """, message=message), 400
        elif not valid:
            # 기타 잘못된 요청 (Referer, User-Agent 누락 등)
            return message, 400
        
        session_client_id = get_session_client_id()
        log_activity("메인루트 접속", "200")
        html = render_template('index.html', client_id=session_client_id)

        response = make_response(html)
        response.headers['Cache-Control'] = 'public, max-age=30'  # 30초 캐시
        return response


# @app.route('/new')
# @check_abuse
# def newindex():
#     ip = get_real_ip()
#     vpn_used = is_vpn(ip)
#     if vpn_used:
#         log_activity("VPN 사용 감지", "403")
#         return render_template_string("""
#             <!DOCTYPE html>
#             <html lang="ko">
#             <head>
#                 <meta charset="UTF-8">
#                 <meta name="viewport" content="width=device-width, initial-scale=1.0">
#                 <title>VPN 감지됨</title>
#             </head>
#             <body>
#                 <div style="display: flex; flex-direction: column; justify-content: center; align-items: center; height: 100vh; background-color: #f8f9fa; color: #333; font-family: Arial, sans-serif;">
#                     <h1 style="font-size: 72px; margin-bottom: 0; text-align: center;">VPN 감지됨</h1>
#                     <p style="font-size: 18px; margin-top: 10px;">VPN 또는 프록시가 활성화되어 있습니다.</p>
#                     <p style="font-size: 18px;">사이트 이용을 위해 VPN을 해제해 주세요.</p>
#                 </div>
#             </body>
#             </html>
#         """)
#     else:
#         valid, message = is_valid_client()
#         if valid == 10:
#             return render_template_string("""
#                 <!DOCTYPE html>
#                 <html lang="ko">
#                 <head>
#                     <meta charset="UTF-8">
#                     <meta name="viewport" content="width=device-width, initial-scale=1.0">
#                     <title>허용되지 않는 브라우저입니다.</title>
#                 </head>
#                 <body>
#                     <div style="display: flex; flex-direction: column; justify-content: center; align-items: center; height: 100vh; background-color: #f8f9fa; color: #333; font-family: Arial, sans-serif;">
#                         <h1 style="font-size: 72px; margin-bottom: 0; text-align: center;">허용되지 않는 브라우저입니다.</h1>
#                         <p style="font-size: 18px; margin-top: 10px;">크롬, 엣지, 사파리로 접속해 주세요.</p>
#                     </div>
#                 </body>
#                 </html>
#             """, message=message), 400
#         elif not valid:
#             # 기타 잘못된 요청 (Referer, User-Agent 누락 등)
#             return message, 400
#         session_client_id = get_session_client_id()
#         log_activity("사용자 /new 접속", "200")
#         return render_template('index.html', client_id=session_client_id)

@app.route('/info')
def info():
    valid, message = is_valid_client()
    if valid == 10:
        return render_template_string("""
            <!DOCTYPE html>
            <html lang="ko">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <link rel='icon' type="image/png" href="https://raw.githubusercontent.com/Anion15/anion15.github.io/refs/heads/main/Preview.png">
                <title>허용되지 않는 브라우저입니다.</title>
            </head>
            <body>
                <div style="display: flex; flex-direction: column; justify-content: center; align-items: center; height: 100vh; background-color: #f8f9fa; color: #333; font-family: Arial, sans-serif;">
                    <h1 style="font-size: 72px; margin-bottom: 0; text-align: center;">허용되지 않는 브라우저입니다.</h1>
                    <p style="font-size: 18px; margin-top: 10px;">크롬, 엣지, 사파리로 접속해 주세요.</p>
                </div>
            </body>
            </html>
        """, message=message), 400
    elif not valid:
        # 기타 잘못된 요청 (Referer, User-Agent 누락 등)
        return message, 400
    session_client_id = get_session_client_id()
    log_activity("사용자 /info 접속", "200")
    html = render_template('info.html', client_id=session_client_id)

    response = make_response(html)
    response.headers['Cache-Control'] = 'public, max-age=60'  # 60초 캐시
    return response

@app.route('/history')
@check_abuse
def history():
    valid, message = is_valid_client()
    if valid == 10:
        return render_template_string("""
            <!DOCTYPE html>
            <html lang="ko">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <link rel='icon' type="image/png" href="https://raw.githubusercontent.com/Anion15/anion15.github.io/refs/heads/main/Preview.png">
                <title>허용되지 않는 브라우저입니다.</title>
            </head>
            <body>
                <div style="display: flex; flex-direction: column; justify-content: center; align-items: center; height: 100vh; background-color: #f8f9fa; color: #333; font-family: Arial, sans-serif;">
                    <h1 style="font-size: 72px; margin-bottom: 0; text-align: center;">허용되지 않는 브라우저입니다.</h1>
                    <p style="font-size: 18px; margin-top: 10px;">크롬, 엣지, 사파리로 접속해 주세요.</p>
                </div>
            </body>
            </html>
        """, message=message), 400
    elif not valid:
        # 기타 잘못된 요청 (Referer, User-Agent 누락 등)
        return message, 400
    session_client_id = get_session_client_id()
    log_activity("사용자 /history 접속", "200")
    html = render_template('history.html', client_id=session_client_id)

    response = make_response(html)
    response.headers['Cache-Control'] = 'public, max-age=60'  # 60초 캐시
    return response

@app.route('/release-notes')
@check_abuse
def release_notes():
    valid, message = is_valid_client()
    if valid == 10:
        return render_template_string("""
            <!DOCTYPE html>
            <html lang="ko">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <link rel='icon' type="image/png" href="https://raw.githubusercontent.com/Anion15/anion15.github.io/refs/heads/main/Preview.png">
                <title>허용되지 않는 브라우저입니다.</title>
            </head>
            <body>
                <div style="display: flex; flex-direction: column; justify-content: center; align-items: center; height: 100vh; background-color: #f8f9fa; color: #333; font-family: Arial, sans-serif;">
                    <h1 style="font-size: 72px; margin-bottom: 0; text-align: center;">허용되지 않는 브라우저입니다.</h1>
                    <p style="font-size: 18px; margin-top: 10px;">크롬, 엣지, 사파리로 접속해 주세요.</p>
                </div>
            </body>
            </html>
        """, message=message), 400
    elif not valid:
        # 기타 잘못된 요청 (Referer, User-Agent 누락 등)
        return message, 400
    session_client_id = get_session_client_id()
    html = render_template('release-notes.html', client_id=session_client_id)

    response = make_response(html)
    response.headers['Cache-Control'] = 'public, max-age=60'  # 60초 캐시
    return response

@app.route('/sitemap.xml')
@check_abuse
def sitemap():
    urls = [
        {
            'loc': 'https://pages-lan-consolidation-seo.trycloudflare.com/',
            'lastmod': '2025-06-23',
            'changefreq': 'daily',
            'priority': '1.0'
        },
        {
            'loc': 'https://pages-lan-consolidation-seo.trycloudflare.com/info',
            'lastmod': '2025-06-23',
            'changefreq': 'weekly',
            'priority': '0.8'
        },
        {
            'loc': 'https://pages-lan-consolidation-seo.trycloudflare.com/history',
            'lastmod': '2025-06-23',
            'changefreq': 'monthly',
            'priority': '0.7'
        },
        {
            'loc': 'https://pages-lan-consolidation-seo.trycloudflare.com/release-notes',
            'lastmod': '2025-06-23',
            'changefreq': 'monthly',
            'priority': '0.7'
        },
    ]

    xml_content = render_template('sitemap.xml', urls=urls)
    return Response(xml_content, mimetype='application/xml')


@app.route('/rss.xml')
@check_abuse
def rss():
    posts = Post.query.order_by(Post.date.desc()).limit(20).all()

    post_list = []
    for post in posts:
        post_list.append({
            'title': post.title,
            'link': f"https://pages-lan-consolidation-seo.trycloudflare.com/rss.xml",
            'description': post.content[:100],  # 일부만 출력
            'pubDate': post.date.strftime('%a, %d %b %Y %H:%M:%S +0900')
        })

    xml = render_template('rss.xml', posts=post_list)
    return Response(xml, mimetype='application/rss+xml')


@app.route('/robots.txt')
def robots_txt():
    content = """
# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
# @@@@- .!@@@;,,,,,,,,,,-@@@@- .!@@@@@=,,,,:@@@@@@@@
# @@@@-  !@@@:          ,@@@@,  !@@@@@~     #@@@@@@@
# @@@@-  !@@@:          ,@@@@-  !@@@@#.     ;@@@@@@@
# @@@@-  !@@@=.   ~$$$$$$@@@@-  !@@@@!   .  ,@@@@@@@
# @@@@-  ,~~$@#-   -#@@@@@$,,.  !@@@@-  ,!   =@@@@@@
# @@@@-     =@@@~   ,=@@@@$     !@@@$   ;#.  ~@@@@@@
# @@@@-     =@@;     .!@@@$     !@@@;   #@:   #@@@@@
# @@@@-  ~;;##~   ,,   ~#@#*=,  !@@@,  -@@$   ;@@@@@
# @@@@-  !@@@:   ~##~   -@@@@-  !@@=   !@@@-  .@@@@@
# @@@@-  !@@@:  !@@@@;  ,@@@@-  !@@:  .#@@@*   *@@@@
# @@@@-  !@@@:.=@@@@@@=.,@@@@-  !@@-,,:@@@@@-,,:@@@@
# @@@@-  !@@@*#@@@@@@@@#~@@@@!;;=@@@@@@@@@@@@@@@@@@@
# @@@@==*$@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
# @@@@@@@$==========$@@@@@@@@@@#===========#@@@@@@@@
# @@@@@=,            ,=@@@@@@@;.            :#@@@@@@
# @@@@$.              .$@@@@@;               ~@@@@@@
# @@@@:   ,,,,,,,,,,.  ~@@@@#.  -~~~~~~~~~-   =@@@@@
# @@@@,  !@@@@@@@@@@*  ,@@@@=  .@@@@@@@@@@@-  !@@@@@
# @@@@-  :$$$$$$$$$$;  ,@@@@$  .#@@@@@@@@@#,  !@@@@@
# @@@@;                :@@@@@.  ...........  .#@@@@@
# @@@@#,              ,#@@@@@*               ;@@@@@@
# @@@@@#:.          .:#@@@@@@@=-.         .,*@@@@@@@
# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

User-agent: *
Allow:/
"""
    return Response(content, mimetype='text/plain')

@app.route('/term')
def term():
    return render_template('term.html')

@app.route('/service-terms')
def serviceterms():
    return render_template('service-terms.html')

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.route('/log', methods=['GET', 'POST'])
def view_log():
    correct_password = 'yxbh.rh0'
    
    # 액션 결과 메시지 초기화
    action_message = None
    action_type = None  # success, error, warning

    if request.method == 'POST':
        password = request.form.get('password')
        action = request.form.get('action')
        
        if password == correct_password:
            session['logged_in'] = True
            
            # IP 밴/언밴 기능
            if action in ['ban', 'unban']:
                ip_to_ban = request.form.get('ip_address')
                
                if action == 'ban' and ip_to_ban:
                    if ip_to_ban == '116.121.168.190':
                        log_activity("특정 IP 밴 시도 거부", "200", f"시도 IP: {ip_to_ban}")
                        action_message = f"IP {ip_to_ban}는 밴할 수 없습니다."
                        action_type = "error"
                    elif not is_ip_banned(ip_to_ban):
                        new_banned_ip = BannedIP(ip_address=ip_to_ban, reason="관리자 수동 밴")
                        db.session.add(new_banned_ip)
                        db.session.commit()
                        log_activity("IP 밴 성공", "200", f"IP: {ip_to_ban}")
                        action_message = f"IP {ip_to_ban} 밴 성공."
                        action_type = "success"
                    else:
                        log_activity("이미 밴된 IP 밴 시도", "200", f"IP: {ip_to_ban}")
                        action_message = f"IP {ip_to_ban}는 이미 밴되어 있습니다."
                        action_type = "warning"
                        
                elif action == 'unban' and ip_to_ban:
                    banned_ip = BannedIP.query.filter_by(ip_address=ip_to_ban).first()
                    if banned_ip:
                        db.session.delete(banned_ip)
                        db.session.commit()
                        log_activity("IP 언밴 성공", "200", f"IP: {ip_to_ban}")
                        action_message = f"IP {ip_to_ban} 언밴 성공."
                        action_type = "success"
                    else:
                        log_activity("밴되지 않은 IP 언밴 시도", "200", f"IP: {ip_to_ban}")
                        action_message = f"IP {ip_to_ban}는 밴되어 있지 않습니다."
                        action_type = "warning"
            
            # 게시물 관련 기능
            elif action == 'edit_post':
                post_id = request.form.get('post_id')
                new_content = request.form.get('new_content')
                post = Post.query.get(post_id)
                if post:
                    old_content = post.content
                    post.content = new_content
                    db.session.commit()
                    log_activity("게시물 수정", "200", f"게시물 ID: {post_id}")
                    action_message = f"게시물 #{post_id} 수정 완료."
                    action_type = "success"
                else:
                    action_message = f"게시물 #{post_id}를 찾을 수 없습니다."
                    action_type = "error"
                    
            elif action == 'delete_post':
                post_id = request.form.get('post_id')
                post = Post.query.get(post_id)
                if post:
                    db.session.delete(post)
                    db.session.commit()
                    log_activity("게시물 삭제", "200", f"게시물 ID: {post_id}")
                    action_message = f"게시물 #{post_id} 삭제 완료."
                    action_type = "success"
                else:
                    action_message = f"게시물 #{post_id}를 찾을 수 없습니다."
                    action_type = "error"
                    
            elif action == 'edit_post_author':
                post_id = request.form.get('post_id')
                new_author = request.form.get('new_author')
                post = Post.query.get(post_id)
                if post:
                    old_author = post.client_id
                    post.client_id = new_author
                    db.session.commit()
                    log_activity("게시물 작성자 수정", "200", f"게시물 ID: {post_id}, {old_author} -> {new_author}")
                    action_message = f"게시물 #{post_id} 작성자를 '{new_author}'로 변경 완료."
                    action_type = "success"
                else:
                    action_message = f"게시물 #{post_id}를 찾을 수 없습니다."
                    action_type = "error"
                    
            elif action == 'edit_post_votes':
                post_id = request.form.get('post_id')
                new_upvotes = request.form.get('new_upvotes')
                new_downvotes = request.form.get('new_downvotes')
                post = Post.query.get(post_id)
                if post:
                    old_up = post.likes
                    old_down = post.dislikes
                    post.likes = int(new_upvotes) if new_upvotes else 0
                    post.dislikes = int(new_downvotes) if new_downvotes else 0
                    db.session.commit()
                    log_activity("게시물 추천수 수정", "200", f"게시물 ID: {post_id}, 추천: {old_up}->{post.likes}, 비추천: {old_down}->{post.dislikes}")
                    action_message = f"게시물 #{post_id} 추천수 수정 완료."
                    action_type = "success"
                else:
                    action_message = f"게시물 #{post_id}를 찾을 수 없습니다."
                    action_type = "error"
            
            # 댓글 관련 기능
            elif action == 'edit_comment':
                comment_id = request.form.get('comment_id')
                new_content = request.form.get('new_content')
                comment = Comment.query.get(comment_id)
                if comment:
                    old_content = comment.text
                    comment.text = new_content
                    db.session.commit()
                    log_activity("댓글 수정", "200", f"댓글 ID: {comment_id}")
                    action_message = f"댓글 #{comment_id} 수정 완료."
                    action_type = "success"
                else:
                    action_message = f"댓글 #{comment_id}를 찾을 수 없습니다."
                    action_type = "error"
                    
            elif action == 'delete_comment':
                comment_id = request.form.get('comment_id')
                comment = Comment.query.get(comment_id)
                if comment:
                    db.session.delete(comment)
                    db.session.commit()
                    log_activity("댓글 삭제", "200", f"댓글 ID: {comment_id}")
                    action_message = f"댓글 #{comment_id} 삭제 완료."
                    action_type = "success"
                else:
                    action_message = f"댓글 #{comment_id}를 찾을 수 없습니다."
                    action_type = "error"
                    
            elif action == 'edit_comment_author':
                comment_id = request.form.get('comment_id')
                new_author = request.form.get('new_author')
                comment = Comment.query.get(comment_id)
                if comment:
                    old_author = comment.client_id
                    comment.client_id = new_author
                    db.session.commit()
                    log_activity("댓글 작성자 수정", "200", f"댓글 ID: {comment_id}, {old_author} -> {new_author}")
                    action_message = f"댓글 #{comment_id} 작성자를 '{new_author}'로 변경 완료."
                    action_type = "success"
                else:
                    action_message = f"댓글 #{comment_id}를 찾을 수 없습니다."
                    action_type = "error"
                    
            return redirect(url_for('view_log'))
            
        else:
            log_activity("/log 비밀번호 틀림", "401")
            return render_template_string("""
            <title>상정인사이드 관리자 패널 접근</title>
            <h3 style="display: flex; justify-content: center; align-items: center;">비밀번호가 틀렸습니다.</h3>
            <form method="POST" style="display: flex; justify-content: center; align-items: center;">
                <input type="password" name="password" placeholder="비밀번호 입력">
                <button type="submit">확인</button>
            </form>
            """)
    else:
        if not session.get('logged_in'):
            return render_template_string("""
            <title>상정인사이드 관리자 패널 접근</title>
            <h3 style="display: flex; justify-content: center; align-items: center;">접근하려면 비밀번호를 입력하세요.</h3>
            <form method="POST" style="display: flex; justify-content: center; align-items: center;">
                <input type="password" name="password" placeholder="비밀번호 입력">
                <button type="submit">확인</button>
            </form>
            """)

    # 로그 파일 처리 (기존 코드와 동일)
    log_path = 'flask.log'
    if not os.path.exists(log_path):
        return "로그 파일이 존재하지 않습니다.", 404

    filter_type = request.args.get('filter', 'today')
    log_activity(f"/log {filter_type} 접속", "200")
    
    now = datetime.now()
    start_date = None
    end_date = None
    title = ""

    if filter_type == 'today':
        start_date = now.replace(hour=0, minute=0, second=0, microsecond=0)
        title = "오늘"
    elif filter_type == 'yesterday':
        start_date = (now - timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
        end_date = now.replace(hour=0, minute=0, second=0, microsecond=0)
        title = "어제"
    elif filter_type == 'week':
        start_date = now - timedelta(days=7)
        title = "지난 1주일"
    elif filter_type == 'month':
        start_date = now - timedelta(days=30)
        title = "지난 1개월"
    elif filter_type == 'year':
        start_date = now - timedelta(days=365)
        title = "지난 1년"
    else:
        start_date = None
        title = "전체"

    filtered_logs = []
    with open(log_path, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            if start_date:
                try:
                    log_date_str = line.split('time: ')[1].split(' ip:')[0].strip()
                    log_date = datetime.strptime(log_date_str, '%Y-%m-%d %H:%M:%S')
                    
                    if filter_type == 'yesterday':
                        if start_date <= log_date < end_date:
                            filtered_logs.append(line.strip())
                    else:
                        if log_date >= start_date:
                            filtered_logs.append(line.strip())
                except (ValueError, IndexError):
                    continue
            else:
                filtered_logs.append(line.strip())

    filtered_logs.reverse()

    banned_ips = BannedIP.query.all()
    banned_ip_list = [b.ip_address for b in banned_ips]

    # 액션 메시지 HTML 생성
    action_message_html = ""
    if action_message:
        message_class = {
            'success': 'success-message',
            'error': 'error-message',
            'warning': 'warning-message'
        }.get(action_type, 'info-message')
        action_message_html = f'<div class="{message_class}">{action_message}</div>'

    return f"""
    <!DOCTYPE html>
    <html lang="ko">
    <head>
        <title>상정인사이드 관리자 패널 - {title}</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link rel='icon' type="image/png" href="https://raw.githubusercontent.com/Anion15/anion15.github.io/refs/heads/main/Preview.png">
        <style>
            /* 기존 스타일 + 추가 스타일 */
            body {{
                font-family: 'Segoe UI', 'Roboto', 'Helvetica Neue', Arial, sans-serif;
                margin: 0;
                padding: 20px;
                background-color: #eef2f6;
                color: #333;
                line-height: 1.6;
            }}

            .container {{
                max-width: 1400px;
                margin: 20px auto;
                background-color: #ffffff;
                border-radius: 10px;
                box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08);
                overflow: hidden;
            }}

            .header-section {{
                padding: 25px 30px;
                background-color: #f7f9fc;
                border-bottom: 1px solid #e0e6ed;
            }}

            .page-title {{
                font-size: 2em;
                color: #2c3e50;
                margin-top: 0;
                margin-bottom: 20px;
                text-align: center;
            }}

            /* 메시지 스타일 */
            .success-message {{
                background-color: #d4edda;
                color: #155724;
                border: 1px solid #c3e6cb;
                border-radius: 5px;
                padding: 12px;
                margin-bottom: 20px;
                font-weight: bold;
            }}

            .error-message {{
                background-color: #f8d7da;
                color: #721c24;
                border: 1px solid #f5c6cb;
                border-radius: 5px;
                padding: 12px;
                margin-bottom: 20px;
                font-weight: bold;
            }}

            .warning-message {{
                background-color: #fff3cd;
                color: #856404;
                border: 1px solid #ffeaa7;
                border-radius: 5px;
                padding: 12px;
                margin-bottom: 20px;
                font-weight: bold;
            }}

            /* 관리 패널 탭 */
            .admin-tabs {{
                display: flex;
                border-bottom: 2px solid #e0e6ed;
                margin-bottom: 25px;
            }}

            .admin-tab {{
                padding: 12px 24px;
                background-color: #f8f9fa;
                border: none;
                cursor: pointer;
                font-size: 1em;
                font-weight: bold;
                color: #495057;
                border-radius: 5px 5px 0 0;
                margin-right: 5px;
                transition: all 0.3s ease;
            }}

            .admin-tab.active {{
                background-color: #007bff;
                color: white;
            }}

            .admin-tab:hover {{
                background-color: #e9ecef;
            }}

            .admin-tab.active:hover {{
                background-color: #0056b3;
            }}

            /* 탭 컨텐츠 */
            .tab-content {{
                display: none;
                padding: 20px;
                background-color: #f8f9fa;
                border-radius: 8px;
                margin-bottom: 20px;
            }}

            .tab-content.active {{
                display: block;
            }}

            /* 필터 버튼 */
            .filters {{
                display: flex;
                flex-wrap: wrap;
                gap: 10px;
                margin-bottom: 20px;
                justify-content: center;
            }}

            .filter-button {{
                display: inline-block;
                padding: 10px 20px;
                background-color: #3498db;
                color: white;
                text-decoration: none;
                border-radius: 5px;
                transition: background-color 0.3s ease, transform 0.2s ease;
                font-weight: bold;
                font-size: 0.95em;
                box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            }}

            .filter-button:hover {{
                background-color: #2980b9;
                transform: translateY(-2px);
            }}

            .filter-button.active {{
                background-color: #2ecc71;
                box-shadow: 0 3px 8px rgba(46, 204, 113, 0.3);
            }}

            /* 통계 */
            .stats {{
                font-size: 1.1em;
                font-weight: bold;
                color: #555;
                text-align: center;
                margin-bottom: 25px;
                padding: 10px;
                background-color: #ecf0f1;
                border-radius: 5px;
            }}

            /* 관리 섹션 */
            .management-section {{
                background-color: #f0f4f7;
                padding: 20px;
                border-radius: 8px;
                margin-bottom: 20px;
                border: 1px solid #dbe3ed;
            }}

            .section-title {{
                font-size: 1.3em;
                color: #34495e;
                margin-top: 0;
                margin-bottom: 15px;
                border-bottom: 2px solid #aebac8;
                padding-bottom: 8px;
            }}

            /* 폼 스타일 */
            .management-form {{
                display: grid;
                gap: 15px;
                margin-bottom: 20px;
            }}

            .form-row {{
                display: flex;
                gap: 10px;
                align-items: center;
                flex-wrap: wrap;
            }}

            .form-group {{
                display: flex;
                flex-direction: column;
                gap: 5px;
            }}

            .form-group label {{
                font-weight: bold;
                color: #495057;
                font-size: 0.9em;
            }}

            .form-input {{
                padding: 10px 12px;
                border: 1px solid #ccc;
                border-radius: 5px;
                font-size: 1em;
                outline: none;
                transition: border-color 0.3s ease, box-shadow 0.3s ease;
                min-width: 150px;
            }}

            .form-input:focus {{
                border-color: #3498db;
                box-shadow: 0 0 0 3px rgba(52, 152, 219, 0.2);
            }}

            .form-textarea {{
                padding: 10px 12px;
                border: 1px solid #ccc;
                border-radius: 5px;
                font-size: 1em;
                outline: none;
                resize: vertical;
                min-height: 80px;
                font-family: inherit;
            }}

            .form-textarea:focus {{
                border-color: #3498db;
                box-shadow: 0 0 0 3px rgba(52, 152, 219, 0.2);
            }}

            /* 버튼 스타일 */
            .action-button {{
                padding: 10px 18px;
                border: none;
                border-radius: 5px;
                cursor: pointer;
                font-size: 1em;
                font-weight: bold;
                color: white;
                transition: background-color 0.3s ease, transform 0.2s ease;
                text-decoration: none;
                display: inline-block;
                text-align: center;
            }}

            .btn-primary {{ background-color: #007bff; }}
            .btn-primary:hover {{ background-color: #0056b3; transform: translateY(-1px); }}

            .btn-success {{ background-color: #28a745; }}
            .btn-success:hover {{ background-color: #218838; transform: translateY(-1px); }}

            .btn-danger {{ background-color: #dc3545; }}
            .btn-danger:hover {{ background-color: #c82333; transform: translateY(-1px); }}

            .btn-warning {{ background-color: #ffc107; color: #212529; }}
            .btn-warning:hover {{ background-color: #e0a800; transform: translateY(-1px); }}

            .btn-info {{ background-color: #17a2b8; }}
            .btn-info:hover {{ background-color: #138496; transform: translateY(-1px); }}

            .btn-secondary {{ background-color: #6c757d; }}
            .btn-secondary:hover {{ background-color: #5a6268; transform: translateY(-1px); }}

            /* 리스트 스타일 */
            .item-list {{
                list-style-type: none;
                padding: 0;
                margin-top: 15px;
            }}

            .item-list-item {{
                background-color: #ffffff;
                border: 1px solid #ddd;
                padding: 15px;
                margin-bottom: 10px;
                border-radius: 5px;
                display: flex;
                justify-content: space-between;
                align-items: center;
                box-shadow: 0 1px 3px rgba(0,0,0,0.05);
            }}

            .item-info {{
                flex-grow: 1;
                margin-right: 15px;
            }}

            .item-info span {{
                font-family: 'Consolas', 'Monaco', monospace;
                font-size: 0.9em;
                color: #444;
                display: block;
                margin-bottom: 5px;
            }}

            .item-actions {{
                display: flex;
                gap: 8px;
            }}

            .no-items {{
                font-style: italic;
                color: #777;
                text-align: center;
                padding: 20px;
                background-color: #f9f9f9;
                border-radius: 5px;
            }}

            /* 로그 컨테이너 */
            .log-container {{
                background-color: #2d3748;
                color: #e2e8f0;
                padding: 25px 30px;
                border-radius: 0 0 10px 10px;
                max-height: 60vh;
                overflow-y: auto;
                font-size: 0.9em;
                line-height: 1.5;
                box-sizing: border-box;
            }}

            .log-line {{
                margin-bottom: 8px;
                padding: 6px 0;
                border-bottom: 1px solid #4a5568;
                word-wrap: break-word;
                white-space: pre-wrap;
                font-family: 'Fira Code', 'JetBrains Mono', 'Courier New', monospace;
                font-size: 0.85em;
            }}

            .log-line:last-child {{
                border-bottom: none;
            }}

            .log-line:hover {{
                background-color: #4a5568;
                cursor: text;
            }}

            .no-log-message {{
                text-align: center;
                padding: 20px;
                font-style: italic;
                color: #bbb;
            }}

            /* 반응형 */
            @media (max-width: 768px) {{
                body {{ padding: 10px; }}
                .header-section {{ padding: 15px 20px; }}
                .page-title {{ font-size: 1.6em; margin-bottom: 15px; }}
                .filters {{ flex-direction: column; align-items: stretch; }}
                .filter-button {{ text-align: center; padding: 10px; }}
                .form-row {{ flex-direction: column; align-items: stretch; }}
                .form-input {{ width: 100%; margin-bottom: 10px; min-width: auto; }}
                .log-container {{ padding: 15px 20px; font-size: 0.8em; }}
                .admin-tabs {{ flex-wrap: wrap; }}
                .admin-tab {{ margin-bottom: 5px; }}
                .item-list-item {{ flex-direction: column; align-items: stretch; }}
                .item-info {{ margin-right: 0; margin-bottom: 10px; }}
                .item-actions {{ justify-content: center; }}
            }}
        </style>
        <script>
            function showTab(tabName) {{
                // 모든 탭 비활성화
                document.querySelectorAll('.admin-tab').forEach(tab => {{
                    tab.classList.remove('active');
                }});
                document.querySelectorAll('.tab-content').forEach(content => {{
                    content.classList.remove('active');
                }});
                
                // 선택된 탭 활성화
                document.querySelector(`[onclick="showTab('${{tabName}}')"]`).classList.add('active');
                document.getElementById(tabName).classList.add('active');
            }}
            
            // 페이지 로드 시 첫 번째 탭 활성화
            window.onload = function() {{
                showTab('ip-management');
            }};
        </script>
    </head>
    <body>
        <div class="container">
            <div class="header-section">
                <h2 class="page-title">상정인사이드 관리자 패널 - {title}</h2>
                <a href="/logoutadmin" class="action-button btn-secondary" style="text-decoration: none;">로그아웃</a>
                
                {action_message_html}
                
                <div class="filters">
                    <a href="/log?filter=today" class="filter-button {'active' if filter_type == 'today' else ''}">오늘</a>
                    <a href="/log?filter=yesterday" class="filter-button {'active' if filter_type == 'yesterday' else ''}">어제</a>
                    <a href="/log?filter=week" class="filter-button {'active' if filter_type == 'week' else ''}">지난 1주일</a>
                    <a href="/log?filter=month" class="filter-button {'active' if filter_type == 'month' else ''}">지난 1개월</a>
                    <a href="/log?filter=year" class="filter-button {'active' if filter_type == 'year' else ''}">지난 1년</a>
                    <a href="/log?filter=all" class="filter-button {'active' if filter_type == 'all' else ''}">전체</a>
                </div>
                
                <div class="stats">총 {len(filtered_logs)}개의 로그</div>

                <!-- 관리 탭 -->
                <div class="admin-tabs">
                    <button class="admin-tab active" onclick="showTab('ip-management')">IP 관리</button>
                    <button class="admin-tab" onclick="showTab('post-management')">게시물 관리</button>
                    <!-- <button class="admin-tab" onclick="showTab('comment-management')">댓글 관리</button> -->
                </div>

                <!-- IP 관리 탭 -->
                <div id="ip-management" class="tab-content active">
                    <div class="management-section">
                        <h4 class="section-title">IP 밴/언밴</h4>
                        <form method="POST" class="management-form">
                            <input type="hidden" name="password" value="{correct_password}">
                            <div class="form-row">
                                <div class="form-group">
                                    <label for="ip_address">IP 주소</label>
                                    <input type="text" id="ip_address" name="ip_address" placeholder="192.168.1.1" required class="form-input">
                                </div>
                                <button type="submit" name="action" value="ban" class="action-button btn-danger">밴</button>
                                <button type="submit" name="action" value="unban" class="action-button btn-success">언밴</button>
                            </div>
                        </form>
                        
                        <h4 class="section-title">현재 밴된 IP 목록</h4>
                        <ul class="item-list">
                            {"".join(f'''
                                <li class="item-list-item">
                                    <div class="item-info">
                                        <span><strong>IP:</strong> {ip}</span>
                                    </div>
                                    <div class="item-actions">
                                        <form method="POST" style="display: inline;">
                                            <input type="hidden" name="password" value="{correct_password}">
                                            <input type="hidden" name="ip_address" value="{ip}">
                                            <button type="submit" name="action" value="unban" class="action-button btn-warning">언밴</button>
                                        </form>
                                    </div>
                                </li>
                            ''' for ip in banned_ip_list) if banned_ip_list else '<li class="no-items">밴된 IP가 없습니다.</li>'}
                        </ul>
                    </div>
                </div>

                <!-- 게시물 관리 탭 -->
                <div id="post-management" class="tab-content">
                    <div class="management-section">
                        <h4 class="section-title">게시물 수정</h4>
                        <form method="POST" class="management-form">
                            <input type="hidden" name="password" value="{correct_password}">
                            <div class="form-row">
                                <div class="form-group">
                                    <label for="post_id_edit">게시물 ID</label>
                                    <input type="number" id="post_id_edit" name="post_id" placeholder="123" required class="form-input">
                                </div>
                            </div>
                            <div class="form-row">
                                <div class="form-group" style="flex-grow: 1;">
                                    <label for="new_content">새 내용</label>
                                    <textarea id="new_content" name="new_content" placeholder="새로운 게시물 내용을 입력하세요..." required class="form-textarea"></textarea>
                                </div>
                            </div>
                            <div class="form-row">
                                <button type="submit" name="action" value="edit_post" class="action-button btn-primary">게시물 수정</button>
                            </div>
                        </form>
                    </div>

                    <div class="management-section">
                        <h4 class="section-title">게시물 삭제</h4>
                        <form method="POST" class="management-form">
                            <input type="hidden" name="password" value="{correct_password}">
                            <div class="form-row">
                                <div class="form-group">
                                    <label for="post_id_delete">게시물 ID</label>
                                    <input type="number" id="post_id_delete" name="post_id" placeholder="123" required class="form-input">
                                </div>
                                <button type="submit" name="action" value="delete_post" class="action-button btn-danger" onclick="return confirm('정말로 이 게시물을 삭제하시겠습니까?')">게시물 삭제</button>
                            </div>
                        </form>
                    </div>

                    <div class="management-section">
                        <h4 class="section-title">게시물 작성자 변경</h4>
                        <form method="POST" class="management-form">
                            <input type="hidden" name="password" value="{correct_password}">
                            <div class="form-row">
                                <div class="form-group">
                                    <label for="post_id_author">게시물 ID</label>
                                    <input type="number" id="post_id_author" name="post_id" placeholder="123" required class="form-input">
                                </div>
                                <div class="form-group">
                                    <label for="new_author_post">새 작성자</label>
                                    <input type="text" id="new_author_post" name="new_author" placeholder="새로운 작성자명" required class="form-input">
                                </div>
                                <button type="submit" name="action" value="edit_post_author" class="action-button btn-info">작성자 변경</button>
                            </div>
                        </form>
                    </div>

                    <div class="management-section">
                        <h4 class="section-title">게시물 추천수/비추천수 수정</h4>
                        <form method="POST" class="management-form">
                            <input type="hidden" name="password" value="{correct_password}">
                            <div class="form-row">
                                <div class="form-group">
                                    <label for="post_id_votes">게시물 ID</label>
                                    <input type="number" id="post_id_votes" name="post_id" placeholder="123" required class="form-input">
                                </div>
                                <div class="form-group">
                                    <label for="new_upvotes">추천수</label>
                                    <input type="number" id="new_upvotes" name="new_upvotes" placeholder="0" min="0" class="form-input">
                                </div>
                                <div class="form-group">
                                    <label for="new_downvotes">비추천수</label>
                                    <input type="number" id="new_downvotes" name="new_downvotes" placeholder="0" min="0" class="form-input">
                                </div>
                                <button type="submit" name="action" value="edit_post_votes" class="action-button btn-secondary">추천수 수정</button>
                            </div>
                        </form>
                    </div>
                </div>

                <!-- 댓글 관리 탭 -->
                <div id="comment-management" class="tab-content">
                    <div class="management-section">
                        <h4 class="section-title">댓글 수정</h4>
                        <form method="POST" class="management-form">
                            <input type="hidden" name="password" value="{correct_password}">
                            <div class="form-row">
                                <div class="form-group">
                                    <label for="comment_id_edit">댓글 ID</label>
                                    <input type="number" id="comment_id_edit" name="comment_id" placeholder="456" required class="form-input">
                                </div>
                            </div>
                            <div class="form-row">
                                <div class="form-group" style="flex-grow: 1;">
                                    <label for="new_comment_content">새 내용</label>
                                    <textarea id="new_comment_content" name="new_content" placeholder="새로운 댓글 내용을 입력하세요..." required class="form-textarea"></textarea>
                                </div>
                            </div>
                            <div class="form-row">
                                <button type="submit" name="action" value="edit_comment" class="action-button btn-primary">댓글 수정</button>
                            </div>
                        </form>
                    </div>

                    <div class="management-section">
                        <h4 class="section-title">댓글 삭제</h4>
                        <form method="POST" class="management-form">
                            <input type="hidden" name="password" value="{correct_password}">
                            <div class="form-row">
                                <div class="form-group">
                                    <label for="comment_id_delete">댓글 ID</label>
                                    <input type="number" id="comment_id_delete" name="comment_id" placeholder="456" required class="form-input">
                                </div>
                                <button type="submit" name="action" value="delete_comment" class="action-button btn-danger" onclick="return confirm('정말로 이 댓글을 삭제하시겠습니까?')">댓글 삭제</button>
                            </div>
                        </form>
                    </div>

                    <div class="management-section">
                        <h4 class="section-title">댓글 작성자 변경</h4>
                        <form method="POST" class="management-form">
                            <input type="hidden" name="password" value="{correct_password}">
                            <div class="form-row">
                                <div class="form-group">
                                    <label for="comment_id_author">댓글 ID</label>
                                    <input type="number" id="comment_id_author" name="comment_id" placeholder="456" required class="form-input">
                                </div>
                                <div class="form-group">
                                    <label for="new_author_comment">새 작성자</label>
                                    <input type="text" id="new_author_comment" name="new_author" placeholder="새로운 작성자명" required class="form-input">
                                </div>
                                <button type="submit" name="action" value="edit_comment_author" class="action-button btn-info">작성자 변경</button>
                            </div>
                        </form>
                    </div>
                </div>

            </div>
            <div class="log-container">
                {"".join(f'<div class="log-line">{log.replace("<", "&lt;").replace(">", "&gt;")}</div>' for log in filtered_logs) if filtered_logs else '<div class="no-log-message">해당 기간에 로그가 없습니다.</div>'}
            </div>
        </div>
    </body>
    </html>
    """

@app.route('/logoutadmin')
def adminlogout():
    if session.get('logged_in'):
        log_activity("관리자 로그아웃", "200")
        session.pop('logged_in', None)
        return render_template_string("""
        <!DOCTYPE html>
        <html lang="ko">
        <head>
            <title>로그아웃 완료</title>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <link rel='icon' type="image/png" href="https://raw.githubusercontent.com/Anion15/anion15.github.io/refs/heads/main/Preview.png">
            <style>
                body {
                    font-family: 'Segoe UI', 'Roboto', 'Helvetica Neue', Arial, sans-serif;
                    margin: 0;
                    padding: 20px;
                    background-color: #eef2f6;
                    color: #333;
                    line-height: 1.6;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    min-height: 100vh;
                }
                .container {
                    max-width: 500px;
                    background-color: #ffffff;
                    border-radius: 10px;
                    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08);
                    padding: 40px;
                    text-align: center;
                }
                h3 {
                    color: #2c3e50;
                    margin-top: 0;
                    margin-bottom: 20px;
                    font-size: 1.5em;
                }
                .message {
                    background-color: #d4edda;
                    color: #155724;
                    border: 1px solid #c3e6cb;
                    border-radius: 5px;
                    padding: 15px;
                    margin-bottom: 20px;
                    font-weight: bold;
                }
                .action-button {
                    padding: 12px 24px;
                    background-color: #007bff;
                    color: white;
                    text-decoration: none;
                    border-radius: 5px;
                    font-weight: bold;
                    transition: background-color 0.3s ease;
                    display: inline-block;
                }
                .action-button:hover {
                    background-color: #0056b3;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h3>로그아웃 완료</h3>
                <div class="message">성공적으로 로그아웃되었습니다.</div>
                <a href="/log" class="action-button">다시 로그인</a>
            </div>
        </body>
        </html>
        """)
    else:
        return redirect(url_for('view_log'))




@app.route('/register', methods=['POST'])
@check_abuse
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'success': False, 'message': '모든 정보를 입력해주세요.'}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({'success': False, 'message': '이미 존재하는 사용자입니다.'}), 400

    hashed_password = generate_password_hash(password)
    new_user = User(username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
@check_abuse
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data.get('username')).first()
    if user and check_password_hash(user.password, data.get('password')):
        login_user(user)
        session.permanent = False # 세션 유지 (원하는 경우)
        return jsonify({'success': True, 'message': '로그인 성공'})
    return jsonify({'success': False, 'message': '로그인 실패'}), 401

@app.route('/logout')
@login_required
@check_abuse
def logout():
    logout_user()
    return jsonify({'success': True, 'message': '로그아웃 완료'})


@app.route('/getdatasize', methods=['GET'])
def get_data_size():
    with total_bytes_lock:
        current_size = total_bytes_transferred
    return jsonify({'total_bytes_transferred': current_size})

@app.route('/posts')
@limiter.limit("10 per second")
@check_abuse
def get_posts():
    is_valid, message = is_valid_client()
    if not is_valid:
        log_activity("요청 url 변조 감지", "400")
        return jsonify({'success': False, 'message': message}), 400
    
    ip = get_real_ip()
    vpn_used = is_vpn(ip)
    if vpn_used:
        # VPN 사용자에게 HTML 페이지 반환
        return render_template_string("""
            <!DOCTYPE html>
            <html lang="ko">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <link rel='icon' type="image/png" href="https://raw.githubusercontent.com/Anion15/anion15.github.io/refs/heads/main/Preview.png">
                <title>VPN 감지됨</title>
            </head>
            <body>
                <div style="display: flex; flex-direction: column; justify-content: center; align-items: center; height: 100vh; background-color: #f8f9fa; color: #333; font-family: Arial, sans-serif;">
                    <h1 style="font-size: 72px; margin-bottom: 0; text-align: center;">VPN 감지됨</h1>
                    <p style="font-size: 18px; margin-top: 10px;">VPN 또는 프록시가 활성화되어 있습니다.</p>
                    <p style="font-size: 18px;">사이트 이용을 위해 VPN을 해제해 주세요.</p>
                </div>
            </body>
            </html>
        """)


    posts = Post.query.order_by(Post.date.desc()).limit(100).all()
    post_list = []
    for post in posts:
        comments = [{'id': c.id, 'text': c.text, 'date': c.date.strftime('%Y-%m-%d %H:%M:%S'), 'client_id': c.client_id} for c in post.comments]
        is_owner = current_user.is_authenticated and current_user.username == post.client_id
        post_list.append({
            'id': post.id,
            'title': post.title,
            'content': post.content,
            'client_id': post.client_id,
            'date': post.date.strftime('%Y-%m-%d %H:%M:%S'),
            'likes': post.likes,
            'dislikes': post.dislikes,
            'comments': comments,
            'is_owner': is_owner
        })
    return jsonify({'posts': post_list, 'success': True})

@app.route('/post', methods=['POST'])
@limiter.limit("10 per minute", key_func=get_remote_address)
@limiter.limit("15 per minute")
@check_abuse
def create_post():
    data = request.get_json()
    turnstile_token = data.get("cf_turnstile_token")
    if not turnstile_token or not verify_turnstile_token(turnstile_token, get_real_ip()):
        log_activity("Turnstile 인증 실패", "400")
        return jsonify({'success': False, 'message': '인증이 올바르게 처리되지 않았습니다. 새로고침 후 다시 시도해 주세요.'}), 400

    is_valid, message = is_valid_client()
    if not is_valid:
        log_activity("요청 url 변조 감지", "400")
        return jsonify({'success': False, 'message': message}), 400

    ip = get_real_ip()
    if is_vpn(ip):
        return jsonify({'success': False, 'message': 'VPN 또는 프록시가 활성화되어 있습니다. 사이트 이용을 위해 VPN을 해제해 주세요.'}), 403

    title = data.get('title')
    content = data.get('content')
    client_id = get_session_client_id()

    if not validate_client_id(client_id):
        log_activity("요청 uuid 변조 감지", "400")
        return jsonify({'success': False, 'message': '유효하지 않은 client_id입니다.'}), 400

    if contains_invalid_unicode(title) or contains_invalid_unicode(content):
        log_activity("요청문에 비정상 유니코드 감지", "400")
        return jsonify({'success': False, 'message': '제목이나 내용에 허용되지 않는 문자가 포함되어 있습니다.'}), 400

    if not title or len(title.strip()) < 1 or len(title) > 50:
        return jsonify({'success': False, 'message': '제목은 1자 이상 50자 이하로 입력해주세요.'}), 400
    if not content or len(content.strip()) < 1 or len(content) > 500:
        return jsonify({'success': False, 'message': '내용은 1자 이상 500자 이하로 입력해주세요.'}), 400


    import re
    ibb_links = re.findall(r'https://i\.ibb\.co/[^\s]+', content)
    if len(ibb_links) > 3:
        log_activity("요청 변조하여 이미지 첨부 시도", "400")
        return jsonify({'success': False, 'message': '이미지는 최대 3개까지 첨부할 수 있습니다.'}), 400

    if is_spam_by_ip():
        log_activity("게시물 도배 감지", "429")
        posts_to_delete = Post.query.filter_by(client_id=client_id).all()
        for post in posts_to_delete:
            db.session.delete(post)
        db.session.commit()
        return jsonify({'message': '도배 감지.'}), 429

    if is_content_spam(title, content):
        return jsonify({'success': False, 'message': '유사한 내용의 게시물이 최근에 작성되었습니다. 다른 내용을 입력해주세요.'}), 429

    new_post = Post(title=title, content=content, client_id=client_id)
    db.session.add(new_post)
    db.session.commit()
    log_activity("게시물 업로드", "200", f"제목: {title[:20]}{'...' if len(title) > 20 else ''}")

    return jsonify({'success': True})




from flask_limiter.errors import RateLimitExceeded

@app.errorhandler(RateLimitExceeded)
def ratelimit_handler(e):
    return jsonify({
        "success": False,
        "message": "10초에 한 번만 누를 수 있습니다. 잠시 후 다시 시도해주세요."
    }), 429


@app.route('/post/<int:post_id>/vote', methods=['POST'])
@check_abuse
@limiter.limit("1 per 10 seconds")
def vote_post(post_id):
    is_valid, message = is_valid_client()
    if not is_valid:
        log_activity("요청 url 변조 감지", "400")
        return jsonify({'success': False, 'message': message}), 400
    
    ip = get_real_ip()
    vpn_used = is_vpn(ip)
    if vpn_used:
        if vpn_used:
            return jsonify({'success': False, 'message': 'VPN 또는 프록시가 활성화되어 있습니다. 사이트 이용을 위해 VPN을 해제해 주세요.'}), 403

    data = request.get_json()
    like = data.get('like', 0)
    dislike = data.get('dislike', 0)

    # like와 dislike 값이 0 또는 1만 허용하도록 검증
    if like not in [0, 1] or dislike not in [0, 1]:
        # log_activity("비정상 추천/비추천 감지", "400", f"like: {like}, dislike: {dislike}번 요청")
        return jsonify({'success': False, 'message': '도배 방지'}), 400


    post = Post.query.get_or_404(post_id)
    post.likes += like
    post.dislikes += dislike
    db.session.commit()

    if like == 1:
        log_activity("추천 업로드", "200")
    elif dislike == 1:
        log_activity("비추천 업로드", "200")
    
    # if (like != 1) or (dislike != 1):
        # log_activity("비정상 추천/비추천 감지", "400", f"like: {like}, dislike: {dislike}번 요청")

    return jsonify({'success': True, 'likes': post.likes, 'dislikes': post.dislikes})

RECAPTCHA_SECRET_KEY = ''

@app.route('/post/<int:post_id>/comment', methods=['POST'])
@check_abuse
def comment_on_post(post_id):
    is_valid, message = is_valid_client()
    if not is_valid:
        log_activity("요청 url 변조 감지", "400")
        return jsonify({'success': False, 'message': message}), 400
    
    ip = get_real_ip()
    vpn_used = is_vpn(ip)
    if vpn_used:
        if vpn_used:
            return jsonify({'success': False, 'message': 'VPN 또는 프록시가 활성화되어 있습니다. 사이트 이용을 위해 VPN을 해제해 주세요.'}), 403

    data = request.get_json()
    text = data.get('text')
    recaptcha_token = data.get('recaptcha_token')
    client_id = get_session_client_id() # 세션에서 client_id 가져오기

    if not validate_client_id(client_id):
        log_activity("요청 uuid 변조 감지", "400")
        return jsonify({'success': False, 'message': '유효하지 않은 client_id입니다.'}), 400

    if not recaptcha_token:
        return jsonify({'success': False, 'message': 'reCAPTCHA 토큰이 없습니다.'})

    recaptcha_response = requests.post(
        'https://www.google.com/recaptcha/api/siteverify',
        data={
            'secret': RECAPTCHA_SECRET_KEY,
            'response': recaptcha_token,
            'remoteip': ip
        }
    )

    result = recaptcha_response.json()

    if not result.get('success', False):
        log_activity("reCAPTCHA 검증 실패", "400")
        return jsonify({'success': False, 'message': 'reCAPTCHA 검증에 실패했습니다.'}), 400
    
    score = result.get('score', 0)
    action = result.get('action', '')
    # 보통 action이 클라이언트 execute 시 설정한 값과 맞는지도 확인함 ('comment' 등)
    if score < 0.5 or action != 'comment':
        log_activity(f"reCAPTCHA 점수 낮음 또는 action 불일치 (score: {score}, action: {action})", "403")
        return jsonify({'success': False, 'message': '로봇으로 판단되어 댓글 작성이 제한되었습니다.'}), 403

    log_activity(f"reCAPTCHA 검증 통과 (score: {score}, action: {action})", "200")
    
    # 비정상 유니코드 포함 여부 검사
    if contains_invalid_unicode(text):
        log_activity("요청문에 비정상 유니코드 감지", "400")
        return jsonify({'success': False, 'message': '댓글에 허용되지 않는 문자가 포함되어 있습니다.'}), 400

    if not text or len(text.strip()) < 1 or len(text) > 500:
        return jsonify({'success': False, 'message': '댓글은 1자 이상 500자 이하로 입력해주세요.'}), 400

    if is_comment_spam_by_ip(): # IP 기반 도배 감지
        log_activity("댓글 도배 감지", "429")
        # 해당 IP 주소로 작성된 최근 댓글 삭제 (도배성 댓글 가정)
        comments_to_delete = Comment.query.filter_by(client_id=client_id).order_by(Comment.date.desc()).limit(5).all() # 최근 5개 댓글 삭제 예시
        for comment in comments_to_delete:
            db.session.delete(comment)
        db.session.commit()
        return jsonify({'message': '도배 감지.'}), 429


    post = Post.query.get_or_404(post_id)

    new_comment = Comment(text=text, client_id=client_id, post_id=post_id)
    db.session.add(new_comment)
    db.session.commit()

    log_activity("댓글 업로드", "200", f"댓글: {text[:30]}{'...' if len(text) > 30 else ''}")
    return jsonify({'success': True, 'comment_id': new_comment.id, 'text': new_comment.text, 'date': new_comment.date.strftime('%Y-%m-%d %H:%M:%S')})

@app.route('/popular_posts', methods=['GET'])
@check_abuse
def get_popular_posts():
    is_valid, message = is_valid_client()
    if not is_valid:
        return jsonify({'success': False, 'message': message}), 400

    popular_posts = Post.query.order_by(Post.likes.desc()).limit(10).all()
    post_list = []
    for post in popular_posts:
        comments = [{'id': c.id, 'text': c.text, 'date': c.date.strftime('%Y-%m-%d %H:%M:%S'), 'client_id': c.client_id} for c in post.comments]
        is_owner = current_user.is_authenticated and current_user.username == post.client_id
        post_list.append({
            'id': post.id,
            'title': post.title,
            'content': post.content,
            'client_id': post.client_id,
            'date': post.date.strftime('%Y-%m-%d %H:%M:%S'),
            'likes': post.likes,
            'dislikes': post.dislikes,
            'comments': comments,
            'is_owner': is_owner
        })
    return jsonify({'success': True, 'posts': post_list})

@app.route('/post_count', methods=['GET'])
@check_abuse
def get_post_count():
    is_valid, message = is_valid_client()
    if not is_valid:
        return jsonify({'success': False, 'message': message}), 400

    count = Post.query.count()
    return jsonify({'success': True, 'count': count})

@app.route('/comment_count', methods=['GET'])
@check_abuse
def get_comment_count():
    is_valid, message = is_valid_client()
    if not is_valid:
        return jsonify({'success': False, 'message': message}), 400

    count = Comment.query.count()
    return jsonify({'success': True, 'count': count})

@app.route('/posts/last_update', methods=['GET'])
@check_abuse
def get_posts_last_update():
    """최신 게시물들의 마지막 업데이트 시간을 반환"""
    is_valid, message = is_valid_client()
    if not is_valid:
        log_activity("요청 url 변조 감지", "400")
        return jsonify({'success': False, 'message': message}), 400
    
    ip = get_real_ip()
    vpn_used = is_vpn(ip)
    if vpn_used:
        return jsonify({'success': False, 'message': 'VPN 또는 프록시가 활성화되어 있습니다. 사이트 이용을 위해 VPN을 해제해 주세요.'}), 403

    try:
        # 최신 게시물의 마지막 업데이트 시간 가져오기
        # 게시물 생성 시간 또는 최신 댓글 시간 중 더 최신 것을 기준으로 함
        latest_post = Post.query.order_by(Post.date.desc()).first()
        latest_comment = Comment.query.order_by(Comment.date.desc()).first()
        
        last_update = None
        if latest_post and latest_comment:
            last_update = max(latest_post.date, latest_comment.date)
        elif latest_post:
            last_update = latest_post.date
        elif latest_comment:
            last_update = latest_comment.date
        
        if last_update:
            # 타임스탬프를 문자열로 변환
            last_update_str = last_update.strftime('%Y-%m-%d %H:%M:%S.%f')
            return jsonify({'success': True, 'last_update': last_update_str})
        else:
            return jsonify({'success': True, 'last_update': None})
            
    except Exception as e:
        return jsonify({'success': False, 'message': '서버 오류가 발생했습니다.'}), 500


@app.route('/popular_posts/last_update', methods=['GET'])
@check_abuse
def get_popular_posts_last_update():
    """인기 게시물들의 마지막 업데이트 시간을 반환"""
    is_valid, message = is_valid_client()
    if not is_valid:
        return jsonify({'success': False, 'message': message}), 400

    ip = get_real_ip()
    vpn_used = is_vpn(ip)
    if vpn_used:
        return jsonify({'success': False, 'message': 'VPN 또는 프록시가 활성화되어 있습니다. 사이트 이용을 위해 VPN을 해제해 주세요.'}), 403

    try:
        # 인기 게시물 상위 10개에 대한 마지막 업데이트 시간
        popular_posts = Post.query.order_by(Post.likes.desc()).limit(10).all()
        
        if not popular_posts:
            return jsonify({'success': True, 'last_update': None})
        
        # 인기 게시물들과 그 댓글들의 최신 업데이트 시간 찾기
        latest_times = []
        
        for post in popular_posts:
            latest_times.append(post.date)
            # 해당 게시물의 최신 댓글 시간도 확인
            latest_comment = Comment.query.filter_by(post_id=post.id).order_by(Comment.date.desc()).first()
            if latest_comment:
                latest_times.append(latest_comment.date)
        
        # 투표(좋아요/싫어요) 변경사항도 고려해야 하는 경우
        # 별도의 vote_log 테이블이 있다면 그것도 확인해야 함
        # 현재는 단순히 게시물과 댓글의 시간만 확인
        
        last_update = max(latest_times) if latest_times else None
        
        if last_update:
            last_update_str = last_update.strftime('%Y-%m-%d %H:%M:%S.%f')
            return jsonify({'success': True, 'last_update': last_update_str})
        else:
            return jsonify({'success': True, 'last_update': None})
            
    except Exception as e:
        return jsonify({'success': False, 'message': '서버 오류가 발생했습니다.'}), 500



# 핫토픽 코드
# 핫토픽 캐시 (글로벌 변수)
hot_topics_cache = {
    'data': [],
    'last_updated': None,
    'updating': False
}

def get_hot_topics_data():
    """핫토픽 데이터를 계산하는 함수"""
    try:
        # 한 달 전 날짜 계산
        one_month_ago = datetime.now() - timedelta(days=30)
        
        # 한 달 내 게시물들 조회
        posts_last_month = Post.query.filter(Post.date >= one_month_ago).all()
        
        if not posts_last_month:
            return []
        
        hot_topics = []
        
        # 각 게시물에 대한 스코어 계산
        scored_posts = []
        for post in posts_last_month:
            comments_count = post.comments.count()
            likes_count = post.likes
            total_score = comments_count + likes_count
            
            scored_posts.append({
                'post': post,
                'comments_count': comments_count,
                'likes_count': likes_count,
                'total_score': total_score
            })
        
        # 1. 댓글+추천이 가장 많은 게시물 (종합 스코어 기준)
        if scored_posts:
            top_total = max(scored_posts, key=lambda x: x['total_score'])
            hot_topics.append({
                'id': top_total['post'].id,
                'title': top_total['post'].title,
                'content': top_total['post'].content,
                'type': 'hot',
                'likes_count': top_total['likes_count'],
                'comments_count': top_total['comments_count'],
                'created_at': top_total['post'].date.isoformat(),
                'client_id': top_total['post'].client_id
            })
        
        # 2. 댓글이 가장 많은 게시물
        if scored_posts:
            top_comments = max(scored_posts, key=lambda x: x['comments_count'])
            # 중복 방지: 이미 추가된 게시물과 다른 경우만 추가
            if top_comments['post'].id != top_total['post'].id:
                hot_topics.append({
                    'id': top_comments['post'].id,
                    'title': top_comments['post'].title,
                    'content': top_comments['post'].content,
                    'type': 'comments',
                    'likes_count': top_comments['likes_count'],
                    'comments_count': top_comments['comments_count'],
                    'created_at': top_comments['post'].date.isoformat(),
                    'client_id': top_comments['post'].client_id
                })
        
        # 3. 추천이 가장 많은 게시물
        if scored_posts:
            top_likes = max(scored_posts, key=lambda x: x['likes_count'])
            # 중복 방지: 이미 추가된 게시물과 다른 경우만 추가
            existing_ids = [topic['id'] for topic in hot_topics]
            if top_likes['post'].id not in existing_ids:
                hot_topics.append({
                    'id': top_likes['post'].id,
                    'title': top_likes['post'].title,
                    'content': top_likes['post'].content,
                    'type': 'likes',
                    'likes_count': top_likes['likes_count'],
                    'comments_count': top_likes['comments_count'],
                    'created_at': top_likes['post'].date.isoformat(),
                    'client_id': top_likes['post'].client_id
                })
        
        # 상위 5개 게시물 추가 (중복 제거)
        remaining_posts = [sp for sp in scored_posts if sp['post'].id not in [topic['id'] for topic in hot_topics]]
        remaining_posts.sort(key=lambda x: x['total_score'], reverse=True)
        
        for post_data in remaining_posts[:5]:  # 최대 5개 더 추가
            hot_topics.append({
                'id': post_data['post'].id,
                'title': post_data['post'].title,
                'content': post_data['post'].content,
                'type': 'hot',
                'likes_count': post_data['likes_count'],
                'comments_count': post_data['comments_count'],
                'created_at': post_data['post'].date.isoformat(),
                'client_id': post_data['post'].client_id
            })
        
        return hot_topics
        
    except Exception as e:
        print(f"핫토픽 데이터 계산 오류: {e}")
        return []

def update_hot_topics_cache():
    """핫토픽 캐시를 업데이트하는 함수"""
    global hot_topics_cache

    if hot_topics_cache['updating']:
        return

    hot_topics_cache['updating'] = True

    try:
        with app.app_context():  # 🔥 여기가 핵심입니다
            new_data = get_hot_topics_data()
            hot_topics_cache['data'] = new_data
            hot_topics_cache['last_updated'] = datetime.now()
            print(f"핫토픽 캐시 업데이트 완료: {len(new_data)}개 항목")
    except Exception as e:
        print(f"핫토픽 캐시 업데이트 오류: {e}")
    finally:
        hot_topics_cache['updating'] = False


def should_update_cache():
    """캐시를 업데이트해야 하는지 확인"""
    if not hot_topics_cache['data']:  # 데이터가 없으면 업데이트
        return True
    
    if not hot_topics_cache['last_updated']:  # 마지막 업데이트 시간이 없으면 업데이트
        return True
    
    # 마지막 업데이트로부터 24시간이 지났으면 업데이트
    time_diff = datetime.now() - hot_topics_cache['last_updated']
    return time_diff.total_seconds() > 86400  # 24시간 = 86400초

def update_cache_in_background():
    """백그라운드에서 캐시 업데이트"""
    def update_task():
        update_hot_topics_cache()
    
    thread = threading.Thread(target=update_task)
    thread.daemon = True
    thread.start()

@app.route('/hot_topics', methods=['GET'])
@check_abuse
def get_hot_topics():
    """핫토픽 API 엔드포인트"""
    is_valid, message = is_valid_client()
    if not is_valid:
        log_activity("요청 url 변조 감지", "400")
        return jsonify({'success': False, 'message': message}), 400
    
    ip = get_real_ip()
    vpn_used = is_vpn(ip)
    if vpn_used:
        return jsonify({'success': False, 'message': 'VPN 또는 프록시가 활성화되어 있습니다. 사이트 이용을 위해 VPN을 해제해 주세요.'}), 403

    try:
        # 캐시 업데이트가 필요한지 확인
        if should_update_cache():
            # 백그라운드에서 캐시 업데이트
            update_cache_in_background()
            
            # 캐시에 데이터가 없으면 즉시 계산
            if not hot_topics_cache['data']:
                hot_topics_cache['data'] = get_hot_topics_data()
                hot_topics_cache['last_updated'] = datetime.now()
        
        # 캐시된 데이터 반환
        return jsonify({
            'success': True,
            'topics': hot_topics_cache['data'],
            'last_updated': hot_topics_cache['last_updated'].isoformat() if hot_topics_cache['last_updated'] else None
        })
        
    except Exception as e:
        log_activity("핫토픽 조회 오류", "500", str(e))
        return jsonify({'success': False, 'message': '서버 오류가 발생했습니다.'}), 500



#이미지 업로드 로직
ip_upload_times = {}  # IP 주소별 최근 업로드 시각 리스트

def is_image_upload_spam():
    ip = get_real_ip()
    now = datetime.now(timezone.utc)
    window = timedelta(seconds=60)  # 60초 동안
    limit = 3  # 3회 이상 업로드 금지

    times = ip_upload_times.get(ip, [])
    # 유효한 시각만 필터링
    times = [t for t in times if now - t < window]
    times.append(now)
    ip_upload_times[ip] = times

    return len(times) > limit

IMGBB_API_KEY = ""

@app.route('/upload', methods=['POST'])
@check_abuse
def upload_image():
    if is_image_upload_spam():
        log_activity("같은 IP의 과도한 이미지 업로드", "429")
        return jsonify({'error': '너무 많은 이미지 업로드가 감지되었습니다. 잠시 후 다시 시도해 주세요.'}), 429

    if 'image' not in request.files:
        return jsonify({'error': '이미지 파일이 없습니다'}), 400

    image_file = request.files['image']
    encoded_image = base64.b64encode(image_file.read()).decode('utf-8')

    payload = {
        'key': IMGBB_API_KEY,
        'image': encoded_image,
        'name': image_file.filename
    }

    res = requests.post('https://api.imgbb.com/1/upload', data=payload)

    if res.status_code == 200:
        data = res.json()
        log_activity("이미지 업로드 성공", "200")
        return jsonify({'url': data['data']['url']})
    else:
        log_activity("이미지 업로드 실패", "500")
        return jsonify({'error': 'imgbb 업로드 실패', 'details': res.text}), 500




# 앱 시작 시 초기 캐시 로드
# 서버 실행
if __name__ == '__main__':
    update_cache_in_background() 
    app.run(host='0.0.0.0', port=5000, debug=True)
