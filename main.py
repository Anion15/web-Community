# -*- coding: utf-8 -*-
try:
    from flask import Flask, render_template, request, jsonify, redirect, url_for, session, g
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
    from werkzeug.security import generate_password_hash, check_password_hash
except ModuleNotFoundError:
    print("모듈을 찾을 수 없습니다. 'werkzeug.security'가 설치되어 있는지 확인하세요.")
    while True:
        pass
try:
    from dotenv import load_dotenv
except ModuleNotFoundError:
    print("모듈을 찾을 수 없습니다. 'dotenv'가 설치되어 있는지 확인하세요.")
    while True:
        pass

from datetime import datetime, timedelta, timezone
import os
import uuid
import re
import threading

load_dotenv()

# 필수 환경변수 체크
SECRET_KEY = os.getenv('SECRET_KEY')
if not SECRET_KEY:
    raise ValueError("SECRET_KEY 환경변수가 설정되지 않았습니다.")

app = Flask(__name__)
CORS(app)
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

with app.app_context():
    db.create_all()

user_post_times = {}  # client_id: [timestamp, timestamp, timestamp ...]
user_comment_times = {}  # client_id: [timestamp, timestamp, timestamp ...]


ip_post_times = {}  # IP 주소: [timestamp, timestamp, timestamp ...]
ip_comment_times = {}  # IP 주소: [timestamp, timestamp, timestamp ...]


def is_content_spam(title, content):
    # 내용의 반복성 검사
    recent_posts = Post.query.filter_by(client_id=get_session_client_id()).order_by(Post.date.desc()).limit(5).all()
    
    for post in recent_posts:
        # 유사도 계산 (간단한 예)
        title_similarity = len(set(title.split()) & set(post.title.split())) / max(len(set(title.split())), 1)
        content_similarity = len(set(content.split()) & set(post.content.split())) / max(len(set(content.split())), 1)
        
        if title_similarity > 0.7 or content_similarity > 0.7:
            return True
    
    return False

# IP 기반 레이트 리미팅 강화
def is_spam_by_ip():
    ip_address = request.remote_addr
    now = datetime.now(timezone.utc)
    # 시간 윈도우를 15초에서 2분으로 늘림
    times = ip_post_times.get(ip_address, [])
    times = [t for t in times if (now - t) < timedelta(minutes=2)]
    times.append(now)
    ip_post_times[ip_address] = times
    # 임계값을 3에서 5로 늘림
    return len(times) >= 5

def is_comment_spam_by_ip():
    ip_address = request.remote_addr
    now = datetime.now(timezone.utc)
    times = ip_comment_times.get(ip_address, [])
    times = [t for t in times if (now - t) < timedelta(seconds=10)]
    times.append(now)
    ip_comment_times[ip_address] = times
    return len(times) >= 5

def check_session_ip_consistency():
    current_ip = request.remote_addr
    if 'ip_history' in session and session['ip_history']:
        latest_ip, _ = session['ip_history'][-1]
        return current_ip == latest_ip
    return True # 세션에 IP 기록이 없으면 일치하는 것으로 간주

def is_valid_client():
    # 허용된 Origin과 Referer 접두사
    #allowed_origin_prefix = 'https://workout-tasks-facing-kate.trycloudflare.com/'
    #allowed_referer_prefix = 'https://workout-tasks-facing-kate.trycloudflare.com/'

    # 요청 헤더에서 정보 추출
    origin = request.headers.get('Origin')
    referer = request.headers.get('Referer')
    user_agent = request.headers.get('User-Agent')

    # Origin, Referer가 허용된 접두사로 시작하는지 확인
    # if origin and not origin.startswith(allowed_origin_prefix):
    #     return False, 'Invalid Origin'

    #if referer and not referer.startswith(allowed_referer_prefix):
    #    return False, 'Invalid Referer'

    # User-Agent 검증 (예시로 특정 User-Agent만 허용)
    # if not user_agent or 'Mozilla' not in user_agent:
    #     return False, 'Invalid User-Agent'

    return True, 'Valid Client'

def generate_client_id():
    return str(uuid.uuid4())

def get_session_client_id():
    current_ip = request.remote_addr
    if 'client_id' not in session:
        session['client_id'] = generate_client_id()
        session['ip_history'] = [(current_ip, datetime.now(timezone.utc))] # IP 기록 초기화
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
    current_ip = request.remote_addr
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

@app.before_request
def before_request_func():
    g.request_size = len(request.get_data())

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
    print(f"총 전송량: {total_bytes_transferred} bytes")
    return response



# 로그인 관리자
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Abuse 체크용 데코레이터 (IP 변경 빈도 체크 추가)
def check_abuse(func):
    def wrapper(*args, **kwargs):
        if not check_ip_change_frequency():
            return jsonify({'success': False, 'message': '잦은 IP 변경으로 인해 요청이 차단되었습니다.'}), 403
        if not check_session_ip_consistency():
            return jsonify({'success': False, 'message': '세션 IP가 일치하지 않습니다. 보안 위험으로 인해 요청이 차단되었습니다.'}), 403
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper

# Routes
@app.route('/')
@check_abuse
def index():
    session_client_id = get_session_client_id()
    return render_template('index.html', client_id=session_client_id)

@app.route('/new')
@check_abuse
def newindex():
    session_client_id = get_session_client_id()
    return render_template('indexV2.html', client_id=session_client_id)

@app.route('/info')
def info():
    session_client_id = get_session_client_id()
    return render_template('info.html', client_id=session_client_id)

@app.route('/history')
@check_abuse
def history():
    session_client_id = get_session_client_id()
    return render_template('history.html', client_id=session_client_id)

@app.route('/release-notes')
@check_abuse
def release_notes():
    session_client_id = get_session_client_id()
    return render_template('release-notes.html', client_id=session_client_id)

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404



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
        return jsonify({'success': False, 'message': message}), 400

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
@limiter.limit("15 per minute") # 추가적인 분당 제한
@check_abuse
def create_post():
    is_valid, message = is_valid_client()
    if not is_valid:
        return jsonify({'success': False, 'message': message}), 400

    data = request.get_json()
    title = data.get('title')
    content = data.get('content')
    client_id = get_session_client_id() # 세션에서 client_id 가져오기

    if not validate_client_id(client_id):
        return jsonify({'success': False, 'message': '유효하지 않은 client_id입니다.'}), 400

    # 비정상 유니코드 포함 검사
    if contains_invalid_unicode(title) or contains_invalid_unicode(content):
        return jsonify({'success': False, 'message': '제목이나 내용에 허용되지 않는 문자가 포함되어 있습니다.'}), 400


    if not title or len(title.strip()) < 1 or len(title) > 50:
        return jsonify({'success': False, 'message': '제목은 1자 이상 50자 이하로 입력해주세요.'}), 400
    if not content or len(content.strip()) < 1 or len(content) > 500:
        return jsonify({'success': False, 'message': '내용은 1자 이상 500자 이하로 입력해주세요.'}), 400
    if is_spam_by_ip(): # IP 기반 도배 감지
        # 해당 IP 주소로 작성된 모든 게시물 삭제
        posts_to_delete = Post.query.filter_by(client_id=client_id).all() # client_id 기반으로 삭제 (세션 유지 가정)
        for post in posts_to_delete:
            db.session.delete(post)
        db.session.commit()
        return jsonify({'message': '도배 감지.'}), 429
    
    # 내용 기반 도배 감지 추가
    if is_content_spam(title, content):
        return jsonify({'success': False, 'message': '유사한 내용의 게시물이 최근에 작성되었습니다. 다른 내용을 입력해주세요.'}), 429


    new_post = Post(title=title, content=content, client_id=client_id)
    db.session.add(new_post)
    db.session.commit()

    return jsonify({'success': True})

@app.route('/post/<int:post_id>/vote', methods=['POST'])
@check_abuse
def vote_post(post_id):
    is_valid, message = is_valid_client()
    if not is_valid:
        return jsonify({'success': False, 'message': message}), 400

    data = request.get_json()
    like = data.get('like', 0)
    dislike = data.get('dislike', 0)

    # like와 dislike 값이 0 또는 1만 허용하도록 검증
    if like not in [0, 1] or dislike not in [0, 1]:
        return jsonify({'success': False, 'message': '도배 방지.'}), 400


    post = Post.query.get_or_404(post_id)
    post.likes += like
    post.dislikes += dislike
    db.session.commit()
    return jsonify({'success': True, 'likes': post.likes, 'dislikes': post.dislikes})

@app.route('/post/<int:post_id>/comment', methods=['POST'])
@check_abuse
def comment_on_post(post_id):
    is_valid, message = is_valid_client()
    if not is_valid:
        return jsonify({'success': False, 'message': message}), 400

    data = request.get_json()
    text = data.get('text')
    client_id = get_session_client_id() # 세션에서 client_id 가져오기

    if not validate_client_id(client_id):
        return jsonify({'success': False, 'message': '유효하지 않은 client_id입니다.'}), 400

    # 비정상 유니코드 포함 여부 검사
    if contains_invalid_unicode(text):
        return jsonify({'success': False, 'message': '댓글에 허용되지 않는 문자가 포함되어 있습니다.'}), 400

    if not text or len(text.strip()) < 1 or len(text) > 500:
        return jsonify({'success': False, 'message': '댓글은 1자 이상 500자 이하로 입력해주세요.'}), 400

    if is_comment_spam_by_ip(): # IP 기반 도배 감지
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

# 관리자 비밀번호 (하드코딩)
ADMIN_PASSWORD = app.secret_key

@app.route('/super', methods=['GET', 'POST'])
def super_page():
    if request.method == 'POST':
        entered_password = request.form.get('password')
        if entered_password == ADMIN_PASSWORD:
            return redirect(url_for('admin_dashboard'))
        else:
            return render_template('super.html', error="비밀번호가 틀렸습니다.")
    return render_template('super.html')

@app.route('/admin_dashboard')
def admin_dashboard():
    posts = Post.query.order_by(Post.date.desc()).all()

    # 댓글에 작성자 정보(user) 추가하기
    for post in posts:
        for comment in post.comments:
            # comment.user를 통해 작성자 정보 가져오기
            comment.user = User.query.filter_by(id=comment.client_id).first()

    return render_template('admin_dashboard.html', posts=posts)

@app.route('/admin/edit_post/<int:post_id>', methods=['GET', 'POST'])
def edit_post(post_id):
    post = Post.query.get_or_404(post_id)
    if request.method == 'POST':
        post.title = request.form.get('title')
        post.content = request.form.get('content')
        db.session.commit()
        return redirect(url_for('admin_dashboard'))
    return render_template('edit_post.html', post=post)

@app.route('/admin/delete_post/<int:post_id>', methods=['POST'])
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    db.session.delete(post)
    db.session.commit()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_comment/<int:comment_id>', methods=['POST'])
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    db.session.delete(comment)
    db.session.commit()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/edit_comment/<int:comment_id>', methods=['POST'])
def edit_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    new_text = request.form.get('new_text')
    if new_text:
        comment.text = new_text
        db.session.commit()
    return redirect(url_for('admin_dashboard'))

# 서버 실행
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
