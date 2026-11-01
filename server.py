import hmac
import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps
from zoneinfo import ZoneInfo

from dotenv import load_dotenv
from email_validator import EmailNotValidError, validate_email
from flask import Flask, g, jsonify, request, session
from flask_cors import CORS
from itsdangerous import BadData, URLSafeTimedSerializer
from werkzeug.exceptions import BadRequest, HTTPException

load_dotenv()
DB_PATH = os.getenv('DB_PATH', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'workshop.db'))
BEIRUT = ZoneInfo('Asia/Beirut')
DEFAULT_DEADLINE = os.getenv('ORDER_DEADLINE', '2026-12-31T23:59:59+02:00')
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16384
app.config.update(
    SECRET_KEY=os.getenv('ADMIN_SESSION_SECRET') or os.getenv('ADMIN_CODE') or secrets.token_hex(32),
    PERMANENT_SESSION_LIFETIME=timedelta(days=30),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE=os.getenv('SESSION_COOKIE_SAMESITE', 'Lax'),
    SESSION_COOKIE_SECURE=os.getenv('SESSION_COOKIE_SECURE', '').lower() in ('1', 'true', 'yes'),
)
CORS(app, origins=os.getenv('FRONTEND_ORIGIN', '*'), supports_credentials=True)


def beirut_datetime(value):
    if not isinstance(value, str):
        raise ValueError('Enter a valid date and time.')
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    return parsed.astimezone(BEIRUT) if parsed.tzinfo else parsed.replace(tzinfo=BEIRUT)


def init():
    os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)
    with sqlite3.connect(DB_PATH, timeout=15) as connection:
        connection.execute('PRAGMA journal_mode=WAL')
        connection.execute('''CREATE TABLE IF NOT EXISTS teams(
            id INTEGER PRIMARY KEY,
            school_name TEXT NOT NULL,
            team_name TEXT NOT NULL DEFAULT '',
            interested_major TEXT NOT NULL,
            entered INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )''')
        team_columns = {column[1] for column in connection.execute('PRAGMA table_info(teams)')}
        if 'team_name' not in team_columns:
            connection.execute("ALTER TABLE teams ADD COLUMN team_name TEXT NOT NULL DEFAULT ''")
        connection.execute('''CREATE TABLE IF NOT EXISTS team_members(
            id INTEGER PRIMARY KEY,
            team_id INTEGER NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            phone TEXT NOT NULL
        )''')
        connection.execute('CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT)')
        connection.execute('CREATE INDEX IF NOT EXISTS team_members_team_id ON team_members(team_id)')
        connection.execute('CREATE INDEX IF NOT EXISTS teams_school_name ON teams(school_name)')
        connection.execute("INSERT OR IGNORE INTO settings(key,value) VALUES('deadline',?)", (beirut_datetime(DEFAULT_DEADLINE).isoformat(),))


def db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH, timeout=15)
        g.db.row_factory = sqlite3.Row
        g.db.execute('PRAGMA foreign_keys=ON')
    return g.db


@app.teardown_appcontext
def close_database(_):
    connection = g.pop('db', None)
    if connection is not None:
        connection.close()


@app.errorhandler(HTTPException)
def http_error(error):
    return jsonify(error=error.description), error.code


@app.errorhandler(sqlite3.OperationalError)
def database_error(error):
    app.logger.error('Database operation failed: %s', error)
    return jsonify(error='The database is temporarily unavailable. Please try again.'), 503


def rows(query, *args):
    return [dict(row) for row in db().execute(query, args).fetchall()]


def one(query, *args):
    row = db().execute(query, args).fetchone()
    return dict(row) if row else None


def body():
    value = request.get_json(silent=True)
    if not isinstance(value, dict):
        raise BadRequest('Send a valid JSON object.')
    return value


def text_field(data, name, limit, optional=False):
    value = data.get(name, '' if optional else None)
    if not isinstance(value, str):
        raise BadRequest(f'{name} must be text.')
    value = value.strip()
    if (not optional and not value) or len(value) > limit:
        raise BadRequest(f'{name} must contain {"0" if optional else "1"}–{limit} characters.')
    return value


def valid_email(email):
    try:
        validate_email(email, check_deliverability=False)
        return True
    except EmailNotValidError:
        return False


def valid_phone(phone):
    digits = re.sub(r'\D', '', phone)
    return bool(re.fullmatch(r'[0-9+() -]+', phone)) and 7 <= len(digits) <= 15


def get_deadline():
    row = one("SELECT value FROM settings WHERE key='deadline'")
    return beirut_datetime(row['value'] if row else DEFAULT_DEADLINE).isoformat()


def deadline_passed():
    return datetime.now(timezone.utc) >= beirut_datetime(get_deadline()).astimezone(timezone.utc)


def admin_token_version():
    row = one("SELECT value FROM settings WHERE key='admin_token_version'")
    if row:
        return row['value']
    version = secrets.token_urlsafe(18)
    with db() as connection:
        connection.execute("INSERT OR IGNORE INTO settings(key,value) VALUES('admin_token_version',?)", (version,))
    return one("SELECT value FROM settings WHERE key='admin_token_version'")['value']


def make_admin_token():
    return URLSafeTimedSerializer(app.config['SECRET_KEY'], salt='mme-workshop-admin').dumps({
        'role': 'admin', 'version': admin_token_version(),
    })


def admin(fn):
    @wraps(fn)
    def authenticated(*args, **kwargs):
        code = os.getenv('ADMIN_CODE')
        supplied = request.headers.get('x-admin-code', '')
        authorization = request.headers.get('Authorization', '')
        token = authorization[7:] if authorization.startswith('Bearer ') else ''
        try:
            token_data = URLSafeTimedSerializer(app.config['SECRET_KEY'], salt='mme-workshop-admin').loads(
                token, max_age=int(app.config['PERMANENT_SESSION_LIFETIME'].total_seconds())
            )
            signed_in = isinstance(token_data, dict) and token_data.get('role') == 'admin' and token_data.get('version') == admin_token_version()
        except BadData:
            signed_in = False
        if not code or not (signed_in or hmac.compare_digest(supplied.encode(), code.encode())):
            return jsonify(error='Wrong admin code.'), 401
        return fn(*args, **kwargs)
    return authenticated


@app.post('/api/admin/login')
def admin_login():
    supplied = text_field(body(), 'code', 200)
    code = os.getenv('ADMIN_CODE')
    if not code or not hmac.compare_digest(supplied.encode(), code.encode()):
        return jsonify(error='Wrong admin code.'), 401
    session.clear()
    return jsonify(ok=True, adminToken=make_admin_token())


@app.post('/api/admin/logout')
def admin_logout():
    session.clear()
    return jsonify(ok=True)


@app.get('/api/public')
def public():
    return jsonify(closed=deadline_passed(), deadline=get_deadline(), timezone='Asia/Beirut')


@app.post('/api/teams')
def register_team():
    if deadline_passed():
        return jsonify(error='Registration is closed.'), 403
    data = body()
    school_name = text_field(data, 'schoolName', 120)
    team_name = text_field(data, 'teamName', 120, optional=True)
    interested_major = text_field(data, 'interestedMajor', 120)
    members = data.get('members')
    if not isinstance(members, list) or not 1 <= len(members) <= 3:
        raise BadRequest('A team must have between 1 and 3 students.')
    cleaned = []
    for index, member in enumerate(members, start=1):
        if not isinstance(member, dict):
            raise BadRequest(f'Student {index} must be valid.')
        name = text_field(member, 'name', 100)
        email = text_field(member, 'email', 120)
        phone = text_field(member, 'phone', 40)
        if not valid_email(email):
            raise BadRequest(f'Enter a valid email for student {index}.')
        if not valid_phone(phone):
            raise BadRequest(f'Enter a valid phone number for student {index}.')
        cleaned.append((name, email, phone))
    with db() as connection:
        connection.execute('BEGIN IMMEDIATE')
        team_id = connection.execute(
            'INSERT INTO teams(school_name,team_name,interested_major) VALUES(?,?,?)',
            (school_name, team_name, interested_major),
        ).lastrowid
        connection.executemany(
            'INSERT INTO team_members(team_id,name,email,phone) VALUES(?,?,?,?)',
            [(team_id, *member) for member in cleaned],
        )
    return jsonify(id=team_id, members=len(cleaned)), 201


@app.get('/api/admin/state')
@admin
def state():
    return jsonify(ok=True)


@app.get('/api/admin/stats')
@admin
def stats():
    result = one('''SELECT
        COUNT(*) AS totalTeams,
        COALESCE(SUM(entered), 0) AS enteredTeams,
        COUNT(DISTINCT LOWER(TRIM(school_name))) AS totalSchools,
        COALESCE(SUM(CASE WHEN LOWER(interested_major)='mechatronics engineering' THEN 1 ELSE 0 END), 0) AS mechatronicsTeams,
        COALESCE(SUM(CASE WHEN LOWER(interested_major)='mechanical engineering' THEN 1 ELSE 0 END), 0) AS mechanicalTeams
        FROM teams''')
    result['totalStudents'] = one('SELECT COUNT(*) AS count FROM team_members')['count']
    result['enteredStudents'] = one('''SELECT COUNT(*) AS count FROM team_members AS member
        JOIN teams AS team ON team.id=member.team_id WHERE team.entered=1''')['count']
    return jsonify(result)


def team_with_members(team_id):
    team = one('SELECT * FROM teams WHERE id=?', team_id)
    if team:
        team['members'] = rows('SELECT id,name,email,phone FROM team_members WHERE team_id=? ORDER BY id', team_id)
    return team


@app.get('/api/admin/teams')
@admin
def teams():
    query = request.args.get('q', '').strip()
    entered = request.args.get('entered', '')
    if entered not in ('', '0', '1'):
        raise BadRequest('Invalid check-in filter.')
    where, args = ['1=1'], []
    if query:
        where.append('''(team.school_name LIKE ? OR team.team_name LIKE ? OR team.interested_major LIKE ? OR EXISTS(
            SELECT 1 FROM team_members member WHERE member.team_id=team.id
            AND (member.name LIKE ? OR member.email LIKE ? OR member.phone LIKE ?)))''')
        args.extend(['%' + query + '%'] * 6)
    if entered:
        where.append('team.entered=?')
        args.append(int(entered))
    result = rows(f'''SELECT team.*, COUNT(member.id) AS member_count FROM teams team
        LEFT JOIN team_members member ON member.team_id=team.id
        WHERE {' AND '.join(where)} GROUP BY team.id ORDER BY team.id DESC''', *args)
    return jsonify(teams=result, count=len(result))


@app.get('/api/admin/teams/<int:team_id>')
@admin
def team_details(team_id):
    team = team_with_members(team_id)
    if not team:
        return jsonify(error='Team not found.'), 404
    return jsonify(team)


@app.post('/api/admin/teams/<int:team_id>/entered')
@admin
def mark_team_entered(team_id):
    value = body().get('value')
    if type(value) is not bool:
        raise BadRequest('value must be true or false.')
    with db() as connection:
        changed = connection.execute('UPDATE teams SET entered=? WHERE id=?', (int(value), team_id)).rowcount
    if not changed:
        return jsonify(error='Team not found.'), 404
    return jsonify(ok=True, value=value, team=team_with_members(team_id))


@app.get('/api/admin/deadline')
@admin
def admin_deadline():
    return jsonify(deadline=get_deadline(), timezone='Asia/Beirut')


@app.post('/api/admin/deadline')
@admin
def set_deadline():
    value = text_field(body(), 'deadline', 40)
    try:
        deadline = beirut_datetime(value).isoformat()
    except ValueError:
        raise BadRequest('Enter a valid date and time.')
    with db() as connection:
        connection.execute("INSERT INTO settings(key,value) VALUES('deadline',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (deadline,))
    return jsonify(deadline=deadline, timezone='Asia/Beirut')


init()
if __name__ == '__main__':
    from waitress import serve
    port = int(os.getenv('PORT', 3000))
    print(f'MME Workshop backend running on port {port}')
    serve(app, host='0.0.0.0', port=port)
