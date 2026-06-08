import os
import json
import time
import shutil
import secrets
import uuid
from datetime import datetime
from functools import wraps
from typing import Any, Iterable, Optional

from flask import Flask, render_template, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)

# -----------------------------------------------------------------------------
# Production-friendly configuration
# -----------------------------------------------------------------------------
# IMPORTANT: Set SECRET_KEY in production. Example on Windows PowerShell:
#   setx SECRET_KEY "change-this-to-a-long-random-value"
app.secret_key = os.environ.get('SECRET_KEY', 'dev-only-change-this-secret-key')

os.makedirs(os.path.join(BASE_DIR, 'instance'), exist_ok=True)
DB_PATH = os.path.join(BASE_DIR, 'instance', 'portal_new.db')

# For local use this keeps SQLite. For server use you can set DATABASE_URL to
# PostgreSQL/MySQL later without changing code.
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///' + DB_PATH)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JSON_SORT_KEYS'] = False

app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('COOKIE_SECURE', '0') == '1'

# Default 2 GB upload limit. Change with MAX_UPLOAD_MB environment variable.
app.config['MAX_CONTENT_LENGTH'] = int(os.environ.get('MAX_UPLOAD_MB', '2048')) * 1024 * 1024

UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Safer upload policy for a production-pipeline portal.
# Instead of blocking unknown creative/3D formats, reject executable/script formats.
# This avoids bugs when uploading Maya/Houdini/Nuke/Substance/cache files.
BLOCKED_EXTENSIONS = {
    'exe', 'msi', 'bat', 'cmd', 'com', 'scr', 'ps1', 'vbs', 'reg',
    'sh', 'bash', 'zsh', 'fish',
    'php', 'phtml', 'jsp', 'asp', 'aspx',
    'html', 'htm', 'js', 'mjs', 'cjs',
    'jar', 'apk', 'dmg', 'app',
    'dll', 'so', 'dylib'
}

ADMIN_ROLES = {'admin'}
STAFF_ROLES = {'admin'}
# v8 company workspace mode.
# Root admin owns the main workspace and can create/delete company workspaces.
# Company admins can work like admins inside their own company workspace, but
# cannot add companies or change the global login wallpaper.
ROOT_ADMIN_ROLE = 'admin'
COMPANY_ADMIN_ROLE = 'company_admin'
ADMIN_ROLES = {'admin', 'company_admin'}
STAFF_ROLES = {'admin', 'company_admin'}
LEGACY_MANAGER_ROLE = 'manager'
ALLOWED_TEAM_ROLES = {'client', 'freelancer', 'supervisor'}
PROJECT_CREATOR_ROLES = {'admin', 'company_admin', 'client', 'supervisor'}
PROJECT_WORK_ROLES = {'admin', 'company_admin', 'client', 'supervisor', 'freelancer'}


db = SQLAlchemy(app)
GLOBAL_STATE = {'last_updated': time.time()}
DAY_MS = 24 * 60 * 60 * 1000
DEFAULT_COMPANY_SUBSCRIPTION_DAYS = int(os.environ.get('DEFAULT_COMPANY_SUBSCRIPTION_DAYS', '30'))


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
def mark_db_updated() -> None:
    GLOBAL_STATE['last_updated'] = time.time()


def safe_json_loads(value: Optional[str], default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except Exception:
        return default


def generate_unique_logincode() -> str:
    """Create a login code that is guaranteed unique in the current database."""
    for _ in range(20):
        code = f"{secrets.token_hex(2)}-{secrets.token_hex(2)}-{secrets.token_hex(2)}"
        if not User.query.filter_by(logincode=code).first():
            return code
    # Extremely unlikely fallback with timestamp entropy.
    return f"{int(time.time())}-{secrets.token_hex(4)}"


def generate_internal_username(role: str) -> str:
    """Non-admin users login with logincode, but a unique username avoids DB issues on some engines."""
    safe_role = ''.join(ch for ch in (role or 'user').lower() if ch.isalnum()) or 'user'
    for _ in range(20):
        username = f"{safe_role}_{int(time.time() * 1000)}_{secrets.token_hex(3)}"
        if not User.query.filter_by(username=username).first():
            return username
    return f"{safe_role}_{int(time.time() * 1000)}_{secrets.token_hex(6)}"


def generate_session_uid() -> str:
    """Permanent per-account identity used to prevent deleted sessions becoming new accounts."""
    for _ in range(20):
        value = uuid.uuid4().hex
        if not User.query.filter_by(session_uid=value).first():
            return value
    return f"{uuid.uuid4().hex}{secrets.token_hex(4)}"


def ensure_user_session_uid(user: 'User') -> str:
    """Backfill old database rows and return a stable non-reused account identity."""
    if not getattr(user, 'session_uid', None):
        user.session_uid = generate_session_uid()
        db.session.commit()
    return user.session_uid


def generate_company_id() -> str:
    for _ in range(20):
        value = 'co_' + secrets.token_hex(6)
        if not Company.query.get(value):
            return value
    return 'co_' + uuid.uuid4().hex


def is_root_admin(user: Optional['User']) -> bool:
    return bool(user and user.role == ROOT_ADMIN_ROLE and not user.company_id)


def is_company_admin(user: Optional['User']) -> bool:
    return bool(user and user.role == COMPANY_ADMIN_ROLE and user.company_id)


def frontend_role(user: 'User') -> str:
    # Company admin uses the same frontend admin interface, but backend keeps a
    # separate real role and company_id for security/data isolation.
    return 'admin' if user.role == COMPANY_ADMIN_ROLE else user.role


def user_workspace_id(user: Optional['User']) -> Optional[str]:
    return user.company_id if user else None


def same_workspace(user: Optional['User'], company_id: Optional[str]) -> bool:
    if not user:
        return False
    return (user.company_id or None) == (company_id or None)


def company_remaining_days(company: Optional['Company']) -> Optional[int]:
    if not company or not getattr(company, 'expires_at', None):
        return None
    remaining_ms = float(company.expires_at) - (time.time() * 1000)
    if remaining_ms <= 0:
        return 0
    return int((remaining_ms + DAY_MS - 1) // DAY_MS)


def parse_expiry_date_to_ms(value: str) -> Optional[float]:
    """Parse a manual YYYY-MM-DD subscription expiry date as end-of-day."""
    if not value:
        return None
    try:
        dt = datetime.strptime(str(value).strip(), '%Y-%m-%d').replace(hour=23, minute=59, second=59, microsecond=999000)
        return dt.timestamp() * 1000
    except Exception:
        return None


def company_subscription_payload(company: Optional['Company']) -> dict:
    """Compact subscription status used by root admin list and company users."""
    if not company:
        return {
            "companySubscriptionDays": None,
            "companyExpiresAt": None,
            "companyRemainingDays": None,
            "companyExpired": False,
            "companySubscriptionPercent": 100,
            "companySubscriptionWarning": "none",
        }
    remaining_days = company_remaining_days(company)
    total_days = int(getattr(company, 'subscription_days', 0) or 0)
    expired = company_is_expired(company)
    if remaining_days is None:
        percent = 100
        warning = "none"
    else:
        denominator = max(total_days, 1)
        percent = max(0, min(100, int(round((remaining_days / denominator) * 100))))
        if expired or remaining_days <= 0:
            warning = "expired"
        elif remaining_days <= 3:
            warning = "critical"
        elif remaining_days <= 7:
            warning = "warning"
        else:
            warning = "ok"
    return {
        "companySubscriptionDays": total_days,
        "companyExpiresAt": company.expires_at,
        "companyRemainingDays": remaining_days,
        "companyExpired": expired,
        "companySubscriptionPercent": percent,
        "companySubscriptionWarning": warning,
    }


def company_is_expired(company: Optional['Company']) -> bool:
    if not company:
        return False
    if getattr(company, 'active', True) is False:
        return True
    expires_at = getattr(company, 'expires_at', None)
    return bool(expires_at and (time.time() * 1000) > float(expires_at))


def company_for_user(user: Optional['User']) -> Optional['Company']:
    if user and getattr(user, 'company_id', None):
        return Company.query.get(user.company_id)
    return None


def company_access_block_response():
    return jsonify({"success": False, "message": "Company subscription expired. Please contact root admin."}), 403


def workspace_query_matches(user: 'User', row) -> bool:
    return same_workspace(user, getattr(row, 'company_id', None))


def public_user_id(user: 'User') -> str:
    return f"u{user.id}"


def parse_public_user_id(user_id: str) -> Optional[int]:
    try:
        return int(str(user_id).replace('u', '', 1))
    except Exception:
        return None


def get_current_user() -> Optional['User']:
    user_id = session.get('user_id')
    if not user_id:
        return None
    user = User.query.get(user_id)
    if not user:
        return None

    # Security fix v6:
    # Browser sessions used to store only numeric user_id. SQLite can reuse a deleted
    # numeric id, so an old deleted manager page could become the next new manager.
    # A session is now valid only when this permanent account identity also matches.
    session_uid = session.get('session_uid')
    if not session_uid or not getattr(user, 'session_uid', None) or session_uid != user.session_uid:
        session.clear()
        return None
    return user


def require_login_json():
    return jsonify({"success": False, "message": "Unauthorized"}), 401


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return require_login_json()
        current_user = get_current_user()
        if not current_user:
            session.clear()
            return require_login_json()
        # Company subscription gate: all company users/employees are blocked
        # after expiry. Root admin support mode is allowed so you can inspect
        # technical issues without needing the company password.
        if current_user.company_id and not session.get('support_root_user_id'):
            if company_is_expired(company_for_user(current_user)):
                session.clear()
                return company_access_block_response()
        return f(*args, **kwargs)
    return decorated_function


def require_roles(*roles: str):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            user = get_current_user()
            if not user or user.role not in roles:
                return jsonify({"success": False, "message": "Forbidden"}), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator


def allowed_project_ids(user: 'User') -> list[str]:
    return safe_json_loads(user.allowed_projects, [])


def created_by_manager_id(created_by_id: Optional[int]) -> Optional[int]:
    """Return the manager id when a row belongs to a manager studio workspace."""
    if not created_by_id:
        return None
    creator = User.query.get(created_by_id)
    if creator and creator.role == 'manager':
        return creator.id
    return None


def project_manager_owner_id(project: Optional['Project']) -> Optional[int]:
    """
    Detect manager-owned projects strictly.

    Normal case: project.created_by_id is the manager id.
    Repair case: older rows may have NULL created_by_id, so infer ownership from
    manager-created users, assignments, or invoices linked to the project.
    """
    if not project:
        return None

    direct_owner = created_by_manager_id(project.created_by_id)
    if direct_owner:
        return direct_owner

    # Backward compatibility for data made before the ownership column worked.
    for user in User.query.filter(User.created_by_id.isnot(None)).all():
        owner_id = created_by_manager_id(user.created_by_id)
        if owner_id and project.id in allowed_project_ids(user):
            return owner_id

    for assignment in Assignment.query.filter_by(project_id=project.id).all():
        owner_id = created_by_manager_id(assignment.created_by_id)
        if owner_id:
            return owner_id

    for invoice in Invoice.query.filter_by(projectId=project.id).all():
        owner_id = created_by_manager_id(invoice.created_by_id)
        if owner_id:
            return owner_id

    return None


def is_manager_owned_by_other(project: Optional['Project'], user: Optional['User']) -> bool:
    """True when a project belongs to a manager workspace that is not this manager."""
    owner_id = project_manager_owner_id(project)
    return bool(owner_id and (not user or owner_id != user.id))


def is_user_visible_to(current_user: 'User', target_user: 'User') -> bool:
    if not current_user or not target_user:
        return False
    if current_user.id == target_user.id:
        return True

    # Hide legacy manager accounts from normal lists.
    if target_user.role == LEGACY_MANAGER_ROLE:
        return False

    # Root admin sees only main/root workspace users, not company users.
    # Company admin sees only users inside that company workspace.
    if current_user.role in STAFF_ROLES:
        if target_user.role in STAFF_ROLES:
            return False
        return same_workspace(current_user, target_user.company_id)

    return False


def user_has_project_access(user: 'User', project_id: Optional[str]) -> bool:
    if not user or not project_id:
        return False

    project = Project.query.get(project_id)
    if not project:
        return False

    # Admin-like users see all projects inside only their own workspace.
    if user.role in STAFF_ROLES:
        return same_workspace(user, project.company_id)

    if user.role == LEGACY_MANAGER_ROLE:
        return False

    return same_workspace(user, project.company_id) and project_id in allowed_project_ids(user)


def user_has_assignment_access(user: 'User', assignment: Optional['Assignment']) -> bool:
    if not user or not assignment:
        return False

    project = Project.query.get(assignment.project_id)
    if not project:
        return False

    if not same_workspace(user, assignment.company_id or project.company_id):
        return False

    if user.role in STAFF_ROLES:
        return True

    if user_has_project_access(user, assignment.project_id):
        return True

    uid = public_user_id(user)
    if assignment.assigned_to == uid:
        return True

    assignees = safe_json_loads(assignment.stage_assignees, {})
    if isinstance(assignees, dict):
        return uid in assignees.values() or uid in assignees.keys()
    return False


def user_can_create_or_manage_project(user: 'User') -> bool:
    return bool(user and user.role in PROJECT_CREATOR_ROLES)


def user_can_work_on_project(user: 'User', project_id: Optional[str]) -> bool:
    return bool(user and user.role in PROJECT_WORK_ROLES and user_has_project_access(user, project_id))


def user_can_manage_all(user: 'User') -> bool:
    return bool(user and user.role in STAFF_ROLES)


def can_modify_user(current_user: 'User', target_user: 'User') -> bool:
    if not current_user or not target_user:
        return False
    if current_user.id == target_user.id:
        return True
    if current_user.role in STAFF_ROLES:
        # Company/admin accounts are managed separately, not from Team list.
        if target_user.role in STAFF_ROLES:
            return False
        return same_workspace(current_user, target_user.company_id)
    return False


def can_manage_project(user: 'User', project: 'Project') -> bool:
    if not user or not project:
        return False
    return user.role in STAFF_ROLES and same_workspace(user, project.company_id)


def can_access_invoice(user: 'User', invoice: 'Invoice') -> bool:
    if not user or not invoice:
        return False

    invoice_company = invoice.company_id
    if not invoice_company and invoice.projectId:
        project = Project.query.get(invoice.projectId)
        invoice_company = project.company_id if project else None

    if not same_workspace(user, invoice_company):
        return False

    if user.role in STAFF_ROLES:
        return True

    uid = public_user_id(user)
    return invoice.targetUserId == uid or (invoice.projectId and user_has_project_access(user, invoice.projectId) and user.show_payments)


def validate_project_access_or_403(project_id: Optional[str]):
    user = get_current_user()
    if not user_has_project_access(user, project_id):
        return jsonify({"success": False, "message": "You do not have access to this project"}), 403
    return None


def allowed_file(filename: str) -> bool:
    # Keep compatibility with creative-production files while blocking executable/script files.
    if not filename:
        return False
    safe_name = secure_filename(filename)
    if not safe_name or safe_name in {'.', '..'}:
        return False
    if '.' not in safe_name:
        return True
    ext = safe_name.rsplit('.', 1)[1].lower()
    return ext not in BLOCKED_EXTENSIONS


def safe_join_upload(*parts: str) -> str:
    base = os.path.abspath(app.config['UPLOAD_FOLDER'])
    final_path = os.path.abspath(os.path.join(base, *parts))
    if not (final_path == base or final_path.startswith(base + os.sep)):
        raise ValueError('Invalid upload path')
    return final_path


def project_id_from_upload_url(file_url: str) -> Optional[str]:
    """Infer project access from upload URL.

    Root workspace: /static/uploads/<project>/...
    Company workspace: /static/uploads/companies/<company_id>/<project>/...
    """
    if not file_url or not file_url.startswith('/static/uploads/'):
        return None
    parts = file_url.split('/')
    if len(parts) < 4:
        return None
    if len(parts) >= 6 and parts[3] == 'companies':
        company_id = parts[4]
        secure_project_name = parts[5]
        for project in Project.query.filter_by(company_id=company_id).all():
            if secure_filename(project.name) == secure_project_name:
                return project.id
        return None
    secure_project_name = parts[3]
    for project in Project.query.filter(Project.company_id.is_(None)).all():
        if secure_filename(project.name) == secure_project_name:
            return project.id
    return None


def serialize_user(user: 'User', include_sensitive: bool = False) -> dict:
    company = Company.query.get(user.company_id) if user.company_id else None
    data = {
        "id": public_user_id(user),
        "name": user.name,
        "role": frontend_role(user),
        "realRole": user.role,
        "isRootAdmin": is_root_admin(user),
        "isCompanyAdmin": is_company_admin(user),
        "companyId": user.company_id,
        "companyName": company.name if company else None,
        "profilePic": user.profile_pic,
        "lastActive": user.last_active,
        "showPayments": user.show_payments,
        "createdBy": public_user_id(User.query.get(user.created_by_id)) if user.created_by_id and User.query.get(user.created_by_id) else None,
    }
    data.update(company_subscription_payload(company))
    # Root Admin Support Login / impersonation info.
    # Only the currently active session user receives these fields.
    if session.get('support_root_user_id') and session.get('user_id') == user.id:
        data.update({
            "supportMode": True,
            "supportCompanyId": session.get('support_company_id'),
            "supportCompanyName": session.get('support_company_name') or (company.name if company else None),
        })
    else:
        data.update({"supportMode": False})

    if include_sensitive:
        data.update({
            "username": user.username,
            "logincode": user.logincode,
            "allowedProjects": allowed_project_ids(user),
        })
    return data


def serialize_project(project: 'Project') -> dict:
    stages_data = safe_json_loads(project.stages, ["Mod", "BS", "UV", "Tex", "Rig"])
    return {
        "id": project.id,
        "name": project.name,
        "img": project.img,
        "active": project.active,
        "type": project.type,
        "stages": stages_data,
        "pipeline_graph": project.pipeline_graph,
        "episodes": safe_json_loads(project.episodes, []),
        "episodeThumbs": safe_json_loads(project.episode_thumbs, {}),
        "createdBy": public_user_id(User.query.get(project.created_by_id)) if project.created_by_id and User.query.get(project.created_by_id) else None,
        "companyId": project.company_id
    }


def serialize_assignment(a: 'Assignment') -> dict:
    return {
        "id": a.id,
        "projectId": a.project_id,
        "name": a.name,
        "status": a.status,
        "img": a.img,
        "mandays": a.mandays,
        "levels": safe_json_loads(a.levels, []),
        "currentLevelIndex": a.current_level_index,
        "activeStages": safe_json_loads(a.active_stages, []),
        "stageAssignees": safe_json_loads(a.stage_assignees, {}),
        "completedLevels": safe_json_loads(a.completed_levels, []),
        "versions": safe_json_loads(a.versions, []),
        "inputData": safe_json_loads(a.input_data, None),
        "assignedTo": a.assigned_to,
        "createdAt": a.created_at,
        "accumulatedTime": a.accumulated_time or 0.0,
        "orderIndex": a.order_index,
        "createdBy": public_user_id(User.query.get(a.created_by_id)) if a.created_by_id and User.query.get(a.created_by_id) else None,
        "companyId": a.company_id
    }


def serialize_invoice(i: 'Invoice') -> dict:
    return {
        "id": i.id,
        "roleType": i.roleType,
        "targetUserId": i.targetUserId,
        "paymentType": i.paymentType,
        "projectId": i.projectId,
        "assignmentId": i.assignmentId,
        "stage": i.stage,
        "issueDate": i.issueDate,
        "dueDate": i.dueDate,
        "description": i.description,
        "amount": i.amount,
        "status": i.status,
        "createdAt": i.created_at,
        "createdBy": public_user_id(User.query.get(i.created_by_id)) if i.created_by_id and User.query.get(i.created_by_id) else None,
        "companyId": i.company_id
    }


# -----------------------------------------------------------------------------
# Database models
# -----------------------------------------------------------------------------
class Company(db.Model):
    id = db.Column(db.String(50), primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    # Passwords are NOT shown in the company list. Root admin can use
    # support login or reset the password if needed. This column remains only
    # for backward compatibility with old databases and is not serialized.
    visible_password = db.Column(db.Text, nullable=True)
    subscription_days = db.Column(db.Integer, default=DEFAULT_COMPANY_SUBSCRIPTION_DAYS)
    expires_at = db.Column(db.Float, nullable=True)
    created_at = db.Column(db.Float, nullable=False, default=lambda: time.time() * 1000)
    active = db.Column(db.Boolean, default=True)


class User(db.Model):
    # sqlite_autoincrement reduces id reuse for new databases. Existing databases
    # are protected by session_uid below.
    __table_args__ = {'sqlite_autoincrement': True}

    id = db.Column(db.Integer, primary_key=True)
    session_uid = db.Column(db.String(80), unique=True, nullable=True)
    name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=True)
    password = db.Column(db.String(255), nullable=True)
    logincode = db.Column(db.String(50), unique=True, nullable=True)
    allowed_projects = db.Column(db.Text, nullable=True)
    profile_pic = db.Column(db.Text, nullable=True)
    last_active = db.Column(db.Float, default=0.0)
    show_payments = db.Column(db.Boolean, default=True)
    created_by_id = db.Column(db.Integer, nullable=True)
    company_id = db.Column(db.String(50), nullable=True)


class Project(db.Model):
    id = db.Column(db.String(50), primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    img = db.Column(db.Text, nullable=True)
    active = db.Column(db.Boolean, default=False)
    stages = db.Column(db.Text, nullable=True)
    type = db.Column(db.String(50), default='Asset')
    episodes = db.Column(db.Text, nullable=True)
    episode_thumbs = db.Column(db.Text, nullable=True)
    pipeline_graph = db.Column(db.Text, nullable=True)
    created_by_id = db.Column(db.Integer, nullable=True)
    company_id = db.Column(db.String(50), nullable=True)


class Assignment(db.Model):
    id = db.Column(db.String(50), primary_key=True)
    project_id = db.Column(db.String(50), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(50), default='paused')
    img = db.Column(db.Text, nullable=True)
    mandays = db.Column(db.Float, nullable=True)
    levels = db.Column(db.Text, nullable=True)
    current_level_index = db.Column(db.Integer, default=0)
    active_stages = db.Column(db.Text, nullable=True)
    stage_assignees = db.Column(db.Text, nullable=True)
    completed_levels = db.Column(db.Text, nullable=True)
    versions = db.Column(db.Text, nullable=True)
    input_data = db.Column(db.Text, nullable=True)
    assigned_to = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.Float, nullable=False)
    accumulated_time = db.Column(db.Float, default=0.0)
    order_index = db.Column(db.Float, nullable=True)
    created_by_id = db.Column(db.Integer, nullable=True)
    company_id = db.Column(db.String(50), nullable=True)


class Invoice(db.Model):
    id = db.Column(db.String(50), primary_key=True)
    roleType = db.Column(db.String(50), nullable=True)
    targetUserId = db.Column(db.String(50), nullable=True)
    paymentType = db.Column(db.String(50), nullable=True)
    projectId = db.Column(db.String(50), nullable=True)
    assignmentId = db.Column(db.String(50), nullable=True)
    stage = db.Column(db.String(100), nullable=True)
    issueDate = db.Column(db.String(50), nullable=True)
    dueDate = db.Column(db.String(50), nullable=True)
    description = db.Column(db.Text, nullable=True)
    amount = db.Column(db.Float, nullable=False, default=0.0)
    status = db.Column(db.String(50), default='pending')
    created_at = db.Column(db.Float, nullable=False)
    created_by_id = db.Column(db.Integer, nullable=True)
    company_id = db.Column(db.String(50), nullable=True)


# -----------------------------------------------------------------------------
# Startup migrations for your existing SQLite file
# -----------------------------------------------------------------------------
def add_column_if_missing(table_name: str, column_name: str, ddl: str) -> None:
    try:
        db.session.execute(text(f'SELECT {column_name} FROM {table_name} LIMIT 1'))
    except Exception:
        db.session.rollback()
        db.session.execute(text(f'ALTER TABLE {table_name} ADD COLUMN {ddl}'))
        db.session.commit()


with app.app_context():
    db.create_all()
    add_column_if_missing('user', 'show_payments', 'show_payments BOOLEAN DEFAULT 1')
    add_column_if_missing('project', 'type', "type VARCHAR(50) DEFAULT 'Asset'")
    add_column_if_missing('project', 'stages', 'stages TEXT')
    add_column_if_missing('project', 'pipeline_graph', 'pipeline_graph TEXT')
    add_column_if_missing('user', 'last_active', 'last_active FLOAT DEFAULT 0.0')
    add_column_if_missing('assignment', 'accumulated_time', 'accumulated_time FLOAT DEFAULT 0.0')
    add_column_if_missing('assignment', 'order_index', 'order_index FLOAT')
    add_column_if_missing('project', 'episodes', 'episodes TEXT')
    add_column_if_missing('project', 'episode_thumbs', 'episode_thumbs TEXT')
    add_column_if_missing('assignment', 'active_stages', 'active_stages TEXT')
    add_column_if_missing('assignment', 'stage_assignees', 'stage_assignees TEXT')
    add_column_if_missing('user', 'created_by_id', 'created_by_id INTEGER')
    add_column_if_missing('user', 'session_uid', 'session_uid TEXT')
    add_column_if_missing('project', 'created_by_id', 'created_by_id INTEGER')
    add_column_if_missing('assignment', 'created_by_id', 'created_by_id INTEGER')
    add_column_if_missing('invoice', 'created_by_id', 'created_by_id INTEGER')
    add_column_if_missing('user', 'company_id', 'company_id VARCHAR(50)')
    add_column_if_missing('project', 'company_id', 'company_id VARCHAR(50)')
    add_column_if_missing('assignment', 'company_id', 'company_id VARCHAR(50)')
    add_column_if_missing('invoice', 'company_id', 'company_id VARCHAR(50)')
    add_column_if_missing('company', 'visible_password', 'visible_password TEXT')
    add_column_if_missing('company', 'subscription_days', f'subscription_days INTEGER DEFAULT {DEFAULT_COMPANY_SUBSCRIPTION_DAYS}')
    add_column_if_missing('company', 'expires_at', 'expires_at FLOAT')

    # Backfill subscription expiry for old company rows. Existing companies get
    # the default number of days from the first v12 launch unless they already
    # have an expiry date.
    changed_companies = False
    now_ms = time.time() * 1000
    for existing_company in Company.query.all():
        if not getattr(existing_company, 'subscription_days', None):
            existing_company.subscription_days = DEFAULT_COMPANY_SUBSCRIPTION_DAYS
            changed_companies = True
        if not getattr(existing_company, 'expires_at', None):
            existing_company.expires_at = now_ms + (int(existing_company.subscription_days or DEFAULT_COMPANY_SUBSCRIPTION_DAYS) * DAY_MS)
            changed_companies = True
    if changed_companies:
        db.session.commit()

    # Backfill permanent account identities for old databases. This fixes the
    # security issue where a deleted user's browser session could match a newly
    # created user if SQLite reused the numeric id.
    changed_session_uid = False
    seen_session_uids = set()
    for existing_user in User.query.all():
        if not existing_user.session_uid or existing_user.session_uid in seen_session_uids:
            existing_user.session_uid = generate_session_uid()
            changed_session_uid = True
        seen_session_uids.add(existing_user.session_uid)
    if changed_session_uid:
        db.session.commit()

    if not User.query.filter_by(role='admin').first():
        hashed_pw = generate_password_hash(os.environ.get('DEFAULT_ADMIN_PASSWORD', '123'))
        admin_user = User(
            session_uid=generate_session_uid(),
            name='Admin',
            role='admin',
            username=os.environ.get('DEFAULT_ADMIN_USERNAME', 'admin'),
            password=hashed_pw,
            allowed_projects='[]',
            profile_pic=None,
            created_by_id=None,
            company_id=None
        )
        db.session.add(admin_user)
        db.session.commit()


# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------
@app.route('/')
def home():
    return render_template('portal_v08.html')


@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({"success": True, "status": "ok", "version": "fixed_v22_company_controls"})


@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json(silent=True) or {}
    login_type = data.get('type')
    user = None

    if login_type == 'admin':
        username_input = data.get('username', '').strip()
        password_input = data.get('password', '').strip()
        user = User.query.filter(User.username == username_input, User.role.in_([ROOT_ADMIN_ROLE, COMPANY_ADMIN_ROLE])).first()
        if user:
            is_valid = False
            if user.password:
                # One-time migration for very old plaintext admin password.
                if user.password == password_input:
                    is_valid = True
                    user.password = generate_password_hash(password_input)
                    db.session.commit()
                    mark_db_updated()
                else:
                    try:
                        is_valid = check_password_hash(user.password, password_input)
                    except Exception:
                        is_valid = False
            if not is_valid:
                user = None
    else:
        logincode_input = data.get('logincode', '').strip()
        if logincode_input:
            user = User.query.filter_by(logincode=logincode_input).first()

    if user and user.role == LEGACY_MANAGER_ROLE:
        session.clear()
        return jsonify({"success": False, "message": "Manager role has been removed. Please use Admin, Client, Supervisor, or Freelancer login."}), 403

    if user and user.company_id:
        company = company_for_user(user)
        if company_is_expired(company):
            session.clear()
            return jsonify({"success": False, "message": "Company subscription expired. Please contact root admin."}), 403

    if user:
        account_session_uid = ensure_user_session_uid(user)
        session.clear()
        session['user_id'] = user.id
        session['role'] = user.role
        session['session_uid'] = account_session_uid
        user.last_active = time.time()
        db.session.commit()
        current_user_data = serialize_user(user, include_sensitive=True)
        current_user_data["allowedProjects"] = allowed_project_ids(user)
        return jsonify({"success": True, "user": current_user_data})

    return jsonify({"success": False, "message": "Invalid credentials!"}), 401


@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({"success": True})


@app.route('/api/session', methods=['GET'])
def get_session_user():
    """Restore the browser session after page refresh without asking the user to login again."""
    user = get_current_user()
    if not user:
        session.clear()
        return jsonify({"success": False, "message": "No active session"}), 401

    if user.company_id and not session.get('support_root_user_id'):
        if company_is_expired(company_for_user(user)):
            session.clear()
            return company_access_block_response()

    user.last_active = time.time()
    db.session.commit()
    return jsonify({"success": True, "user": serialize_user(user, include_sensitive=True)})


@app.route('/api/sync_status', methods=['GET'])
@login_required
def sync_status():
    user = get_current_user()
    current_time = time.time()

    if user and (current_time - (user.last_active or 0)) > 5:
        user.last_active = current_time
        db.session.commit()

    # Only expose online users from the current workspace.
    online_users = [public_user_id(u) for u in User.query.all() if same_workspace(user, u.company_id) and u.last_active and (current_time - u.last_active) < 12]
    payload = {"success": True, "last_updated": GLOBAL_STATE['last_updated'], "online_users": online_users}
    if user and user.company_id:
        payload.update(company_subscription_payload(company_for_user(user)))
    return jsonify(payload)


@app.route('/api/admin/credentials', methods=['PUT'])
@login_required
@require_roles('admin', 'company_admin')
def update_admin_credentials():
    data = request.get_json(silent=True) or {}
    old_password = data.get('old_password', '').strip()
    new_username = data.get('username', '').strip()
    new_password = data.get('password', '').strip()

    admin_user = get_current_user()
    is_valid_old = False
    if admin_user.password == old_password:
        is_valid_old = True
    else:
        try:
            is_valid_old = check_password_hash(admin_user.password, old_password)
        except Exception:
            is_valid_old = False

    if not is_valid_old:
        return jsonify({"success": False, "message": "Incorrect current password!"}), 401

    if new_username:
        existing = User.query.filter(User.username == new_username, User.id != admin_user.id).first()
        if existing:
            return jsonify({"success": False, "message": "Username already exists"}), 409
        admin_user.username = new_username
    if new_password:
        admin_user.password = generate_password_hash(new_password)

    db.session.commit()
    mark_db_updated()
    return jsonify({"success": True})


@app.route('/api/users', methods=['GET'])
@login_required
def get_users():
    current_user = get_current_user()
    include_sensitive = current_user.role in STAFF_ROLES

    visible_users = [u for u in User.query.all() if is_user_visible_to(current_user, u)]

    # Frontend needs allowedProjects for team filtering and assignee dropdowns.
    user_list = []
    for u in visible_users:
        item = serialize_user(u, include_sensitive=include_sensitive)
        item["allowedProjects"] = allowed_project_ids(u)
        if not include_sensitive:
            item["logincode"] = None
        user_list.append(item)

    return jsonify({"success": True, "users": user_list})


@app.route('/api/users', methods=['POST'])
@login_required
@require_roles('admin', 'company_admin')
def add_user():
    data = request.get_json(silent=True) or {}
    current_user = get_current_user()
    role = (data.get('role') or '').strip()

    if not role:
        return jsonify({"success": False, "message": "Role is required"}), 400
    if role == LEGACY_MANAGER_ROLE:
        return jsonify({"success": False, "message": "Manager role has been removed"}), 400
    if role == 'admin':
        return jsonify({"success": False, "message": "Create or change admin only from Admin Credentials"}), 400
    if role not in ALLOWED_TEAM_ROLES:
        return jsonify({"success": False, "message": "Invalid role"}), 400

    name = (data.get('name') or '').strip()
    if not name:
        return jsonify({"success": False, "message": "Name is required"}), 400

    # Login code is mandatory for client/freelancer/supervisor/manager login.
    # If the frontend accidentally sends a duplicate/blank value, generate a fresh one
    # instead of breaking with a database save error.
    requested_logincode = (data.get('logincode') or '').strip()
    if requested_logincode and not User.query.filter_by(logincode=requested_logincode).first():
        logincode = requested_logincode
    else:
        logincode = generate_unique_logincode()

    initial_projects = data.get('allowedProjects', [])
    if not isinstance(initial_projects, list):
        initial_projects = []

    # For all non-admin accounts, set an internal unique username even though login uses logincode.
    # This avoids multi-user failures on stricter database engines and old migrated DB files.
    internal_username = generate_internal_username(role) if role != 'admin' else None

    new_user = User(
        session_uid=generate_session_uid(),
        name=name,
        role=role,
        username=internal_username,
        logincode=logincode,
        allowed_projects=json.dumps(initial_projects),
        show_payments=data.get('showPayments', True),
        created_by_id=current_user.id if current_user.role in STAFF_ROLES else None,
        company_id=current_user.company_id
    )

    try:
        db.session.add(new_user)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({"success": False, "message": "Database save failed: login code already exists"}), 409
    except Exception:
        db.session.rollback()
        return jsonify({"success": False, "message": "Database save failed"}), 500

    mark_db_updated()
    return jsonify({"success": True, "user_id": public_user_id(new_user), "logincode": new_user.logincode})

@app.route('/api/users/<user_id>', methods=['PUT'])
@login_required
def update_user(user_id):
    data = request.get_json(silent=True) or {}
    current_user = get_current_user()
    target_int_id = parse_public_user_id(user_id)
    if target_int_id is None:
        return jsonify({"success": False, "message": "Invalid user id"}), 400

    target_user = User.query.get(target_int_id)
    if not target_user:
        return jsonify({"success": False}), 404

    is_self = current_user.id == target_user.id
    is_staff = current_user.role in STAFF_ROLES
    if not can_modify_user(current_user, target_user):
        return jsonify({"success": False, "message": "Forbidden"}), 403

    # Anyone may edit their own profile pic/name. Only staff can edit permissions/payments.
    if 'profilePic' in data:
        target_user.profile_pic = data['profilePic']
    if 'name' in data and (is_self or is_staff):
        new_name = str(data['name']).strip()
        if new_name:
            target_user.name = new_name
    if is_staff:
        if 'allowedProjects' in data:
            projects_to_save = data['allowedProjects']
            target_user.allowed_projects = json.dumps(projects_to_save)
        if 'showPayments' in data:
            target_user.show_payments = bool(data['showPayments'])

    db.session.commit()
    mark_db_updated()
    return jsonify({"success": True})


@app.route('/api/users/<user_id>', methods=['DELETE'])
@login_required
@require_roles('admin', 'company_admin')
def delete_user(user_id):
    current_user = get_current_user()
    target_int_id = parse_public_user_id(user_id)
    if target_int_id is None:
        return jsonify({"success": False, "message": "Invalid user id"}), 400

    user = User.query.get(target_int_id)
    if not user:
        return jsonify({"success": False}), 404
    if user.role == 'admin':
        return jsonify({"success": False, "message": "You cannot delete another admin from here"}), 403
    if not can_modify_user(current_user, user):
        return jsonify({"success": False, "message": "Forbidden"}), 403
    if user.id == current_user.id:
        return jsonify({"success": False, "message": "You cannot delete your own account"}), 400

    def remove_profile_pic(target):
        if target.profile_pic and target.profile_pic.startswith('/static/uploads/'):
            relative_path = target.profile_pic.replace('/static/uploads/', '', 1)
            if '..' not in relative_path and not relative_path.startswith('/'):
                file_path = safe_join_upload(relative_path)
                if os.path.exists(file_path):
                    try:
                        os.remove(file_path)
                    except Exception:
                        pass

    # If root admin deletes a manager, remove that manager workspace: team members, projects, assignments and records.
    if user.role == 'manager' and current_user.role == 'admin':
        managed_user_ids = [u.id for u in User.query.filter_by(created_by_id=user.id).all()]
        for child in User.query.filter_by(created_by_id=user.id).all():
            remove_profile_pic(child)
            db.session.delete(child)

        manager_projects = [p for p in Project.query.all() if project_manager_owner_id(p) == user.id]
        for project in manager_projects:
            proj_name = secure_filename(project.name)
            folder_path = safe_join_upload(proj_name)
            if os.path.exists(folder_path):
                shutil.rmtree(folder_path, ignore_errors=True)
            Assignment.query.filter_by(project_id=project.id).delete()
            Invoice.query.filter_by(projectId=project.id).delete()
            db.session.delete(project)

        if managed_user_ids:
            Invoice.query.filter(Invoice.targetUserId.in_([f"u{x}" for x in managed_user_ids])).delete(synchronize_session=False)
        Invoice.query.filter_by(created_by_id=user.id).delete()

    remove_profile_pic(user)
    db.session.delete(user)
    db.session.commit()
    mark_db_updated()
    return jsonify({"success": True})


@app.route('/api/projects', methods=['GET'])
@login_required
def get_projects():
    current_user = get_current_user()
    projects = Project.query.all()
    projects = [p for p in projects if user_has_project_access(current_user, p.id)]
    return jsonify({"success": True, "projects": [serialize_project(p) for p in projects]})


@app.route('/api/projects', methods=['POST'])
@login_required
def add_project():
    current_user = get_current_user()
    if not user_can_create_or_manage_project(current_user):
        return jsonify({"success": False, "message": "Forbidden"}), 403

    data = request.get_json(silent=True) or {}
    new_project_id = (data.get('id') or '').strip()
    name = (data.get('name') or '').strip()
    if not new_project_id or not name:
        return jsonify({"success": False, "message": "Project id and name are required"}), 400
    if Project.query.get(new_project_id):
        return jsonify({"success": False, "message": "Project already exists"}), 409

    db.session.add(Project(
        id=new_project_id,
        name=name,
        img=data.get('img'),
        active=data.get('active', False),
        type=data.get('type', 'Asset'),
        stages=json.dumps(data.get('stages', ["Mod", "BS", "UV", "Tex", "Rig"])),
        pipeline_graph=data.get('pipeline_graph', None),
        episodes=json.dumps(data.get('episodes', [])),
        episode_thumbs=json.dumps(data.get('episodeThumbs', {})),
        created_by_id=current_user.id if current_user.role in STAFF_ROLES else None,
        company_id=current_user.company_id
    ))

    # Keep current frontend compatible: creator can see the newly created project.
    if current_user.role != 'admin':
        allowed = allowed_project_ids(current_user)
        if new_project_id not in allowed:
            allowed.append(new_project_id)
            current_user.allowed_projects = json.dumps(allowed)

    db.session.commit()
    mark_db_updated()
    return jsonify({"success": True})


@app.route('/api/projects/<project_id>', methods=['PUT'])
@login_required
def update_project(project_id):
    current_user = get_current_user()
    data = request.get_json(silent=True) or {}
    project = Project.query.get(project_id)
    if not project:
        return jsonify({"success": False}), 404
    if not user_has_project_access(current_user, project_id):
        return jsonify({"success": False, "message": "Forbidden"}), 403

    # Admin can edit full project/pipeline settings. Project-access users can update safe visual/episode data.
    if can_manage_project(current_user, project):
        if 'name' in data and str(data['name']).strip():
            project.name = str(data['name']).strip()
        if 'active' in data:
            project.active = bool(data['active'])
        if 'type' in data:
            project.type = data['type']
        if 'stages' in data:
            project.stages = json.dumps(data['stages'])
        if 'pipeline_graph' in data:
            project.pipeline_graph = data['pipeline_graph']

    if 'img' in data:
        project.img = data['img']
    if 'episodes' in data:
        project.episodes = json.dumps(data['episodes'])
    if 'episodeThumbs' in data:
        project.episode_thumbs = json.dumps(data['episodeThumbs'])

    db.session.commit()
    mark_db_updated()
    return jsonify({"success": True})


@app.route('/api/projects/<project_id>', methods=['DELETE'])
@login_required
@require_roles('admin', 'company_admin')
def delete_project(project_id):
    project = Project.query.get(project_id)
    if not project:
        return jsonify({"success": False}), 404
    if not can_manage_project(get_current_user(), project):
        return jsonify({"success": False, "message": "Forbidden"}), 403

    proj_name = secure_filename(project.name)
    folder_path = safe_join_upload(proj_name)
    if os.path.exists(folder_path):
        shutil.rmtree(folder_path, ignore_errors=True)

    Assignment.query.filter_by(project_id=project_id).delete()
    Invoice.query.filter_by(projectId=project_id).delete()
    db.session.delete(project)
    db.session.commit()
    mark_db_updated()
    return jsonify({"success": True})


@app.route('/api/assignments', methods=['GET'])
@login_required
def get_assignments():
    current_user = get_current_user()
    assignments = [a for a in Assignment.query.all() if user_has_assignment_access(current_user, a)]
    return jsonify({"success": True, "assignments": [serialize_assignment(a) for a in assignments]})


@app.route('/api/assignments', methods=['POST'])
@login_required
def add_assignment():
    current_user = get_current_user()
    data = request.get_json(silent=True) or {}
    project_id = data.get('projectId')

    if current_user.role not in PROJECT_CREATOR_ROLES or not user_has_project_access(current_user, project_id):
        return jsonify({"success": False, "message": "Forbidden"}), 403

    assignment_id = data.get('id')
    if not assignment_id or Assignment.query.get(assignment_id):
        return jsonify({"success": False, "message": "Invalid or duplicate assignment id"}), 400

    new_assignment = Assignment(
        id=assignment_id,
        project_id=project_id,
        name=data.get('name') or 'Untitled',
        status=data.get('status', 'paused'),
        img=data.get('img'),
        mandays=data.get('mandays', 0),
        levels=json.dumps(data.get('levels', [])),
        current_level_index=data.get('currentLevelIndex', 0),
        active_stages=json.dumps(data.get('activeStages', [])),
        stage_assignees=json.dumps(data.get('stageAssignees', {})),
        completed_levels=json.dumps(data.get('completedLevels', [])),
        versions=json.dumps(data.get('versions', [])),
        input_data=json.dumps(data.get('inputData', {})),
        assigned_to=data.get('assignedTo'),
        created_at=data.get('createdAt') or time.time() * 1000,
        accumulated_time=data.get('accumulatedTime', 0.0),
        order_index=data.get('orderIndex'),
        created_by_id=current_user.id if current_user.role in STAFF_ROLES else None,
        company_id=(Project.query.get(project_id).company_id if Project.query.get(project_id) else current_user.company_id)
    )
    db.session.add(new_assignment)
    db.session.commit()
    mark_db_updated()
    return jsonify({"success": True})


@app.route('/api/assignments/<assign_id>', methods=['PUT'])
@login_required
def update_assignment(assign_id):
    current_user = get_current_user()
    data = request.get_json(silent=True) or {}
    assignment = Assignment.query.get(assign_id)
    if not assignment:
        return jsonify({"success": False}), 404
    if not user_has_assignment_access(current_user, assignment):
        return jsonify({"success": False, "message": "Forbidden"}), 403

    fields = ['status', 'currentLevelIndex', 'assignedTo', 'createdAt', 'accumulatedTime', 'orderIndex']
    for field in fields:
        if field in data:
            db_field = (field
                        .replace('currentLevelIndex', 'current_level_index')
                        .replace('assignedTo', 'assigned_to')
                        .replace('createdAt', 'created_at')
                        .replace('accumulatedTime', 'accumulated_time')
                        .replace('orderIndex', 'order_index'))
            setattr(assignment, db_field, data[field])

    if 'completedLevels' in data:
        assignment.completed_levels = json.dumps(data['completedLevels'])
    if 'versions' in data:
        assignment.versions = json.dumps(data['versions'])
    if 'inputData' in data:
        assignment.input_data = json.dumps(data['inputData'])
    if 'activeStages' in data:
        assignment.active_stages = json.dumps(data['activeStages'])
    if 'stageAssignees' in data and current_user.role in STAFF_ROLES:
        assignment.stage_assignees = json.dumps(data['stageAssignees'])
    if 'levels' in data and current_user.role in STAFF_ROLES:
        assignment.levels = json.dumps(data['levels'])

    db.session.commit()
    mark_db_updated()
    return jsonify({"success": True})


@app.route('/api/assignments/<assign_id>', methods=['DELETE'])
@login_required
@require_roles('admin', 'company_admin')
def delete_assignment(assign_id):
    assignment = Assignment.query.get(assign_id)
    if not assignment:
        return jsonify({"success": False}), 404

    project = Project.query.get(assignment.project_id)
    if not can_manage_project(get_current_user(), project):
        return jsonify({"success": False, "message": "Forbidden"}), 403
    if project:
        proj_name = secure_filename(project.name)
        assign_name = secure_filename(assignment.name)
        folder_path = safe_join_upload(proj_name, assign_name)
        if os.path.exists(folder_path):
            shutil.rmtree(folder_path, ignore_errors=True)

    Invoice.query.filter_by(assignmentId=assign_id).delete()
    db.session.delete(assignment)
    db.session.commit()
    mark_db_updated()
    return jsonify({"success": True})


@app.route('/api/invoices', methods=['GET'])
@login_required
def get_invoices():
    current_user = get_current_user()
    invoices = [i for i in Invoice.query.all() if can_access_invoice(current_user, i)]
    return jsonify({"success": True, "invoices": [serialize_invoice(i) for i in invoices]})


@app.route('/api/invoices', methods=['POST'])
@login_required
def add_invoice():
    current_user = get_current_user()
    data = request.get_json(silent=True) or {}
    project_id = data.get('projectId')

    # Staff can create records only inside their visible workspace.
    if not project_id or not user_has_project_access(current_user, project_id):
        return jsonify({"success": False, "message": "Forbidden"}), 403

    inv_id = data.get('id')
    if not inv_id or Invoice.query.get(inv_id):
        return jsonify({"success": False, "message": "Invalid or duplicate invoice id"}), 400

    new_inv = Invoice(
        id=inv_id,
        roleType=data.get('roleType'),
        targetUserId=data.get('targetUserId'),
        paymentType=data.get('paymentType'),
        projectId=project_id,
        assignmentId=data.get('assignmentId'),
        stage=data.get('stage'),
        issueDate=data.get('issueDate'),
        dueDate=data.get('dueDate'),
        description=data.get('description'),
        amount=float(data.get('amount', 0.0) or 0.0),
        status=data.get('status', 'pending'),
        created_at=data.get('createdAt') or time.time() * 1000,
        created_by_id=current_user.id if current_user.role in STAFF_ROLES else None,
        company_id=(Project.query.get(project_id).company_id if Project.query.get(project_id) else current_user.company_id)
    )
    db.session.add(new_inv)
    db.session.commit()
    mark_db_updated()
    return jsonify({"success": True})


@app.route('/api/invoices/<inv_id>', methods=['PUT'])
@login_required
def update_invoice(inv_id):
    current_user = get_current_user()
    data = request.get_json(silent=True) or {}
    inv = Invoice.query.get(inv_id)
    if not inv:
        return jsonify({"success": False}), 404

    is_staff = current_user.role in STAFF_ROLES
    if not can_access_invoice(current_user, inv):
        return jsonify({"success": False, "message": "Forbidden"}), 403

    if 'status' in data:
        inv.status = data['status']
    # Amount changes are restricted to staff to avoid client/freelancer tampering.
    if 'amount' in data:
        if not is_staff:
            return jsonify({"success": False, "message": "Only staff can edit invoice amount"}), 403
        inv.amount = float(data['amount'])

    db.session.commit()
    mark_db_updated()
    return jsonify({"success": True})


@app.route('/api/invoices/<inv_id>', methods=['DELETE'])
@login_required
@require_roles('admin', 'company_admin')
def delete_invoice(inv_id):
    inv = Invoice.query.get(inv_id)
    if not inv:
        return jsonify({"success": False}), 404
    if not can_access_invoice(get_current_user(), inv):
        return jsonify({"success": False, "message": "Forbidden"}), 403
    db.session.delete(inv)
    db.session.commit()
    mark_db_updated()
    return jsonify({"success": True})


@app.route('/api/file', methods=['DELETE'])
@login_required
def delete_single_file():
    current_user = get_current_user()
    data = request.get_json(silent=True) or {}
    file_url = data.get('fileUrl')

    if not file_url or not file_url.startswith('/static/uploads/'):
        return jsonify({"success": False, "message": "Invalid file URL"}), 400

    # Users can delete their own profile picture, or files inside projects they can access.
    project_id = project_id_from_upload_url(file_url)
    if file_url != current_user.profile_pic and not user_has_project_access(current_user, project_id):
        return jsonify({"success": False, "message": "Forbidden"}), 403

    relative_path = file_url.replace('/static/uploads/', '', 1)
    if '..' in relative_path or relative_path.startswith('/'):
        return jsonify({"success": False, "message": "Invalid path traversal detected"}), 400

    file_path = safe_join_upload(relative_path)
    if os.path.exists(file_path) and os.path.isfile(file_path):
        try:
            os.remove(file_path)
            mark_db_updated()
        except Exception:
            return jsonify({"success": False, "message": "Could not delete file"}), 500

    return jsonify({"success": True})


@app.route('/api/upload', methods=['POST'])
@login_required
def upload_file():
    current_user = get_current_user()

    if 'file' not in request.files:
        return jsonify({"success": False, "message": "No file part"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"success": False, "message": "No selected file"}), 400
    if not allowed_file(file.filename):
        return jsonify({"success": False, "message": "File type not allowed"}), 400

    project_name_raw = request.form.get('projectName', 'Misc')
    assignment_name_raw = request.form.get('assignmentName', 'Misc')
    folder_type_raw = request.form.get('folderType', 'General')

    project_name = secure_filename(project_name_raw) or 'Misc'
    assignment_name = secure_filename(assignment_name_raw) or 'Misc'
    folder_type = secure_filename(folder_type_raw) or 'General'

    # Only root admin may change the global login wallpaper.
    if project_name == 'System' and assignment_name == 'Settings' and folder_type == 'Backgrounds' and not is_root_admin(current_user):
        return jsonify({"success": False, "message": "Only root admin can change wallpaper"}), 403

    # Best-effort permission check: projectName is sent by frontend, not projectId.
    # This keeps compatibility while blocking unrelated project uploads.
    if project_name not in {'Profile', 'System'}:
        matched_project = next((p for p in Project.query.all() if same_workspace(current_user, p.company_id) and secure_filename(p.name) == project_name), None)
        if matched_project and not user_has_project_access(current_user, matched_project.id):
            return jsonify({"success": False, "message": "Forbidden"}), 403

    custom_file_name = request.form.get('customFileName')
    if custom_file_name:
        filename_to_save = secure_filename(custom_file_name)
        if not allowed_file(filename_to_save):
            return jsonify({"success": False, "message": "Custom file type not allowed"}), 400
    else:
        filename_to_save = f"{int(time.time())}_{secure_filename(file.filename)}"

    if current_user.company_id and project_name != 'System':
        dynamic_folder = safe_join_upload('companies', current_user.company_id, project_name, assignment_name, folder_type)
        url_folder = f"static/uploads/companies/{current_user.company_id}/{project_name}/{assignment_name}/{folder_type}"
    else:
        dynamic_folder = safe_join_upload(project_name, assignment_name, folder_type)
        url_folder = f"static/uploads/{project_name}/{assignment_name}/{folder_type}"
    os.makedirs(dynamic_folder, exist_ok=True)

    filepath = os.path.join(dynamic_folder, filename_to_save)
    file.save(filepath)

    file_url = f"/{url_folder}/{filename_to_save}"

    thumbnail_url = None
    if 'thumbnail' in request.files:
        thumb_file = request.files['thumbnail']
        if thumb_file and thumb_file.filename != '':
            if not allowed_file(thumb_file.filename):
                return jsonify({"success": False, "message": "Thumbnail file type not allowed"}), 400
            thumb_ext = os.path.splitext(secure_filename(thumb_file.filename))[1]
            thumb_filename = filename_to_save.rsplit('.', 1)[0] + "_thumb" + thumb_ext
            thumb_filepath = os.path.join(dynamic_folder, thumb_filename)
            thumb_file.save(thumb_filepath)
            thumbnail_url = f"/{url_folder}/{thumb_filename}"

    if not thumbnail_url and filename_to_save.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg')):
        thumbnail_url = file_url

    mark_db_updated()
    return jsonify({"success": True, "fileUrl": file_url, "filename": filename_to_save, "thumbnailUrl": thumbnail_url})




def serialize_company(company: 'Company') -> dict:
    admin_user = User.query.filter_by(company_id=company.id, role=COMPANY_ADMIN_ROLE).first()
    subscription = company_subscription_payload(company)
    remaining_days = subscription.get("companyRemainingDays")
    return {
        "id": company.id,
        "name": company.name,
        "username": admin_user.username if admin_user else "",
        "profilePic": admin_user.profile_pic if admin_user else None,
        "lastActive": admin_user.last_active if admin_user else 0,
        "active": bool(company.active),
        "blocked": (company.active is False),
        "subscriptionDays": int(company.subscription_days or 0),
        "expiresAt": company.expires_at,
        "remainingDays": remaining_days,
        "expired": company_is_expired(company),
        "subscriptionPercent": subscription.get("companySubscriptionPercent", 0),
        "subscriptionWarning": subscription.get("companySubscriptionWarning", "none"),
        "createdAt": company.created_at,
        "teamCount": User.query.filter(User.company_id == company.id, User.role.notin_([COMPANY_ADMIN_ROLE, LEGACY_MANAGER_ROLE])).count(),
        "projectCount": Project.query.filter_by(company_id=company.id).count(),
    }


@app.route('/api/companies', methods=['GET'])
@login_required
@require_roles('admin')
def get_companies():
    current_user = get_current_user()
    if not is_root_admin(current_user):
        return jsonify({"success": False, "message": "Only root admin can manage companies"}), 403
    companies = Company.query.order_by(Company.created_at.desc()).all()
    return jsonify({"success": True, "companies": [serialize_company(c) for c in companies]})


@app.route('/api/companies', methods=['POST'])
@login_required
@require_roles('admin')
def add_company():
    current_user = get_current_user()
    if not is_root_admin(current_user):
        return jsonify({"success": False, "message": "Only root admin can add companies"}), 403

    data = request.get_json(silent=True) or {}
    name = (data.get('name') or '').strip()
    username = (data.get('username') or '').strip()
    password = (data.get('password') or '').strip()
    now_ms = time.time() * 1000
    expires_at = parse_expiry_date_to_ms(data.get('expiresAtDate') or data.get('expiryDate') or '')
    if expires_at is None:
        try:
            subscription_days = int(data.get('subscriptionDays') or DEFAULT_COMPANY_SUBSCRIPTION_DAYS)
        except Exception:
            subscription_days = DEFAULT_COMPANY_SUBSCRIPTION_DAYS
        subscription_days = max(1, min(subscription_days, 3650))
        expires_at = now_ms + (subscription_days * DAY_MS)
    else:
        subscription_days = max(0, min(int((expires_at - now_ms + DAY_MS - 1) // DAY_MS), 3650))

    if not name or not username or not password:
        return jsonify({"success": False, "message": "Company name, username and password are required"}), 400
    if subscription_days < 1:
        return jsonify({"success": False, "message": "Choose a future expiry date"}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({"success": False, "message": "Username already exists"}), 409

    company = Company(
        id=generate_company_id(),
        name=name,
        visible_password=None,
        subscription_days=subscription_days,
        expires_at=expires_at,
        created_at=now_ms,
        active=True
    )
    company_admin = User(
        session_uid=generate_session_uid(),
        name=name,
        role=COMPANY_ADMIN_ROLE,
        username=username,
        password=generate_password_hash(password),
        allowed_projects='[]',
        profile_pic=None,
        created_by_id=current_user.id,
        company_id=company.id,
        show_payments=True
    )
    try:
        db.session.add(company)
        db.session.add(company_admin)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({"success": False, "message": "Database save failed: username already exists"}), 409
    except Exception:
        db.session.rollback()
        return jsonify({"success": False, "message": "Database save failed"}), 500

    mark_db_updated()
    return jsonify({"success": True, "company": serialize_company(company)})


@app.route('/api/companies/<company_id>/credentials', methods=['PUT'])
@login_required
@require_roles('admin')
def update_company_credentials(company_id):
    current_user = get_current_user()
    if not is_root_admin(current_user):
        return jsonify({"success": False, "message": "Only root admin can update company login"}), 403

    company = Company.query.get(company_id)
    if not company:
        return jsonify({"success": False, "message": "Company not found"}), 404

    admin_user = User.query.filter_by(company_id=company.id, role=COMPANY_ADMIN_ROLE).first()
    if not admin_user:
        return jsonify({"success": False, "message": "Company admin account not found"}), 404

    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    password = (data.get('password') or '').strip()
    if not username and not password:
        return jsonify({"success": False, "message": "Enter username or password to update"}), 400

    if username and username != admin_user.username:
        existing = User.query.filter_by(username=username).first()
        if existing and existing.id != admin_user.id:
            return jsonify({"success": False, "message": "Username already exists"}), 409
        admin_user.username = username

    if password:
        admin_user.password = generate_password_hash(password)
        company.visible_password = None

    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({"success": False, "message": "Database save failed: username already exists"}), 409
    except Exception:
        db.session.rollback()
        return jsonify({"success": False, "message": "Database save failed"}), 500

    mark_db_updated()
    return jsonify({"success": True, "company": serialize_company(company)})


@app.route('/api/companies/<company_id>/subscription', methods=['PUT'])
@login_required
@require_roles('admin')
def update_company_subscription(company_id):
    current_user = get_current_user()
    if not is_root_admin(current_user):
        return jsonify({"success": False, "message": "Only root admin can update company subscription"}), 403

    company = Company.query.get(company_id)
    if not company:
        return jsonify({"success": False, "message": "Company not found"}), 404

    data = request.get_json(silent=True) or {}
    now_ms = time.time() * 1000
    expires_at = parse_expiry_date_to_ms(data.get('expiresAtDate') or data.get('expiryDate') or '')
    if expires_at is None:
        try:
            days = int(data.get('subscriptionDays'))
        except Exception:
            return jsonify({"success": False, "message": "Enter valid expiry date"}), 400
        days = max(0, min(days, 3650))
        expires_at = now_ms + (days * DAY_MS)
    else:
        days = max(0, min(int((expires_at - now_ms + DAY_MS - 1) // DAY_MS), 3650))

    company.subscription_days = days
    company.expires_at = expires_at
    company.active = days > 0
    db.session.commit()
    mark_db_updated()
    return jsonify({"success": True, "company": serialize_company(company)})


@app.route('/api/companies/<company_id>/add-days', methods=['PUT'])
@login_required
@require_roles('admin')
def add_company_subscription_days(company_id):
    current_user = get_current_user()
    if not is_root_admin(current_user):
        return jsonify({"success": False, "message": "Only root admin can update company subscription"}), 403

    company = Company.query.get(company_id)
    if not company:
        return jsonify({"success": False, "message": "Company not found"}), 404

    data = request.get_json(silent=True) or {}
    try:
        add_days = int(data.get('days') or data.get('addDays') or 0)
    except Exception:
        return jsonify({"success": False, "message": "Enter valid days"}), 400

    # v22: allow positive OR negative days. Positive extends the subscription.
    # Negative reduces from the current expiry date. Zero is ignored so mistakes
    # do not silently change the company access.
    if add_days == 0:
        return jsonify({"success": False, "message": "Enter days other than 0. Use a negative number to reduce days."}), 400
    add_days = max(-3650, min(add_days, 3650))
    now_ms = time.time() * 1000
    current_expiry = float(company.expires_at or 0)
    base_ms = current_expiry if current_expiry > 0 else now_ms
    if add_days > 0 and base_ms < now_ms:
        base_ms = now_ms
    new_expiry = base_ms + (add_days * DAY_MS)
    # Prevent accidental huge negative dates; make it expired from now instead.
    if new_expiry < 0:
        new_expiry = now_ms - DAY_MS
    company.expires_at = new_expiry
    company.subscription_days = max(0, min(int((company.expires_at - now_ms + DAY_MS - 1) // DAY_MS), 3650))
    # Do not automatically unblock a manually blocked company. If it was active,
    # keep it active and let expiry decide access.
    if company.active is not False:
        company.active = True
    db.session.commit()
    mark_db_updated()
    return jsonify({"success": True, "company": serialize_company(company)})


@app.route('/api/companies/<company_id>/block', methods=['PUT'])
@login_required
@require_roles('admin')
def set_company_block(company_id):
    """Root admin can block/unblock one company and its whole team."""
    current_user = get_current_user()
    if not is_root_admin(current_user):
        return jsonify({"success": False, "message": "Only root admin can block companies"}), 403

    company = Company.query.get(company_id)
    if not company:
        return jsonify({"success": False, "message": "Company not found"}), 404

    data = request.get_json(silent=True) or {}
    if 'blocked' in data:
        blocked = bool(data.get('blocked'))
    elif 'active' in data:
        blocked = not bool(data.get('active'))
    else:
        blocked = not (company.active is False)

    company.active = not blocked
    db.session.commit()
    mark_db_updated()
    return jsonify({"success": True, "company": serialize_company(company)})


@app.route('/api/companies/<company_id>/login-as', methods=['POST'])
@login_required
@require_roles('admin')
def login_as_company(company_id):
    """Root admin support login: open a company workspace without knowing its password."""
    root_user = get_current_user()
    if not is_root_admin(root_user):
        return jsonify({"success": False, "message": "Only root admin can use support login"}), 403

    company = Company.query.get(company_id)
    if not company:
        return jsonify({"success": False, "message": "Company not found"}), 404

    company_admin = User.query.filter_by(company_id=company.id, role=COMPANY_ADMIN_ROLE).first()
    if not company_admin:
        return jsonify({"success": False, "message": "Company admin account not found"}), 404

    root_session_uid = ensure_user_session_uid(root_user)
    company_session_uid = ensure_user_session_uid(company_admin)

    session.clear()
    session['user_id'] = company_admin.id
    session['role'] = company_admin.role
    session['session_uid'] = company_session_uid
    session['support_root_user_id'] = root_user.id
    session['support_root_session_uid'] = root_session_uid
    session['support_company_id'] = company.id
    session['support_company_name'] = company.name

    company_admin.last_active = time.time()
    db.session.commit()
    mark_db_updated()

    current_user_data = serialize_user(company_admin, include_sensitive=True)
    current_user_data["allowedProjects"] = allowed_project_ids(company_admin)
    return jsonify({"success": True, "user": current_user_data})


@app.route('/api/support/exit', methods=['POST'])
@login_required
def exit_support_login():
    """Return from company support mode back to the root admin session."""
    root_id = session.get('support_root_user_id')
    root_uid = session.get('support_root_session_uid')
    if not root_id or not root_uid:
        return jsonify({"success": False, "message": "Not in support mode"}), 400

    root_user = User.query.get(root_id)
    if not root_user or root_user.role != ROOT_ADMIN_ROLE or root_user.company_id:
        session.clear()
        return jsonify({"success": False, "message": "Root admin session not found"}), 401

    if not getattr(root_user, 'session_uid', None):
        ensure_user_session_uid(root_user)
    if root_user.session_uid != root_uid:
        session.clear()
        return jsonify({"success": False, "message": "Root admin session expired"}), 401

    session.clear()
    session['user_id'] = root_user.id
    session['role'] = root_user.role
    session['session_uid'] = root_user.session_uid
    root_user.last_active = time.time()
    db.session.commit()
    mark_db_updated()

    current_user_data = serialize_user(root_user, include_sensitive=True)
    current_user_data["allowedProjects"] = allowed_project_ids(root_user)
    return jsonify({"success": True, "user": current_user_data})


@app.route('/api/companies/<company_id>', methods=['DELETE'])
@login_required
@require_roles('admin')
def delete_company(company_id):
    current_user = get_current_user()
    if not is_root_admin(current_user):
        return jsonify({"success": False, "message": "Only root admin can remove companies"}), 403

    company = Company.query.get(company_id)
    if not company:
        return jsonify({"success": False, "message": "Company not found"}), 404

    # Remove company upload folder first.
    company_upload_folder = safe_join_upload('companies', company_id)
    if os.path.exists(company_upload_folder):
        shutil.rmtree(company_upload_folder, ignore_errors=True)

    Invoice.query.filter_by(company_id=company_id).delete(synchronize_session=False)
    Assignment.query.filter_by(company_id=company_id).delete(synchronize_session=False)
    Project.query.filter_by(company_id=company_id).delete(synchronize_session=False)
    User.query.filter_by(company_id=company_id).delete(synchronize_session=False)
    db.session.delete(company)
    db.session.commit()
    mark_db_updated()
    return jsonify({"success": True})


@app.errorhandler(413)
def request_entity_too_large(error):
    max_mb = app.config['MAX_CONTENT_LENGTH'] // (1024 * 1024)
    return jsonify({"success": False, "message": f"File too large. Max upload size is {max_mb} MB."}), 413


if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_DEBUG', '0') == '1'
    host = os.environ.get('HOST', '127.0.0.1')
    port = int(os.environ.get('PORT', '5000'))
    app.run(host=host, port=port, debug=debug_mode)
