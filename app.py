import os
import json
import time
import shutil
from functools import wraps
from flask import Flask, render_template, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text  # <-- ADDED FOR COMPATIBILITY
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'super-secret-production-key-change-this-later')

os.makedirs(os.path.join(BASE_DIR, 'instance'), exist_ok=True)
DB_PATH = os.path.join(BASE_DIR, 'instance', 'portal_new.db')

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + DB_PATH
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JSON_SORT_KEYS'] = False  # <-- FIXED FOR OLDER FLASK VERSIONS

app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.config['SESSION_COOKIE_HTTPONLY'] = True

UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

db = SQLAlchemy(app)

GLOBAL_STATE = {'last_updated': time.time()}

def mark_db_updated():
    GLOBAL_STATE['last_updated'] = time.time()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({"success": False, "message": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated_function

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=True)
    password = db.Column(db.String(255), nullable=True)
    logincode = db.Column(db.String(50), unique=True, nullable=True)
    allowed_projects = db.Column(db.Text, nullable=True)
    profile_pic = db.Column(db.Text, nullable=True)
    last_active = db.Column(db.Float, default=0.0)
    show_payments = db.Column(db.Boolean, default=True)

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

with app.app_context():
    db.create_all()

    try:
        db.session.execute(text('SELECT show_payments FROM user LIMIT 1'))
    except Exception:
        db.session.rollback()
        db.session.execute(text('ALTER TABLE user ADD COLUMN show_payments BOOLEAN DEFAULT 1'))
        db.session.commit()

    # --- DB MIGRATIONS (FIXED FOR COMPATIBILITY) ---
    try:
        db.session.execute(text('SELECT type FROM project LIMIT 1'))
    except Exception:
        db.session.rollback()
        db.session.execute(text("ALTER TABLE project ADD COLUMN type VARCHAR(50) DEFAULT 'Asset'"))
        db.session.commit()

    try:
        db.session.execute(text('SELECT stages FROM project LIMIT 1'))
    except Exception:
        db.session.rollback()
        db.session.execute(text('ALTER TABLE project ADD COLUMN stages TEXT'))
        db.session.commit()

    try:
        db.session.execute(text('SELECT pipeline_graph FROM project LIMIT 1'))
    except Exception:
        db.session.rollback()
        db.session.execute(text('ALTER TABLE project ADD COLUMN pipeline_graph TEXT'))
        db.session.commit()

    try:
        db.session.execute(text('SELECT last_active FROM user LIMIT 1'))
    except Exception:
        db.session.rollback()
        db.session.execute(text('ALTER TABLE user ADD COLUMN last_active FLOAT DEFAULT 0.0'))
        db.session.commit()

    try:
        db.session.execute(text('SELECT accumulated_time FROM assignment LIMIT 1'))
    except Exception:
        db.session.rollback()
        db.session.execute(text('ALTER TABLE assignment ADD COLUMN accumulated_time FLOAT DEFAULT 0.0'))
        db.session.commit()

    try:
        db.session.execute(text('SELECT order_index FROM assignment LIMIT 1'))
    except Exception:
        db.session.rollback()
        db.session.execute(text('ALTER TABLE assignment ADD COLUMN order_index FLOAT'))
        db.session.commit()

    try:
        db.session.execute(text('SELECT episodes FROM project LIMIT 1'))
    except Exception:
        db.session.rollback()
        db.session.execute(text('ALTER TABLE project ADD COLUMN episodes TEXT'))
        db.session.commit()

    try:
        db.session.execute(text('SELECT episode_thumbs FROM project LIMIT 1'))
    except Exception:
        db.session.rollback()
        db.session.execute(text('ALTER TABLE project ADD COLUMN episode_thumbs TEXT'))
        db.session.commit()

    try:
        db.session.execute(text('SELECT active_stages FROM assignment LIMIT 1'))
    except Exception:
        db.session.rollback()
        db.session.execute(text('ALTER TABLE assignment ADD COLUMN active_stages TEXT'))
        db.session.commit()

    try:
        db.session.execute(text('SELECT stage_assignees FROM assignment LIMIT 1'))
    except Exception:
        db.session.rollback()
        db.session.execute(text('ALTER TABLE assignment ADD COLUMN stage_assignees TEXT'))
        db.session.commit()

    if not User.query.filter_by(role='admin').first():
        hashed_pw = generate_password_hash('123')
        admin_user = User(name='Admin', role='admin', username='admin', password=hashed_pw, allowed_projects='[]', profile_pic=None)
        db.session.add(admin_user)
        db.session.commit()

@app.route('/')
def home():
    return render_template('portal_v08.html')

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    login_type = data.get('type')
    if login_type == 'admin':
        username_input = data.get('username', '').strip()
        password_input = data.get('password', '').strip()
        user = User.query.filter_by(username=username_input, role='admin').first()
        if user:
            is_valid = False
            if user.password:
                if user.password == password_input:
                    is_valid = True
                    user.password = generate_password_hash(password_input)
                    db.session.commit()
                    mark_db_updated()
                else:
                    try:
                        if check_password_hash(user.password, password_input):
                            is_valid = True
                    except: pass
            if not is_valid: user = None
    else:
        logincode_input = data.get('logincode', '').strip()
        user = User.query.filter_by(logincode=logincode_input).first()

    if user:
        session['user_id'] = user.id
        session['role'] = user.role
        return jsonify({"success": True, "user": {"id": f"u{user.id}", "name": user.name, "role": user.role, "profilePic": user.profile_pic, "allowedProjects": json.loads(user.allowed_projects) if user.allowed_projects else [], "showPayments": user.show_payments}})
    return jsonify({"success": False, "message": "Invalid credentials!"}), 401

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({"success": True})

@app.route('/api/sync_status', methods=['GET'])
@login_required
def sync_status():
    user = User.query.get(session['user_id'])
    current_time = time.time()

    if user and (current_time - (user.last_active or 0)) > 5:
        user.last_active = current_time
        db.session.commit()

    online_users = [f"u{u.id}" for u in User.query.all() if u.last_active and (current_time - u.last_active) < 12]

    return jsonify({
        "success": True,
        "last_updated": GLOBAL_STATE['last_updated'],
        "online_users": online_users
    })

@app.route('/api/admin/credentials', methods=['PUT'])
@login_required
def update_admin_credentials():
    data = request.get_json()
    old_password = data.get('old_password', '').strip()
    new_username = data.get('username', '').strip()
    new_password = data.get('password', '').strip()
    admin_user = User.query.filter_by(role='admin').first()
    if admin_user:
        is_valid_old = False
        if admin_user.password == old_password:
            is_valid_old = True
        else:
            try:
                if check_password_hash(admin_user.password, old_password):
                    is_valid_old = True
            except: pass
        if not is_valid_old: return jsonify({"success": False, "message": "Incorrect current password!"}), 401
        if new_username: admin_user.username = new_username
        if new_password: admin_user.password = generate_password_hash(new_password)
        db.session.commit()
        mark_db_updated()
        return jsonify({"success": True})
    return jsonify({"success": False, "message": "Admin user not found!"}), 404

@app.route('/api/users', methods=['GET'])
@login_required
def get_users():
    users = User.query.all()
    user_list = [{
        "id": f"u{u.id}",
        "name": u.name,
        "role": u.role,
        "logincode": u.logincode,
        "profilePic": u.profile_pic,
        "allowedProjects": json.loads(u.allowed_projects) if u.allowed_projects else [],
        "lastActive": u.last_active,
        "showPayments": u.show_payments
    } for u in users]
    return jsonify({"success": True, "users": user_list})

@app.route('/api/users', methods=['POST'])
@login_required
def add_user():
    data = request.get_json()
    new_user = User(name=data.get('name'), role=data.get('role'), logincode=data.get('logincode'), allowed_projects='[]')
    db.session.add(new_user)
    db.session.commit()
    mark_db_updated()
    return jsonify({"success": True, "user_id": f"u{new_user.id}"})

@app.route('/api/users/<user_id>', methods=['PUT'])
@login_required
def update_user(user_id):
    data = request.get_json()
    user = User.query.get(int(user_id.replace('u', '')))
    if user:
        if 'allowedProjects' in data: user.allowed_projects = json.dumps(data['allowedProjects'])
        if 'profilePic' in data: user.profile_pic = data['profilePic']
        if 'name' in data: user.name = data['name']
        if 'showPayments' in data: user.show_payments = data['showPayments']
        db.session.commit()
        mark_db_updated()
        return jsonify({"success": True})
    return jsonify({"success": False}), 404

@app.route('/api/users/<user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    user = User.query.get(int(user_id.replace('u', '')))
    if user:
        if user.profile_pic and user.profile_pic.startswith('/static/uploads/'):
            relative_path = user.profile_pic.replace('/static/uploads/', '', 1)
            if '..' not in relative_path and not relative_path.startswith('/'):
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], relative_path)
                if os.path.exists(file_path):
                    try: os.remove(file_path)
                    except Exception: pass
        db.session.delete(user)
        db.session.commit()
        mark_db_updated()
        return jsonify({"success": True})
    return jsonify({"success": False}), 404

@app.route('/api/projects', methods=['GET'])
@login_required
def get_projects():
    projects = []
    for p in Project.query.all():
        try:
            stages_data = json.loads(p.stages) if p.stages else ["Mod", "BS", "UV", "Tex", "Rig"]
        except:
            stages_data = ["Mod", "BS", "UV", "Tex", "Rig"]

        projects.append({
            "id": p.id, "name": p.name, "img": p.img, "active": p.active, "type": p.type,
            "stages": stages_data,
            "pipeline_graph": p.pipeline_graph,
            "episodes": json.loads(p.episodes) if p.episodes else [],
            "episodeThumbs": json.loads(p.episode_thumbs) if p.episode_thumbs else {}
        })
    return jsonify({"success": True, "projects": projects})

@app.route('/api/projects', methods=['POST'])
@login_required
def add_project():
    data = request.get_json()
    new_project_id = data.get('id')
    db.session.add(Project(
        id=new_project_id,
        name=data.get('name'),
        img=data.get('img'),
        active=data.get('active', False),
        type=data.get('type', 'Asset'),
        stages=json.dumps(data.get('stages', ["Mod", "BS", "UV", "Tex", "Rig"])),
        pipeline_graph=data.get('pipeline_graph', None),
        episodes=json.dumps(data.get('episodes', [])),
        episode_thumbs=json.dumps(data.get('episodeThumbs', {}))
    ))

    user_id = session.get('user_id')
    if user_id:
        user = User.query.get(user_id)
        if user and user.role == 'client':
            allowed = json.loads(user.allowed_projects) if user.allowed_projects else []
            if new_project_id not in allowed:
                allowed.append(new_project_id)
                user.allowed_projects = json.dumps(allowed)
    db.session.commit()
    mark_db_updated()
    return jsonify({"success": True})

@app.route('/api/projects/<project_id>', methods=['PUT'])
@login_required
def update_project(project_id):
    data = request.get_json()
    project = Project.query.get(project_id)
    if project:
        if 'stages' in data: project.stages = json.dumps(data['stages'])
        if 'pipeline_graph' in data: project.pipeline_graph = data['pipeline_graph']
        if 'episodes' in data: project.episodes = json.dumps(data['episodes'])
        if 'episodeThumbs' in data: project.episode_thumbs = json.dumps(data['episodeThumbs'])
        db.session.commit()
        mark_db_updated()
        return jsonify({"success": True})
    return jsonify({"success": False}), 404

@app.route('/api/projects/<project_id>', methods=['DELETE'])
@login_required
def delete_project(project_id):
    project = Project.query.get(project_id)
    if project:
        proj_name = secure_filename(project.name)
        folder_path = os.path.join(app.config['UPLOAD_FOLDER'], proj_name)
        if os.path.exists(folder_path): shutil.rmtree(folder_path, ignore_errors=True)
        db.session.delete(project)
        Assignment.query.filter_by(project_id=project_id).delete()
        db.session.commit()
        mark_db_updated()
        return jsonify({"success": True})
    return jsonify({"success": False}), 404

@app.route('/api/assignments', methods=['GET'])
@login_required
def get_assignments():
    assignments = Assignment.query.all()
    assign_list = []
    for a in assignments:
        assign_list.append({
            "id": a.id, "projectId": a.project_id, "name": a.name, "status": a.status, "img": a.img, "mandays": a.mandays,
            "levels": json.loads(a.levels) if a.levels else [], "currentLevelIndex": a.current_level_index,
            "activeStages": json.loads(a.active_stages) if a.active_stages else [],
            "stageAssignees": json.loads(a.stage_assignees) if a.stage_assignees else {},
            "completedLevels": json.loads(a.completed_levels) if a.completed_levels else [],
            "versions": json.loads(a.versions) if a.versions else [],
            "inputData": json.loads(a.input_data) if a.input_data else None,
            "assignedTo": a.assigned_to,
            "createdAt": a.created_at,
            "accumulatedTime": a.accumulated_time or 0.0,
            "orderIndex": a.order_index
        })
    return jsonify({"success": True, "assignments": assign_list})

@app.route('/api/assignments', methods=['POST'])
@login_required
def add_assignment():
    data = request.get_json()
    new_assignment = Assignment(
        id=data.get('id'), project_id=data.get('projectId'), name=data.get('name'), status=data.get('status', 'paused'),
        img=data.get('img'), mandays=data.get('mandays', 0), levels=json.dumps(data.get('levels', [])),
        current_level_index=data.get('currentLevelIndex', 0),
        active_stages=json.dumps(data.get('activeStages', [])),
        stage_assignees=json.dumps(data.get('stageAssignees', {})),
        completed_levels=json.dumps(data.get('completedLevels', [])),
        versions=json.dumps(data.get('versions', [])), input_data=json.dumps(data.get('inputData', {})),
        assigned_to=data.get('assignedTo'), created_at=data.get('createdAt'),
        accumulated_time=data.get('accumulatedTime', 0.0),
        order_index=data.get('orderIndex')
    )
    db.session.add(new_assignment)
    db.session.commit()
    mark_db_updated()
    return jsonify({"success": True})

@app.route('/api/assignments/<assign_id>', methods=['PUT'])
@login_required
def update_assignment(assign_id):
    data = request.get_json()
    assignment = Assignment.query.get(assign_id)
    if assignment:
        fields = ['status', 'currentLevelIndex', 'assignedTo', 'createdAt', 'accumulatedTime', 'orderIndex']
        for field in fields:
            if field in data:
                db_field = field.replace('currentLevelIndex', 'current_level_index').replace('assignedTo', 'assigned_to').replace('createdAt', 'created_at').replace('accumulatedTime', 'accumulated_time').replace('orderIndex', 'order_index')
                setattr(assignment, db_field, data[field])

        if 'completedLevels' in data: assignment.completed_levels = json.dumps(data['completedLevels'])
        if 'versions' in data: assignment.versions = json.dumps(data['versions'])
        if 'inputData' in data: assignment.input_data = json.dumps(data['inputData'])
        if 'activeStages' in data: assignment.active_stages = json.dumps(data['activeStages'])
        if 'stageAssignees' in data: assignment.stage_assignees = json.dumps(data['stageAssignees'])
        if 'levels' in data: assignment.levels = json.dumps(data['levels'])

        db.session.commit()
        mark_db_updated()
        return jsonify({"success": True})
    return jsonify({"success": False}), 404

@app.route('/api/assignments/<assign_id>', methods=['DELETE'])
@login_required
def delete_assignment(assign_id):
    assignment = Assignment.query.get(assign_id)
    if assignment:
        project = Project.query.get(assignment.project_id)
        if project:
            proj_name = secure_filename(project.name)
            assign_name = secure_filename(assignment.name)
            folder_path = os.path.join(app.config['UPLOAD_FOLDER'], proj_name, assign_name)
            if os.path.exists(folder_path): shutil.rmtree(folder_path, ignore_errors=True)
        db.session.delete(assignment)
        db.session.commit()
        mark_db_updated()
        return jsonify({"success": True})
    return jsonify({"success": False}), 404

@app.route('/api/invoices', methods=['GET'])
@login_required
def get_invoices():
    invoices = Invoice.query.all()
    inv_list = []
    for i in invoices:
        inv_list.append({
            "id": i.id, "roleType": i.roleType, "targetUserId": i.targetUserId,
            "paymentType": i.paymentType, "projectId": i.projectId,
            "assignmentId": i.assignmentId, "stage": i.stage,
            "issueDate": i.issueDate, "dueDate": i.dueDate, "description": i.description,
            "amount": i.amount, "status": i.status, "createdAt": i.created_at
        })
    return jsonify({"success": True, "invoices": inv_list})

@app.route('/api/invoices', methods=['POST'])
@login_required
def add_invoice():
    data = request.get_json()
    new_inv = Invoice(
        id=data.get('id'), roleType=data.get('roleType'), targetUserId=data.get('targetUserId'),
        paymentType=data.get('paymentType'), projectId=data.get('projectId'),
        assignmentId=data.get('assignmentId'), stage=data.get('stage'),
        issueDate=data.get('issueDate'), dueDate=data.get('dueDate'), description=data.get('description'),
        amount=data.get('amount', 0.0), status=data.get('status', 'pending'),
        created_at=data.get('createdAt')
    )
    db.session.add(new_inv)
    db.session.commit()
    mark_db_updated()
    return jsonify({"success": True})

@app.route('/api/invoices/<inv_id>', methods=['PUT'])
@login_required
def update_invoice(inv_id):
    data = request.get_json()
    inv = Invoice.query.get(inv_id)
    if inv:
        if 'status' in data: inv.status = data['status']
        if 'amount' in data: inv.amount = float(data['amount'])
        db.session.commit()
        mark_db_updated()
        return jsonify({"success": True})
    return jsonify({"success": False}), 404

@app.route('/api/invoices/<inv_id>', methods=['DELETE'])
@login_required
def delete_invoice(inv_id):
    inv = Invoice.query.get(inv_id)
    if inv:
        db.session.delete(inv)
        db.session.commit()
        mark_db_updated()
        return jsonify({"success": True})
    return jsonify({"success": False}), 404

@app.route('/api/file', methods=['DELETE'])
@login_required
def delete_single_file():
    data = request.get_json()
    file_url = data.get('fileUrl')

    if file_url and file_url.startswith('/static/uploads/'):
        relative_path = file_url.lstrip('/')
        file_path = os.path.abspath(os.path.join(BASE_DIR, relative_path))
        if file_path.startswith(os.path.abspath(app.config['UPLOAD_FOLDER'])):
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                    mark_db_updated()
                except Exception:
                    pass
        else:
            return jsonify({"success": False, "message": "Invalid path traversal detected"}), 400

    return jsonify({"success": True})

@app.route('/api/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files: return jsonify({"success": False, "message": "No file part"}), 400
    file = request.files['file']
    if file.filename == '': return jsonify({"success": False, "message": "No selected file"}), 400

    if file:
        project_name = secure_filename(request.form.get('projectName', 'Misc'))
        assignment_name = secure_filename(request.form.get('assignmentName', 'Misc'))
        folder_type = secure_filename(request.form.get('folderType', 'General'))
        custom_file_name = request.form.get('customFileName')

        filename_to_save = secure_filename(custom_file_name) if custom_file_name else f"{int(time.time())}_{secure_filename(file.filename)}"

        dynamic_folder = os.path.join(app.config['UPLOAD_FOLDER'], project_name, assignment_name, folder_type)
        os.makedirs(dynamic_folder, exist_ok=True)

        filepath = os.path.join(dynamic_folder, filename_to_save)
        file.save(filepath)

        url_folder = f"static/uploads/{project_name}/{assignment_name}/{folder_type}"
        file_url = f"/{url_folder}/{filename_to_save}"

        thumbnail_url = None
        if 'thumbnail' in request.files:
            thumb_file = request.files['thumbnail']
            if thumb_file and thumb_file.filename != '':
                thumb_filename = filename_to_save.rsplit('.', 1)[0] + "_thumb" + os.path.splitext(thumb_file.filename)[1]
                thumb_filepath = os.path.join(dynamic_folder, thumb_filename)
                thumb_file.save(thumb_filepath)
                thumbnail_url = f"/{url_folder}/{thumb_filename}"

        if not thumbnail_url and filename_to_save.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.webp')):
             thumbnail_url = file_url

        mark_db_updated()
        return jsonify({"success": True, "fileUrl": file_url, "filename": filename_to_save, "thumbnailUrl": thumbnail_url})

if __name__ == '__main__':
    app.run(debug=True)