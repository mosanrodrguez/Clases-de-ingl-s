#!/usr/bin/env python3
"""
servidor de clases de inglés - versión 5.0
estructura mejorada con archivos separados para estudiante y profesor
"""

import os
import psycopg2
import json
import hashlib
import secrets
import jwt
import datetime
from psycopg2.extras import realdictcursor
from typing import dict, optional
from functools import wraps

from flask import flask, request, jsonify, send_file, send_from_directory
from flask_cors import cors
from werkzeug.utils import secure_filename
from flask_socketio import socketio, emit
import cloudinary
import cloudinary.uploader

# ============ configuración ============
app = flask(__name__, static_folder='.', static_url_path='')
cors(app, resources={r"/*": {"origins": "*"}})

app.config['secret_key'] = os.environ.get('secret_key', secrets.token_hex(32))
app.config['max_content_length'] = 50 * 1024 * 1024  # 50mb

# base de datos
database_url = "postgresql://englishcourse_user:vi8pyttx2bbv2yftidvhoukxtk6j7ehd@dpg-d64mmungi27c73b53hr0-a/englishcourse"

# cloudinary
cloudinary.config(
    cloud_name="dj72b0ykc",
    api_key="215156196366932",
    api_secret="ivdpe_mkt3rsx5asfto6qjdwalq",
    secure=true
)

# códigos de acceso
student_code = "qwerty89"
teacher_code = "moisés5m"

# extensiones permitidas
allowed_extensions = {
    'pdf', 'doc', 'docx', 'ppt', 'pptx', 
    'txt', 'jpg', 'jpeg', 'png', 'gif',
    'mp3', 'mp4', 'mov', 'avi', 'webm'
}

socketio = socketio(app, cors_allowed_origins="*", ping_timeout=60, ping_interval=25)

# ============ funciones auxiliares ============
def allowed_file(filename: str) -> bool:
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in allowed_extensions

def get_file_type(filename: str) -> str:
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    file_types = {
        'pdf': 'pdf', 'doc': 'word', 'docx': 'word',
        'ppt': 'powerpoint', 'pptx': 'powerpoint',
        'txt': 'texto', 'jpg': 'imagen', 'jpeg': 'imagen',
        'png': 'imagen', 'gif': 'gif', 'mp3': 'audio',
        'mp4': 'video', 'mov': 'video', 'avi': 'video',
        'webm': 'video'
    }
    return file_types.get(ext, 'archivo')

def get_db_connection():
    return psycopg2.connect(database_url, cursor_factory=realdictcursor)

def init_db():
    """inicializar base de datos"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # tabla de usuarios
        cursor.execute('''
            create table if not exists users (
                id serial primary key,
                username varchar(100) unique not null,
                password_hash varchar(255) not null,
                name varchar(200) not null,
                role varchar(20) not null check(role in ('student', 'teacher')),
                level varchar(50) default 'sin asignar',
                registration_date timestamp default current_timestamp,
                last_login timestamp,
                is_active boolean default true
            )
        ''')
        
        # tabla de clases
        cursor.execute('''
            create table if not exists classes (
                id serial primary key,
                title varchar(255) not null,
                description text not null,
                level varchar(10) not null check(level in ('a1', 'a2', 'b1')),
                file_name varchar(255),
                file_url text,
                file_type varchar(50),
                file_size integer,
                uploaded_by integer not null,
                created_at timestamp default current_timestamp,
                is_active boolean default true,
                foreign key (uploaded_by) references users (id) on delete cascade
            )
        ''')
        
        # tabla de acceso estudiante-clase
        cursor.execute('''
            create table if not exists student_access (
                id serial primary key,
                student_id integer not null,
                class_id integer not null,
                has_access boolean default false,
                downloaded boolean default false,
                downloaded_at timestamp,
                granted_by integer,
                granted_at timestamp default current_timestamp,
                foreign key (student_id) references users (id) on delete cascade,
                foreign key (class_id) references classes (id) on delete cascade,
                foreign key (granted_by) references users (id) on delete set null,
                unique(student_id, class_id)
            )
        ''')
        
        # tabla de descargas
        cursor.execute('''
            create table if not exists downloads (
                id serial primary key,
                user_id integer not null,
                class_id integer not null,
                downloaded_at timestamp default current_timestamp,
                foreign key (user_id) references users (id) on delete cascade,
                foreign key (class_id) references classes (id) on delete cascade
            )
        ''')
        
        # tabla de publicaciones
        cursor.execute('''
            create table if not exists publications (
                id serial primary key,
                title varchar(255) not null,
                content text,
                publication_type varchar(20) not null check(publication_type in ('text', 'photo', 'video', 'document')),
                file_url text,
                file_name varchar(255),
                file_type varchar(50),
                created_by integer not null,
                created_at timestamp default current_timestamp,
                is_active boolean default true,
                foreign key (created_by) references users (id) on delete cascade
            )
        ''')
        
        # tabla de reacciones (likes)
        cursor.execute('''
            create table if not exists publication_reactions (
                id serial primary key,
                user_id integer not null,
                publication_id integer not null,
                reacted_at timestamp default current_timestamp,
                foreign key (user_id) references users (id) on delete cascade,
                foreign key (publication_id) references publications (id) on delete cascade,
                unique(user_id, publication_id)
            )
        ''')
        
        # tabla de vistas de publicaciones
        cursor.execute('''
            create table if not exists publication_views (
                id serial primary key,
                user_id integer not null,
                publication_id integer not null,
                viewed_at timestamp default current_timestamp,
                foreign key (user_id) references users (id) on delete cascade,
                foreign key (publication_id) references publications (id) on delete cascade,
                unique(user_id, publication_id)
            )
        ''')
        
        conn.commit()
        print("✅ base de datos configurada")
        
        # crear profesor por defecto si no existe
        cursor.execute("select id from users where role = 'teacher' limit 1")
        if not cursor.fetchone():
            password_hash = hash_password("admin123")
            cursor.execute('''
                insert into users (username, password_hash, name, role, level)
                values (%s, %s, %s, %s, %s)
            ''', ('profesor', password_hash, 'profesor moisés', 'teacher', none))
            conn.commit()
            print("✅ profesor por defecto: usuario='profesor', password='admin123'")
        
    except exception as e:
        print(f"⚠️ error: {str(e)}")
        conn.rollback()
    finally:
        cursor.close()
        conn.close()

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password: str, password_hash: str) -> bool:
    return hash_password(password) == password_hash

def generate_token(user_id: int, username: str, role: str) -> str:
    payload = {
        'user_id': user_id,
        'username': username,
        'role': role,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7)
    }
    return jwt.encode(payload, app.config['secret_key'], algorithm='hs256')

def verify_token(token: str) -> optional[dict]:
    try:
        return jwt.decode(token, app.config['secret_key'], algorithms=['hs256'])
    except:
        return none

# ============ decoradores ============
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = none
        auth_header = request.headers.get('authorization')
        
        if auth_header and auth_header.startswith('bearer '):
            token = auth_header.split(' ')[1]
        
        if not token:
            return jsonify({'error': 'token requerido'}), 401
        
        payload = verify_token(token)
        if not payload:
            return jsonify({'error': 'token inválido'}), 401
        
        request.user_id = payload['user_id']
        request.username = payload['username']
        request.user_role = payload['role']
        
        return f(*args, **kwargs)
    return decorated

def teacher_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not hasattr(request, 'user_role') or request.user_role != 'teacher':
            return jsonify({'error': 'acceso denegado'}), 403
        return f(*args, **kwargs)
    return decorated

# ============ rutas principales ============
@app.route('/')
def index():
    return send_file('auth.html')

@app.route('/auth.html')
def auth_page():
    return send_file('auth.html')

@app.route('/estudiante.html')
def estudiante_page():
    return send_file('estudiante.html')

@app.route('/profesor.html')
def profesor_page():
    return send_file('profesor.html')

# ============ autenticación ============
@app.route('/api/register', methods=['post'])
def register():
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'datos inválidos'}), 400
        
        required_fields = ['name', 'username', 'password', 'code']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'campo {field} requerido'}), 400
        
        code = data['code']
        if code not in [student_code, teacher_code]:
            return jsonify({'error': 'código incorrecto'}), 400
        
        role = 'teacher' if code == teacher_code else 'student'
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('select id from users where username = %s', (data['username'],))
        if cursor.fetchone():
            cursor.close()
            conn.close()
            return jsonify({'error': 'usuario ya existe'}), 400
        
        password_hash = hash_password(data['password'])
        
        cursor.execute('''
            insert into users (username, password_hash, name, role, level)
            values (%s, %s, %s, %s, %s) returning id, username, name, role, level, registration_date
        ''', (
            data['username'],
            password_hash,
            data['name'],
            role,
            'sin asignar' if role == 'student' else none
        ))
        
        user = cursor.fetchone()
        conn.commit()
        
        token = generate_token(user['id'], user['username'], user['role'])
        
        cursor.close()
        conn.close()
        
        return jsonify({
            'message': 'registro exitoso',
            'user': dict(user),
            'token': token
        }), 201
        
    except exception as e:
        print(f"❌ error: {str(e)}")
        return jsonify({'error': 'error interno'}), 500

@app.route('/api/login', methods=['post'])
def login():
    try:
        data = request.get_json()
        
        if not data or not data.get('username') or not data.get('password'):
            return jsonify({'error': 'usuario y contraseña requeridos'}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('select * from users where username = %s', (data['username'],))
        user_row = cursor.fetchone()
        
        if not user_row:
            cursor.close()
            conn.close()
            return jsonify({'error': 'credenciales incorrectas'}), 401
        
        user = dict(user_row)
        
        if not verify_password(data['password'], user['password_hash']):
            cursor.close()
            conn.close()
            return jsonify({'error': 'credenciales incorrectas'}), 401
        
        cursor.execute('update users set last_login = current_timestamp where id = %s', (user['id'],))
        conn.commit()
        
        del user['password_hash']
        
        token = generate_token(user['id'], user['username'], user['role'])
        
        cursor.close()
        conn.close()
        
        # redirigir según el rol
        redirect_url = 'profesor.html' if user['role'] == 'teacher' else 'estudiante.html'
        
        return jsonify({
            'message': 'login exitoso',
            'user': user,
            'token': token,
            'redirect': redirect_url
        }), 200
        
    except exception as e:
        print(f"❌ error: {str(e)}")
        return jsonify({'error': 'error interno'}), 500

# ============ publicaciones ============
@app.route('/api/publications', methods=['get'])
@token_required
def get_publications():
    try:
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 20))
        offset = (page - 1) * limit
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # marcar automáticamente como vista
        cursor.execute('''
            insert into publication_views (user_id, publication_id)
            select %s, id from publications p
            where p.is_active = true
            and not exists (
                select 1 from publication_views pv 
                where pv.publication_id = p.id and pv.user_id = %s
            )
        ''', (request.user_id, request.user_id))
        conn.commit()
        
        # obtener publicaciones
        cursor.execute('''
            select p.*, u.name as author_name,
                   (select count(*) from publication_reactions pr where pr.publication_id = p.id) as likes_count,
                   (select count(*) from publication_views pv where pv.publication_id = p.id) as views_count,
                   exists(select 1 from publication_reactions pr where pr.publication_id = p.id and pr.user_id = %s) as user_liked
            from publications p
            join users u on p.created_by = u.id
            where p.is_active = true
            order by p.created_at desc
            limit %s offset %s
        ''', (request.user_id, limit, offset))
        
        publications = []
        for row in cursor.fetchall():
            publications.append(dict(row))
        
        cursor.close()
        conn.close()
        
        return jsonify(publications), 200
        
    except exception as e:
        print(f"❌ error: {str(e)}")
        return jsonify({'error': 'error obteniendo publicaciones'}), 500

@app.route('/api/publications/<int:publication_id>/like', methods=['post'])
@token_required
def toggle_like(publication_id: int):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # verificar si ya dio like
        cursor.execute('''
            select id from publication_reactions 
            where user_id = %s and publication_id = %s
        ''', (request.user_id, publication_id))
        
        existing = cursor.fetchone()
        
        if existing:
            # quitar like
            cursor.execute('''
                delete from publication_reactions 
                where user_id = %s and publication_id = %s
            ''', (request.user_id, publication_id))
            liked = false
        else:
            # dar like
            cursor.execute('''
                insert into publication_reactions (user_id, publication_id)
                values (%s, %s)
            ''', (request.user_id, publication_id))
            liked = true
        
        conn.commit()
        
        # obtener nuevo conteo
        cursor.execute('''
            select count(*) as count from publication_reactions 
            where publication_id = %s
        ''', (publication_id,))
        count = cursor.fetchone()['count']
        
        cursor.close()
        conn.close()
        
        # emitir evento en tiempo real
        socketio.emit('like_updated', {
            'publication_id': publication_id,
            'likes_count': count,
            'user_id': request.user_id,
            'liked': liked
        })
        
        return jsonify({
            'liked': liked,
            'likes_count': count
        }), 200
        
    except exception as e:
        print(f"❌ error: {str(e)}")
        return jsonify({'error': 'error'}), 500

@app.route('/api/publications', methods=['post'])
@token_required
@teacher_required
def create_publication():
    try:
        publication_type = request.form.get('type', 'text')
        
        if publication_type not in ['text', 'photo', 'video', 'document']:
            return jsonify({'error': 'tipo no válido'}), 400
        
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        
        if not title:
            return jsonify({'error': 'título requerido'}), 400
        
        if publication_type == 'text' and not content:
            return jsonify({'error': 'contenido requerido'}), 400
        
        file_url = none
        file_name = none
        file_type = none
        
        if publication_type in ['photo', 'video', 'document']:
            if 'file' not in request.files:
                return jsonify({'error': 'archivo requerido'}), 400
            
            file = request.files['file']
            
            if file.filename == '':
                return jsonify({'error': 'archivo vacío'}), 400
            
            if not allowed_file(file.filename):
                return jsonify({'error': 'tipo no permitido'}), 400
            
            resource_type = 'auto'
            if publication_type == 'video':
                resource_type = 'video'
            elif publication_type == 'photo':
                resource_type = 'image'
            
            upload_result = cloudinary.uploader.upload(
                file,
                folder="publicaciones",
                resource_type=resource_type,
                use_filename=true,
                unique_filename=true
            )
            
            file_url = upload_result['secure_url']
            file_name = secure_filename(file.filename)
            file_type = get_file_type(file.filename)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('select name from users where id = %s', (request.user_id,))
        teacher = cursor.fetchone()
        teacher_name = teacher['name'] if teacher else 'profesor'
        
        cursor.execute('''
            insert into publications 
            (title, content, publication_type, file_url, file_name, file_type, created_by)
            values (%s, %s, %s, %s, %s, %s, %s)
            returning id, title, created_at
        ''', (
            title,
            content if publication_type == 'text' else '',
            publication_type,
            file_url,
            file_name,
            file_type,
            request.user_id
        ))
        
        new_publication = cursor.fetchone()
        conn.commit()
        cursor.close()
        conn.close()
        
        socketio.emit('new_publication', {
            'id': new_publication['id'],
            'title': title,
            'author_name': teacher_name,
            'created_at': new_publication['created_at'].isoformat()
        })
        
        return jsonify({
            'message': 'publicación creada',
            'publication': dict(new_publication)
        }), 201
        
    except exception as e:
        print(f"❌ error: {str(e)}")
        return jsonify({'error': 'error'}), 500

@app.route('/api/publications/<int:publication_id>', methods=['delete'])
@token_required
@teacher_required
def delete_publication(publication_id: int):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('update publications set is_active = false where id = %s', (publication_id,))
        conn.commit()
        
        cursor.close()
        conn.close()
        
        return jsonify({'message': 'publicación eliminada'}), 200
        
    except exception as e:
        print(f"❌ error: {str(e)}")
        return jsonify({'error': 'error'}), 500

# ============ clases ============
@app.route('/api/classes', methods=['get'])
@token_required
def get_classes():
    try:
        level = request.args.get('level')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if request.user_role == 'teacher':
            # profesor: ve todas las clases con filtro opcional
            if level:
                cursor.execute('''
                    select c.*, u.name as uploaded_by_name 
                    from classes c 
                    join users u on c.uploaded_by = u.id 
                    where c.level = %s and c.is_active = true
                    order by c.created_at desc
                ''', (level,))
            else:
                cursor.execute('''
                    select c.*, u.name as uploaded_by_name 
                    from classes c 
                    join users u on c.uploaded_by = u.id 
                    where c.is_active = true
                    order by c.created_at desc
                ''')
        else:
            # estudiante: solo ve clases de su nivel con acceso
            cursor.execute('''
                select c.*, u.name as uploaded_by_name, 
                       sa.has_access, sa.downloaded
                from classes c 
                join users u on c.uploaded_by = u.id 
                left join student_access sa on c.id = sa.class_id and sa.student_id = %s
                where c.level = %s and c.is_active = true and sa.has_access = true
                order by c.created_at desc
            ''', (request.user_id, level))
        
        classes = []
        for row in cursor.fetchall():
            classes.append(dict(row))
        
        cursor.close()
        conn.close()
        
        return jsonify(classes), 200
        
    except exception as e:
        print(f"❌ error: {str(e)}")
        return jsonify({'error': 'error'}), 500

@app.route('/api/classes', methods=['post'])
@token_required
@teacher_required
def upload_class():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'archivo requerido'}), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({'error': 'archivo vacío'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': 'tipo no permitido'}), 400
        
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        level = request.form.get('level', '').strip()
        
        if not title or not description or not level:
            return jsonify({'error': 'todos los campos requeridos'}), 400
        
        if level not in ['a1', 'a2', 'b1']:
            return jsonify({'error': 'nivel no válido'}), 400
        
        upload_result = cloudinary.uploader.upload(
            file,
            folder="clases_ingles",
            resource_type="auto",
            use_filename=true,
            unique_filename=true
        )
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            insert into classes 
            (title, description, level, file_name, file_url, file_type, file_size, uploaded_by)
            values (%s, %s, %s, %s, %s, %s, %s, %s)
            returning id, title, level, created_at
        ''', (
            title,
            description,
            level,
            secure_filename(file.filename),
            upload_result['secure_url'],
            get_file_type(file.filename),
            upload_result.get('bytes', 0),
            request.user_id
        ))
        
        new_class = cursor.fetchone()
        conn.commit()
        cursor.close()
        conn.close()
        
        socketio.emit('new_class', {
            'id': new_class['id'],
            'title': title,
            'level': level,
            'created_at': new_class['created_at'].isoformat()
        })
        
        return jsonify({
            'message': 'clase subida',
            'class': dict(new_class)
        }), 201
        
    except exception as e:
        print(f"❌ error: {str(e)}")
        return jsonify({'error': 'error'}), 500

@app.route('/api/classes/<int:class_id>', methods=['put'])
@token_required
@teacher_required
def update_class(class_id: int):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('select * from classes where id = %s', (class_id,))
        if not cursor.fetchone():
            cursor.close()
            conn.close()
            return jsonify({'error': 'clase no encontrada'}), 404
        
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        level = request.form.get('level', '').strip()
        file = request.files.get('file')
        
        if not title or not description or not level:
            return jsonify({'error': 'campos requeridos'}), 400
        
        if level not in ['a1', 'a2', 'b1']:
            return jsonify({'error': 'nivel no válido'}), 400
        
        update_fields = {
            'title': title,
            'description': description,
            'level': level
        }
        
        if file and file.filename != '':
            if not allowed_file(file.filename):
                return jsonify({'error': 'tipo no permitido'}), 400
            
            upload_result = cloudinary.uploader.upload(
                file,
                folder="clases_ingles",
                resource_type="auto",
                use_filename=true,
                unique_filename=true
            )
            
            update_fields.update({
                'file_url': upload_result['secure_url'],
                'file_name': secure_filename(file.filename),
                'file_type': get_file_type(file.filename),
                'file_size': upload_result.get('bytes', 0)
            })
        
        set_clause = ', '.join([f"{k} = %s" for k in update_fields.keys()])
        values = list(update_fields.values())
        values.append(class_id)
        
        cursor.execute(f'''
            update classes 
            set {set_clause}
            where id = %s
        ''', values)
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({'message': 'clase actualizada'}), 200
        
    except exception as e:
        print(f"❌ error: {str(e)}")
        return jsonify({'error': 'error'}), 500

@app.route('/api/classes/<int:class_id>', methods=['delete'])
@token_required
@teacher_required
def delete_class(class_id: int):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('update classes set is_active = false where id = %s', (class_id,))
        conn.commit()
        
        cursor.close()
        conn.close()
        
        return jsonify({'message': 'clase eliminada'}), 200
        
    except exception as e:
        print(f"❌ error: {str(e)}")
        return jsonify({'error': 'error'}), 500

@app.route('/api/classes/<int:class_id>/download', methods=['get'])
@token_required
def download_class(class_id: int):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if request.user_role == 'student':
            cursor.execute('''
                select sa.has_access from student_access sa 
                where sa.student_id = %s and sa.class_id = %s and sa.has_access = true
            ''', (request.user_id, class_id))
            
            if not cursor.fetchone():
                cursor.close()
                conn.close()
                return jsonify({'error': 'sin acceso'}), 403
        
        cursor.execute('select * from classes where id = %s and is_active = true', (class_id,))
        class_data = cursor.fetchone()
        
        if not class_data:
            cursor.close()
            conn.close()
            return jsonify({'error': 'clase no encontrada'}), 404
        
        cursor.execute('insert into downloads (user_id, class_id) values (%s, %s)', 
                      (request.user_id, class_id))
        
        if request.user_role == 'student':
            cursor.execute('''
                update student_access 
                set downloaded = true, downloaded_at = current_timestamp
                where student_id = %s and class_id = %s
            ''', (request.user_id, class_id))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({
            'download_url': class_data['file_url']
        }), 200
        
    except exception as e:
        print(f"❌ error: {str(e)}")
        return jsonify({'error': 'error'}), 500

# ============ estudiantes (profesor) ============
@app.route('/api/students', methods=['get'])
@token_required
@teacher_required
def get_students():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            select u.id, u.username, u.name, u.level, u.registration_date
            from users u 
            where u.role = 'student' and u.is_active = true
            order by u.name
        ''')
        
        students = []
        for row in cursor.fetchall():
            students.append(dict(row))
        
        cursor.close()
        conn.close()
        
        return jsonify(students), 200
        
    except exception as e:
        print(f"❌ error: {str(e)}")
        return jsonify({'error': 'error'}), 500

@app.route('/api/students/<int:student_id>/level', methods=['put'])
@token_required
@teacher_required
def update_student_level(student_id: int):
    try:
        data = request.get_json()
        
        if not data or 'level' not in data:
            return jsonify({'error': 'nivel requerido'}), 400
        
        level = data['level'].strip()
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            update users 
            set level = %s 
            where id = %s and role = 'student'
            returning id, username, name, level
        ''', (level, student_id))
        
        updated = cursor.fetchone()
        conn.commit()
        cursor.close()
        conn.close()
        
        if not updated:
            return jsonify({'error': 'estudiante no encontrado'}), 404
        
        socketio.emit('student_level_updated', {
            'student_id': student_id,
            'level': level
        })
        
        return jsonify({
            'message': 'nivel actualizado',
            'student': dict(updated)
        }), 200
        
    except exception as e:
        print(f"❌ error: {str(e)}")
        return jsonify({'error': 'error'}), 500

@app.route('/api/students/<int:student_id>/access', methods=['get'])
@token_required
@teacher_required
def get_student_access(student_id: int):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            select c.*, sa.has_access, sa.downloaded
            from classes c
            left join student_access sa on c.id = sa.class_id and sa.student_id = %s
            where c.is_active = true
            order by c.level, c.created_at desc
        ''', (student_id,))
        
        classes = []
        for row in cursor.fetchall():
            classes.append(dict(row))
        
        cursor.close()
        conn.close()
        
        return jsonify(classes), 200
        
    except exception as e:
        print(f"❌ error: {str(e)}")
        return jsonify({'error': 'error'}), 500

@app.route('/api/students/<int:student_id>/access', methods=['post'])
@token_required
@teacher_required
def update_student_access(student_id: int):
    try:
        data = request.get_json()
        
        if not data or 'class_id' not in data or 'has_access' not in data:
            return jsonify({'error': 'datos incompletos'}), 400
        
        class_id = data['class_id']
        has_access = data['has_access']
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            insert into student_access (student_id, class_id, has_access, granted_by)
            values (%s, %s, %s, %s)
            on conflict (student_id, class_id) 
            do update set has_access = %s, granted_by = %s, granted_at = current_timestamp
        ''', (student_id, class_id, has_access, request.user_id,
              has_access, request.user_id))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({'message': 'acceso actualizado'}), 200
        
    except exception as e:
        print(f"❌ error: {str(e)}")
        return jsonify({'error': 'error'}), 500

# ============ perfil ============
@app.route('/api/profile', methods=['get'])
@token_required
def get_profile():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            select id, username, name, role, level, registration_date
            from users where id = %s
        ''', (request.user_id,))
        
        user = cursor.fetchone()
        
        if not user:
            cursor.close()
            conn.close()
            return jsonify({'error': 'usuario no encontrado'}), 404
        
        profile = dict(user)
        
        cursor.close()
        conn.close()
        
        return jsonify(profile), 200
        
    except exception as e:
        print(f"❌ error: {str(e)}")
        return jsonify({'error': 'error'}), 500

# ============ websocket ============
@socketio.on('connect')
def handle_connect():
    emit('connected', {'message': 'conectado'})

# ============ inicialización ============
if __name__ == '__main__':
    print("=" * 60)
    print("🚀 servidor de clases de inglés - v5.0")
    print("=" * 60)
    
    init_db()
    
    print(f"🔑 código estudiante: {student_code}")
    print(f"👨‍🏫 código profesor: {teacher_code}")
    print("=" * 60)
    
    port = int(os.environ.get('port', 5000))
    
    socketio.run(
        app, 
        host='0.0.0.0', 
        port=port, 
        debug=false,
        allow_unsafe_werkzeug=true
    )