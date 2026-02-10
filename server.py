#!/usr/bin/env python3
"""
SERVIDOR DE CLASES DE INGLÉS - VERSIÓN 3.0
Sistema de publicaciones y acceso controlado
Con migración automática de base de datos
"""

import os
import psycopg2
import json
import hashlib
import secrets
import jwt
import datetime
from psycopg2.extras import RealDictCursor
from typing import Dict, Optional
from functools import wraps

from flask import Flask, request, jsonify, send_file, send_from_directory
from flask_cors import CORS
from werkzeug.utils import secure_filename
from flask_socketio import SocketIO, emit
import cloudinary
import cloudinary.uploader

# ============ CONFIGURACIÓN ============
app = Flask(__name__, static_folder='.', static_url_path='')
CORS(app, resources={r"/*": {"origins": "*"}})

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB

DATABASE_URL = "postgresql://englishcourse_m885_user:R1mTk8YrWgaPyDRAV7fVFVAWm24QvjRa@dpg-d65malesb7us73btl8ag-a/englishcourse_m885"

cloudinary.config(
    cloud_name="dj72b0ykc",
    api_key="215156196366932",
    api_secret="Ivdpe_mkT3rSx5asFTo6qJdWaLQ",
    secure=True
)

STUDENT_CODE = "QwErTy89"
TEACHER_CODE = "MOISÉS5M"

ALLOWED_EXTENSIONS = {
    'pdf', 'doc', 'docx', 'ppt', 'pptx', 
    'txt', 'jpg', 'jpeg', 'png', 'mp3', 'mp4'
}

socketio = SocketIO(app, cors_allowed_origins="*")

# ============ FUNCIONES AUXILIARES ============
def allowed_file(filename: str) -> bool:
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_file_type(filename: str) -> str:
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    file_types = {
        'pdf': 'PDF', 'doc': 'Word', 'docx': 'Word',
        'ppt': 'PowerPoint', 'pptx': 'PowerPoint',
        'txt': 'Texto', 'jpg': 'Imagen', 'jpeg': 'Imagen',
        'png': 'Imagen', 'mp3': 'Audio', 'mp4': 'Video'
    }
    return file_types.get(ext, 'Archivo')

def get_db_connection():
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
    return conn

# ============ MIGRACIÓN AUTOMÁTICA ============
def auto_migrate_database():
    """Migrar automáticamente la base de datos al nuevo esquema"""
    print("🔄 Iniciando migración automática de base de datos...")
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # 1. Verificar y migrar tabla users
        print("📋 Verificando tabla users...")
        cursor.execute("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'users'
        """)
        
        existing_columns = [row['column_name'] for row in cursor.fetchall()]
        
        if existing_columns:
            print(f"🔍 Tabla users encontrada con columnas: {existing_columns}")
            
            # Verificar si faltan columnas nuevas
            required_columns = ['level', 'is_active', 'registration_date', 'last_login']
            missing_columns = [col for col in required_columns if col not in existing_columns]
            
            if missing_columns:
                print(f"⚠️  Faltan columnas: {missing_columns}")
                print("🔄 Agregando columnas faltantes...")
                
                if 'level' not in existing_columns:
                    cursor.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS level VARCHAR(50) DEFAULT 'Sin asignar'")
                    print("✅ Columna 'level' agregada")
                
                if 'is_active' not in existing_columns:
                    cursor.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT TRUE")
                    print("✅ Columna 'is_active' agregada")
                
                if 'registration_date' not in existing_columns:
                    cursor.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS registration_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
                    print("✅ Columna 'registration_date' agregada")
                
                if 'last_login' not in existing_columns:
                    cursor.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login TIMESTAMP")
                    print("✅ Columna 'last_login' agregada")
                
                conn.commit()
        
        # 2. Crear tablas nuevas si no existen
        print("🆕 Creando tablas nuevas...")
        
        # Tabla classes
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS classes (
                id SERIAL PRIMARY KEY,
                title VARCHAR(255) NOT NULL,
                description TEXT NOT NULL,
                level VARCHAR(10) NOT NULL CHECK(level IN ('A1', 'A2', 'B1')),
                file_name VARCHAR(255),
                file_url TEXT,
                file_type VARCHAR(50),
                file_size INTEGER,
                uploaded_by INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE
            )
        ''')
        print("✅ Tabla 'classes' verificada/creada")
        
        # Verificar constraint de uploaded_by
        cursor.execute("""
            DO $$ 
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.table_constraints 
                    WHERE table_name = 'classes' 
                    AND constraint_name = 'classes_uploaded_by_fkey'
                ) THEN
                    ALTER TABLE classes 
                    ADD CONSTRAINT classes_uploaded_by_fkey 
                    FOREIGN KEY (uploaded_by) REFERENCES users (id) ON DELETE CASCADE;
                END IF;
            END $$;
        """)
        
        # Tabla student_access
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS student_access (
                id SERIAL PRIMARY KEY,
                student_id INTEGER NOT NULL,
                class_id INTEGER NOT NULL,
                has_access BOOLEAN DEFAULT FALSE,
                downloaded BOOLEAN DEFAULT FALSE,
                downloaded_at TIMESTAMP,
                granted_by INTEGER,
                granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                notes TEXT,
                FOREIGN KEY (student_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (class_id) REFERENCES classes (id) ON DELETE CASCADE,
                FOREIGN KEY (granted_by) REFERENCES users (id) ON DELETE SET NULL,
                UNIQUE(student_id, class_id)
            )
        ''')
        print("✅ Tabla 'student_access' verificada/creada")
        
        # Tabla downloads
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS downloads (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                class_id INTEGER NOT NULL,
                downloaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (class_id) REFERENCES classes (id) ON DELETE CASCADE
            )
        ''')
        print("✅ Tabla 'downloads' verificada/creada")
        
        # Tabla publications
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS publications (
                id SERIAL PRIMARY KEY,
                title VARCHAR(255) NOT NULL,
                content TEXT,
                publication_type VARCHAR(20) NOT NULL CHECK(publication_type IN ('text', 'photo', 'video', 'document')),
                file_url TEXT,
                file_name VARCHAR(255),
                file_type VARCHAR(50),
                created_by INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE,
                FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')
        print("✅ Tabla 'publications' verificada/creada")
        
        # Tabla publication_views
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS publication_views (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                publication_id INTEGER NOT NULL,
                viewed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (publication_id) REFERENCES publications (id) ON DELETE CASCADE,
                UNIQUE(user_id, publication_id)
            )
        ''')
        print("✅ Tabla 'publication_views' verificada/creada")
        
        conn.commit()
        print("✅ Migración automática completada exitosamente")
        
        # 3. Intentar migrar datos de tablas antiguas si existen
        migrate_old_data()
        
    except Exception as e:
        print(f"⚠️  Error durante la migración automática: {str(e)}")
        print("ℹ️  Continuando con la estructura existente...")
        conn.rollback()
    finally:
        cursor.close()
        conn.close()

def migrate_old_data():
    """Migrar datos de tablas antiguas si existen"""
    print("📦 Buscando datos antiguos para migrar...")
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Verificar si existe tabla classes_old o similar
        cursor.execute("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_name IN ('classes_old', 'old_classes', 'content', 'materials')
            AND table_schema = 'public'
        """)
        
        old_tables = [row['table_name'] for row in cursor.fetchall()]
        
        for table in old_tables:
            print(f"🔍 Encontrada tabla antigua: {table}")
            
            # Verificar si tiene datos
            cursor.execute(f"SELECT COUNT(*) as count FROM {table}")
            count = cursor.fetchone()['count']
            
            if count > 0:
                print(f"📊 Migrando {count} registros desde {table}...")
                
                # Intentar insertar en nueva tabla classes
                cursor.execute(f"""
                    INSERT INTO classes (title, description, level, file_name, file_url, uploaded_by, created_at)
                    SELECT 
                        COALESCE(title, 'Sin título'),
                        COALESCE(description, 'Sin descripción'),
                        COALESCE(level, 'A1'),
                        file_name,
                        file_url,
                        COALESCE(uploaded_by, 1),
                        COALESCE(created_at, CURRENT_TIMESTAMP)
                    FROM {table}
                    WHERE NOT EXISTS (
                        SELECT 1 FROM classes c WHERE c.file_url = {table}.file_url
                    )
                """)
                
                migrated = cursor.rowcount
                conn.commit()
                print(f"✅ Migrados {migrated} registros desde {table}")
    
    except Exception as e:
        print(f"⚠️  Error migrando datos antiguos: {str(e)}")
        conn.rollback()
    finally:
        cursor.close()
        conn.close()

def init_db():
    """Inicializar la base de datos con migración automática"""
    print("🔧 Configurando base de datos...")
    try:
        # Primero intentar migración automática
        auto_migrate_database()
        
        # Luego verificar estructura básica
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Verificar que todas las tablas necesarias existan
        cursor.execute("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_name IN ('users', 'classes', 'student_access', 'downloads', 'publications', 'publication_views')
            AND table_schema = 'public'
        """)
        
        existing_tables = [row['table_name'] for row in cursor.fetchall()]
        required_tables = ['users', 'classes', 'student_access', 'downloads', 'publications', 'publication_views']
        
        missing_tables = [table for table in required_tables if table not in existing_tables]
        
        if missing_tables:
            print(f"⚠️  Tablas faltantes: {missing_tables}")
            print("🔄 Creando tablas faltantes...")
            
            # Crear tablas faltantes
            if 'users' not in existing_tables:
                cursor.execute('''
                    CREATE TABLE users (
                        id SERIAL PRIMARY KEY,
                        username VARCHAR(100) UNIQUE NOT NULL,
                        password_hash VARCHAR(255) NOT NULL,
                        name VARCHAR(200) NOT NULL,
                        role VARCHAR(20) NOT NULL CHECK(role IN ('student', 'teacher')),
                        level VARCHAR(50) DEFAULT 'Sin asignar',
                        registration_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_login TIMESTAMP,
                        is_active BOOLEAN DEFAULT TRUE
                    )
                ''')
                print("✅ Tabla 'users' creada")
            
            # Las otras tablas ya se crearon en auto_migrate_database
            conn.commit()
        
        print("✅ Base de datos configurada y verificada")
        
    except Exception as e:
        print(f"⚠️  Error al inicializar base de datos: {str(e)}")
        print("ℹ️  Continuando con la estructura existente...")
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
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
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def verify_token(token: str) -> Optional[Dict]:
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return payload
    except:
        return None

# ============ DECORADORES ============
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        
        if not token:
            return jsonify({'error': 'Token de autenticación requerido'}), 401
        
        payload = verify_token(token)
        if not payload:
            return jsonify({'error': 'Token inválido o expirado'}), 401
        
        request.user_id = payload['user_id']
        request.username = payload['username']
        request.user_role = payload['role']
        
        return f(*args, **kwargs)
    return decorated

def teacher_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not hasattr(request, 'user_role') or request.user_role != 'teacher':
            return jsonify({'error': 'Acceso denegado. Solo para profesores'}), 403
        return f(*args, **kwargs)
    return decorated

# ============ RUTAS API ============
@app.route('/')
def index():
    return send_file('auth.html')

# ============ AUTENTICACIÓN ============
@app.route('/api/register', methods=['POST'])
def register():
    """Registrar un nuevo usuario"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Datos JSON inválidos'}), 400
        
        required_fields = ['name', 'username', 'password', 'code']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'Campo {field} es requerido'}), 400
        
        code = data['code']
        if code not in [STUDENT_CODE, TEACHER_CODE]:
            return jsonify({'error': 'Código de acceso incorrecto'}), 400
        
        role = 'teacher' if code == TEACHER_CODE else 'student'
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT id FROM users WHERE username = %s', (data['username'],))
        if cursor.fetchone():
            cursor.close()
            conn.close()
            return jsonify({'error': 'El nombre de usuario ya existe'}), 400
        
        password_hash = hash_password(data['password'])
        
        cursor.execute('''
            INSERT INTO users (username, password_hash, name, role, level)
            VALUES (%s, %s, %s, %s, %s) RETURNING id, username, name, role, level, registration_date
        ''', (
            data['username'],
            password_hash,
            data['name'],
            role,
            'Sin asignar' if role == 'student' else None
        ))
        
        user = cursor.fetchone()
        conn.commit()
        
        token = generate_token(user['id'], user['username'], user['role'])
        
        cursor.close()
        conn.close()
        
        return jsonify({
            'message': 'Usuario registrado exitosamente',
            'user': dict(user),
            'token': token
        }), 201
        
    except Exception as e:
        print(f"❌ Error en registro: {str(e)}")
        return jsonify({'error': 'Error interno del servidor'}), 500

@app.route('/api/login', methods=['POST'])
def login():
    """Iniciar sesión"""
    try:
        data = request.get_json()
        
        if not data or not data.get('username') or not data.get('password'):
            return jsonify({'error': 'Usuario y contraseña son requeridos'}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM users WHERE username = %s', (data['username'],))
        user_row = cursor.fetchone()
        
        if not user_row:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Usuario o contraseña incorrectos'}), 401
        
        user = dict(user_row)
        
        if not verify_password(data['password'], user['password_hash']):
            cursor.close()
            conn.close()
            return jsonify({'error': 'Usuario o contraseña incorrectos'}), 401
        
        cursor.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = %s', (user['id'],))
        conn.commit()
        
        del user['password_hash']
        
        token = generate_token(user['id'], user['username'], user['role'])
        
        cursor.close()
        conn.close()
        
        return jsonify({
            'message': 'Login exitoso',
            'user': user,
            'token': token
        }), 200
        
    except Exception as e:
        print(f"❌ Error en login: {str(e)}")
        return jsonify({'error': 'Error interno del servidor'}), 500

# ============ CLASES ============
@app.route('/api/classes', methods=['GET'])
@token_required
def get_classes():
    """Obtener clases según acceso del usuario"""
    try:
        level = request.args.get('level', 'A1')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if request.user_role == 'teacher':
            # Profesor ve todas las clases
            if level in ['A1', 'A2', 'B1']:
                cursor.execute('''
                    SELECT c.*, u.name as uploaded_by_name 
                    FROM classes c 
                    JOIN users u ON c.uploaded_by = u.id 
                    WHERE c.level = %s AND c.is_active = TRUE
                    ORDER BY c.created_at DESC
                ''', (level,))
            else:
                cursor.execute('''
                    SELECT c.*, u.name as uploaded_by_name 
                    FROM classes c 
                    JOIN users u ON c.uploaded_by = u.id 
                    WHERE c.is_active = TRUE
                    ORDER BY c.created_at DESC
                ''')
        else:
            # Estudiante solo ve clases con acceso
            cursor.execute('''
                SELECT c.*, u.name as uploaded_by_name, sa.has_access, sa.downloaded
                FROM classes c 
                JOIN users u ON c.uploaded_by = u.id 
                LEFT JOIN student_access sa ON c.id = sa.class_id AND sa.student_id = %s
                WHERE c.level = %s AND c.is_active = TRUE 
                AND (sa.has_access = TRUE OR %s = %s)
                ORDER BY c.created_at DESC
            ''', (request.user_id, level, request.user_role, 'teacher'))
        
        classes = []
        for row in cursor.fetchall():
            classes.append(dict(row))
        
        cursor.close()
        conn.close()
        
        return jsonify(classes), 200
        
    except Exception as e:
        print(f"❌ Error obteniendo clases: {str(e)}")
        return jsonify({'error': 'Error obteniendo clases'}), 500

@app.route('/api/classes/all', methods=['GET'])
@token_required
@teacher_required
def get_all_classes():
    """Obtener todas las clases (solo para profesores)"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT c.*, u.name as uploaded_by_name 
            FROM classes c 
            JOIN users u ON c.uploaded_by = u.id 
            WHERE c.is_active = TRUE
            ORDER BY c.created_at DESC
        ''')
        
        classes = []
        for row in cursor.fetchall():
            classes.append(dict(row))
        
        cursor.close()
        conn.close()
        
        return jsonify(classes), 200
        
    except Exception as e:
        print(f"❌ Error obteniendo todas las clases: {str(e)}")
        return jsonify({'error': 'Error obteniendo clases'}), 500

@app.route('/api/classes/<int:class_id>', methods=['GET'])
@token_required
def get_class(class_id: int):
    """Obtener una clase específica"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if request.user_role == 'teacher':
            cursor.execute('''
                SELECT c.*, u.name as uploaded_by_name 
                FROM classes c 
                JOIN users u ON c.uploaded_by = u.id 
                WHERE c.id = %s
            ''', (class_id,))
        else:
            cursor.execute('''
                SELECT c.*, u.name as uploaded_by_name, sa.has_access
                FROM classes c 
                JOIN users u ON c.uploaded_by = u.id 
                LEFT JOIN student_access sa ON c.id = sa.class_id AND sa.student_id = %s
                WHERE c.id = %s AND (sa.has_access = TRUE OR %s = %s)
            ''', (request.user_id, class_id, request.user_role, 'teacher'))
        
        class_data = cursor.fetchone()
        
        if not class_data:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Clase no encontrada o sin acceso'}), 404
        
        cursor.close()
        conn.close()
        
        return jsonify(dict(class_data)), 200
        
    except Exception as e:
        print(f"❌ Error obteniendo clase: {str(e)}")
        return jsonify({'error': 'Error obteniendo clase'}), 500

@app.route('/api/classes', methods=['POST'])
@token_required
@teacher_required
def upload_class():
    """Subir nueva clase"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No se seleccionó ningún archivo'}), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({'error': 'No se seleccionó ningún archivo'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': 'Tipo de archivo no permitido'}), 400
        
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        level = request.form.get('level', '').strip()
        
        if not title or not description or not level:
            return jsonify({'error': 'Todos los campos son requeridos'}), 400
        
        if level not in ['A1', 'A2', 'B1']:
            return jsonify({'error': 'Nivel no válido'}), 400
        
        upload_result = cloudinary.uploader.upload(
            file,
            folder="clases_ingles",
            resource_type="auto",
            use_filename=True,
            unique_filename=True
        )
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO classes 
            (title, description, level, file_name, file_url, file_type, file_size, uploaded_by)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id, title, description, level, file_name, file_url, file_type, created_at
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
        
        socketio.emit('new_class', dict(new_class))
        
        return jsonify({
            'message': 'Clase subida exitosamente',
            'class': dict(new_class)
        }), 201
        
    except Exception as e:
        print(f"❌ Error subiendo clase: {str(e)}")
        return jsonify({'error': 'Error subiendo la clase'}), 500

@app.route('/api/classes/<int:class_id>', methods=['PUT'])
@token_required
@teacher_required
def update_class(class_id: int):
    """Actualizar una clase existente"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM classes WHERE id = %s', (class_id,))
        class_data = cursor.fetchone()
        
        if not class_data:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Clase no encontrada'}), 404
        
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        level = request.form.get('level', '').strip()
        file = request.files.get('file')
        
        if not title or not description or not level:
            return jsonify({'error': 'Todos los campos son requeridos'}), 400
        
        if level not in ['A1', 'A2', 'B1']:
            return jsonify({'error': 'Nivel no válido'}), 400
        
        update_fields = {
            'title': title,
            'description': description,
            'level': level
        }
        
        file_url = class_data['file_url']
        file_name = class_data['file_name']
        file_type = class_data['file_type']
        file_size = class_data['file_size']
        
        if file and file.filename != '':
            if not allowed_file(file.filename):
                return jsonify({'error': 'Tipo de archivo no permitido'}), 400
            
            upload_result = cloudinary.uploader.upload(
                file,
                folder="clases_ingles",
                resource_type="auto",
                use_filename=True,
                unique_filename=True
            )
            
            file_url = upload_result['secure_url']
            file_name = secure_filename(file.filename)
            file_type = get_file_type(file.filename)
            file_size = upload_result.get('bytes', 0)
            
            update_fields.update({
                'file_url': file_url,
                'file_name': file_name,
                'file_type': file_type,
                'file_size': file_size
            })
        
        set_clause = ', '.join([f"{k} = %s" for k in update_fields.keys()])
        values = list(update_fields.values())
        values.append(class_id)
        
        cursor.execute(f'''
            UPDATE classes 
            SET {set_clause}
            WHERE id = %s
            RETURNING id, title, description, level, file_name, file_url, file_type, created_at
        ''', values)
        
        updated_class = cursor.fetchone()
        conn.commit()
        
        cursor.close()
        conn.close()
        
        return jsonify({
            'message': 'Clase actualizada exitosamente',
            'class': dict(updated_class)
        }), 200
        
    except Exception as e:
        print(f"❌ Error actualizando clase: {str(e)}")
        return jsonify({'error': 'Error actualizando la clase'}), 500

@app.route('/api/classes/<int:class_id>', methods=['DELETE'])
@token_required
@teacher_required
def delete_class(class_id: int):
    """Eliminar una clase"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM classes WHERE id = %s', (class_id,))
        if not cursor.fetchone():
            cursor.close()
            conn.close()
            return jsonify({'error': 'Clase no encontrada'}), 404
        
        cursor.execute('UPDATE classes SET is_active = FALSE WHERE id = %s', (class_id,))
        conn.commit()
        
        cursor.close()
        conn.close()
        
        return jsonify({'message': 'Clase eliminada exitosamente'}), 200
        
    except Exception as e:
        print(f"❌ Error eliminando clase: {str(e)}")
        return jsonify({'error': 'Error eliminando la clase'}), 500

@app.route('/api/classes/<int:class_id>/download', methods=['GET'])
@token_required
def download_class(class_id: int):
    """Registrar descarga"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if request.user_role == 'student':
            cursor.execute('''
                SELECT sa.has_access FROM student_access sa 
                WHERE sa.student_id = %s AND sa.class_id = %s AND sa.has_access = TRUE
            ''', (request.user_id, class_id))
            
            if not cursor.fetchone():
                cursor.close()
                conn.close()
                return jsonify({'error': 'No tienes acceso a esta clase'}), 403
        
        cursor.execute('SELECT * FROM classes WHERE id = %s AND is_active = TRUE', (class_id,))
        class_data = cursor.fetchone()
        
        if not class_data:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Clase no encontrada'}), 404
        
        cursor.execute('''
            INSERT INTO downloads (user_id, class_id) 
            VALUES (%s, %s)
        ''', (request.user_id, class_id))
        
        if request.user_role == 'student':
            cursor.execute('''
                UPDATE student_access 
                SET downloaded = TRUE, downloaded_at = CURRENT_TIMESTAMP
                WHERE student_id = %s AND class_id = %s
            ''', (request.user_id, class_id))
        
        conn.commit()
        
        cursor.close()
        conn.close()
        
        return jsonify({
            'message': 'Redirigiendo a descarga',
            'download_url': class_data['file_url']
        }), 200
        
    except Exception as e:
        print(f"❌ Error en descarga: {str(e)}")
        return jsonify({'error': 'Error en la descarga'}), 500

# ============ ESTUDIANTES ============
@app.route('/api/students', methods=['GET'])
@token_required
@teacher_required
def get_students():
    """Obtener todos los estudiantes"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT u.id, u.username, u.name, u.role, u.level, 
                   u.registration_date, u.last_login, u.is_active,
                   (SELECT COUNT(*) FROM student_access sa WHERE sa.student_id = u.id AND sa.has_access = TRUE) as classes_with_access,
                   (SELECT COUNT(*) FROM student_access sa WHERE sa.student_id = u.id AND sa.downloaded = TRUE) as classes_downloaded
            FROM users u 
            WHERE u.role = 'student' AND u.is_active = TRUE
            ORDER BY u.name
        ''')
        
        students = []
        for row in cursor.fetchall():
            students.append(dict(row))
        
        cursor.close()
        conn.close()
        
        return jsonify(students), 200
        
    except Exception as e:
        print(f"❌ Error obteniendo estudiantes: {str(e)}")
        return jsonify({'error': 'Error obteniendo estudiantes'}), 500

@app.route('/api/students/<int:student_id>', methods=['GET'])
@token_required
@teacher_required
def get_student_detail(student_id: int):
    """Obtener detalle de estudiante con sus clases"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT u.* FROM users u 
            WHERE u.id = %s AND u.role = 'student'
        ''', (student_id,))
        
        student = cursor.fetchone()
        
        if not student:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Estudiante no encontrado'}), 404
        
        cursor.execute('''
            SELECT c.*, sa.has_access, sa.downloaded, sa.downloaded_at, sa.granted_at,
                   u2.name as granted_by_name
            FROM classes c
            LEFT JOIN student_access sa ON c.id = sa.class_id AND sa.student_id = %s
            LEFT JOIN users u2 ON sa.granted_by = u2.id
            WHERE c.is_active = TRUE
            ORDER BY c.level, c.created_at DESC
        ''', (student_id,))
        
        classes = []
        for row in cursor.fetchall():
            classes.append(dict(row))
        
        student_dict = dict(student)
        student_dict['classes'] = classes
        
        cursor.close()
        conn.close()
        
        return jsonify(student_dict), 200
        
    except Exception as e:
        print(f"❌ Error obteniendo detalle estudiante: {str(e)}")
        return jsonify({'error': 'Error obteniendo detalle'}), 500

@app.route('/api/students/<int:student_id>/access', methods=['POST'])
@token_required
@teacher_required
def update_student_access(student_id: int):
    """Actualizar acceso a clases de un estudiante"""
    try:
        data = request.get_json()
        
        if not data or 'class_id' not in data or 'has_access' not in data:
            return jsonify({'error': 'Datos incompletos'}), 400
        
        class_id = data['class_id']
        has_access = data['has_access']
        notes = data.get('notes', '')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT id FROM users WHERE id = %s AND role = %s', 
                      (student_id, 'student'))
        if not cursor.fetchone():
            cursor.close()
            conn.close()
            return jsonify({'error': 'Estudiante no encontrado'}), 404
        
        cursor.execute('SELECT id FROM classes WHERE id = %s', (class_id,))
        if not cursor.fetchone():
            cursor.close()
            conn.close()
            return jsonify({'error': 'Clase no encontrada'}), 404
        
        cursor.execute('''
            INSERT INTO student_access (student_id, class_id, has_access, granted_by, notes)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (student_id, class_id) 
            DO UPDATE SET has_access = %s, granted_by = %s, notes = %s, granted_at = CURRENT_TIMESTAMP
            RETURNING *
        ''', (student_id, class_id, has_access, request.user_id, notes,
              has_access, request.user_id, notes))
        
        result = cursor.fetchone()
        conn.commit()
        
        cursor.close()
        conn.close()
        
        return jsonify({
            'message': 'Acceso actualizado exitosamente',
            'access': dict(result)
        }), 200
        
    except Exception as e:
        print(f"❌ Error actualizando acceso: {str(e)}")
        return jsonify({'error': 'Error actualizando acceso'}), 500

@app.route('/api/students/<int:student_id>/level', methods=['PUT'])
@token_required
@teacher_required
def update_student_level(student_id: int):
    """Actualizar nivel de estudiante"""
    try:
        data = request.get_json()
        
        if not data or 'level' not in data:
            return jsonify({'error': 'Nivel es requerido'}), 400
        
        level = data['level'].strip()
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT id FROM users WHERE id = %s AND role = %s', 
                      (student_id, 'student'))
        if not cursor.fetchone():
            cursor.close()
            conn.close()
            return jsonify({'error': 'Estudiante no encontrado'}), 404
        
        cursor.execute('''
            UPDATE users 
            SET level = %s 
            WHERE id = %s
            RETURNING id, username, name, role, level
        ''', (level, student_id))
        
        updated_student = cursor.fetchone()
        conn.commit()
        
        cursor.close()
        conn.close()
        
        socketio.emit('student_updated', {'student_id': student_id, 'level': level})
        
        return jsonify({
            'message': 'Nivel actualizado exitosamente',
            'student': dict(updated_student)
        }), 200
        
    except Exception as e:
        print(f"❌ Error actualizando nivel: {str(e)}")
        return jsonify({'error': 'Error actualizando el nivel'}), 500

@app.route('/api/students/<int:student_id>', methods=['DELETE'])
@token_required
@teacher_required
def delete_student(student_id: int):
    """Eliminar estudiante (desactivar)"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT id FROM users WHERE id = %s AND role = %s', 
                      (student_id, 'student'))
        if not cursor.fetchone():
            cursor.close()
            conn.close()
            return jsonify({'error': 'Estudiante no encontrado'}), 404
        
        cursor.execute('UPDATE users SET is_active = FALSE WHERE id = %s', (student_id,))
        conn.commit()
        
        cursor.close()
        conn.close()
        
        return jsonify({'message': 'Estudiante eliminado exitosamente'}), 200
        
    except Exception as e:
        print(f"❌ Error eliminando estudiante: {str(e)}")
        return jsonify({'error': 'Error eliminando el estudiante'}), 500

# ============ PUBLICACIONES ============
@app.route('/api/publications', methods=['GET'])
@token_required
def get_publications():
    """Obtener publicaciones"""
    try:
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 20))
        offset = (page - 1) * limit
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT p.*, u.name as author_name, 
                   (pv.user_id IS NOT NULL) as is_viewed
            FROM publications p
            JOIN users u ON p.created_by = u.id
            LEFT JOIN publication_views pv ON p.id = pv.publication_id AND pv.user_id = %s
            WHERE p.is_active = TRUE
            ORDER BY p.created_at DESC
            LIMIT %s OFFSET %s
        ''', (request.user_id, limit, offset))
        
        publications = []
        for row in cursor.fetchall():
            publications.append(dict(row))
        
        cursor.close()
        conn.close()
        
        return jsonify(publications), 200
        
    except Exception as e:
        print(f"❌ Error obteniendo publicaciones: {str(e)}")
        return jsonify({'error': 'Error obteniendo publicaciones'}), 500

@app.route('/api/publications/unread', methods=['GET'])
@token_required
def get_unread_count():
    """Obtener conteo de publicaciones no leídas"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT COUNT(*) as count
            FROM publications p
            LEFT JOIN publication_views pv ON p.id = pv.publication_id AND pv.user_id = %s
            WHERE p.is_active = TRUE AND pv.id IS NULL
        ''', (request.user_id,))
        
        result = cursor.fetchone()
        
        cursor.close()
        conn.close()
        
        return jsonify({'unread_count': result['count']}), 200
        
    except Exception as e:
        print(f"❌ Error obteniendo conteo no leído: {str(e)}")
        return jsonify({'unread_count': 0}), 200

@app.route('/api/publications/<int:publication_id>/view', methods=['POST'])
@token_required
def mark_as_viewed(publication_id: int):
    """Marcar publicación como vista"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO publication_views (user_id, publication_id)
            VALUES (%s, %s)
            ON CONFLICT (user_id, publication_id) DO NOTHING
        ''', (request.user_id, publication_id))
        
        conn.commit()
        
        cursor.close()
        conn.close()
        
        return jsonify({'message': 'Publicación marcada como vista'}), 200
        
    except Exception as e:
        print(f"❌ Error marcando como vista: {str(e)}")
        return jsonify({'error': 'Error actualizando vista'}), 500

@app.route('/api/publications', methods=['POST'])
@token_required
@teacher_required
def create_publication():
    """Crear nueva publicación"""
    try:
        publication_type = request.form.get('type', 'text')
        
        if publication_type not in ['text', 'photo', 'video', 'document']:
            return jsonify({'error': 'Tipo de publicación no válido'}), 400
        
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        
        if not title:
            return jsonify({'error': 'El título es requerido'}), 400
        
        if publication_type == 'text' and not content:
            return jsonify({'error': 'El contenido es requerido para publicaciones de texto'}), 400
        
        file_url = None
        file_name = None
        file_type = None
        
        if publication_type in ['photo', 'video', 'document']:
            if 'file' not in request.files:
                return jsonify({'error': 'Archivo es requerido para este tipo de publicación'}), 400
            
            file = request.files['file']
            
            if file.filename == '':
                return jsonify({'error': 'No se seleccionó ningún archivo'}), 400
            
            if not allowed_file(file.filename):
                return jsonify({'error': 'Tipo de archivo no permitido'}), 400
            
            upload_result = cloudinary.uploader.upload(
                file,
                folder="publicaciones",
                resource_type="auto",
                use_filename=True,
                unique_filename=True
            )
            
            file_url = upload_result['secure_url']
            file_name = secure_filename(file.filename)
            file_type = get_file_type(file.filename)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO publications 
            (title, content, publication_type, file_url, file_name, file_type, created_by)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING id, title, content, publication_type, file_url, file_name, file_type, created_at
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
        
        socketio.emit('new_publication', dict(new_publication))
        
        return jsonify({
            'message': 'Publicación creada exitosamente',
            'publication': dict(new_publication)
        }), 201
        
    except Exception as e:
        print(f"❌ Error creando publicación: {str(e)}")
        return jsonify({'error': 'Error creando la publicación'}), 500

@app.route('/api/publications/<int:publication_id>', methods=['DELETE'])
@token_required
@teacher_required
def delete_publication(publication_id: int):
    """Eliminar publicación"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM publications WHERE id = %s', (publication_id,))
        if not cursor.fetchone():
            cursor.close()
            conn.close()
            return jsonify({'error': 'Publicación no encontrada'}), 404
        
        cursor.execute('UPDATE publications SET is_active = FALSE WHERE id = %s', (publication_id,))
        conn.commit()
        
        cursor.close()
        conn.close()
        
        return jsonify({'message': 'Publicación eliminada exitosamente'}), 200
        
    except Exception as e:
        print(f"❌ Error eliminando publicación: {str(e)}")
        return jsonify({'error': 'Error eliminando la publicación'}), 500

# ============ PERFIL ============
@app.route('/api/profile', methods=['GET'])
@token_required
def get_profile():
    """Obtener perfil del usuario"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, username, name, role, level, registration_date, last_login
            FROM users WHERE id = %s
        ''', (request.user_id,))
        
        user = cursor.fetchone()
        
        if not user:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Usuario no encontrado'}), 404
        
        if request.user_role == 'student':
            cursor.execute('''
                SELECT COUNT(*) as total_classes,
                       COUNT(CASE WHEN downloaded = TRUE THEN 1 END) as downloaded_classes
                FROM student_access 
                WHERE student_id = %s AND has_access = TRUE
            ''', (request.user_id,))
        else:
            cursor.execute('''
                SELECT COUNT(*) as total_classes FROM classes WHERE uploaded_by = %s AND is_active = TRUE
            ''', (request.user_id,))
            cursor.execute('''
                SELECT COUNT(*) as total_students FROM users WHERE role = %s AND is_active = TRUE
            ''', ('student',))
        
        stats = dict(cursor.fetchone())
        
        cursor.close()
        conn.close()
        
        profile = dict(user)
        profile['stats'] = stats
        
        return jsonify(profile), 200
        
    except Exception as e:
        print(f"❌ Error obteniendo perfil: {str(e)}")
        return jsonify({'error': 'Error obteniendo perfil'}), 500

# ============ ARCHIVOS ESTÁTICOS ============
@app.route('/<path:path>')
def serve_static(path):
    try:
        return send_from_directory('.', path)
    except:
        return jsonify({'error': 'Archivo no encontrado'}), 404

# ============ WEBSOCKET ============
@socketio.on('connect')
def handle_connect():
    emit('connection_response', {'message': 'Conectado'})

@socketio.on('disconnect')
def handle_disconnect():
    pass

# ============ INICIALIZACIÓN ============
if __name__ == '__main__':
    print("=" * 60)
    print("🚀 INICIANDO SERVIDOR DE CLASES DE INGLÉS - V3.0")
    print("=" * 60)
    print("🔧 Configurando base de datos PostgreSQL...")
    
    try:
        # Ejecutar migración automática
        init_db()
        
        print("✅ Base de datos configurada exitosamente")
        print(f"🔑 Código estudiante: {STUDENT_CODE}")
        print(f"👨‍🏫 Código profesor: {TEACHER_CODE}")
        print("=" * 60)
        print("🌐 Servidor listo para recibir conexiones...")
        print("=" * 60)
    except Exception as e:
        print(f"⚠️  Error configurando base de datos: {str(e)}")
        print("ℹ️  Continuando con estructura existente...")
    
    port = int(os.environ.get('PORT', 5000))
    
    socketio.run(
        app, 
        host='0.0.0.0', 
        port=port, 
        debug=False,
        allow_unsafe_werkzeug=True
    )