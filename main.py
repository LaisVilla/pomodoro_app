import os
from flask import Flask, render_template, request, jsonify, abort, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from datetime import datetime
import json

# Configuração do aplicativo
app = Flask(__name__)
app.config['SECRET_KEY'] = 'sua_chave_secreta_aqui'  # Altere para um valor seguro
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///pomodoro.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Inicialização das extensões
db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Modelos de Banco de Dados
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    tasks = db.relationship('Task', backref='user', lazy=True)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(200), nullable=False)
    completed = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class UserSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    focus_time = db.Column(db.Integer, default=25)
    short_break = db.Column(db.Integer, default=5)
    long_break = db.Column(db.Integer, default=15)

# Classe Pomodoro Timer (sem alterações)
class PomodoroTimer:
    def __init__(self):
        self.state = None  # 'focus', 'short_break', 'long_break'
        self.remaining_time = 0
        self.total_time = 0
        self.is_running = False
        self.last_update = None
        
    def start_focus(self, minutes=25):
        self.state = 'focus'
        self.total_time = minutes * 60
        self.remaining_time = self.total_time
        self.is_running = True
        self.last_update = datetime.utcnow()
        
    def start_break(self, break_type='short'):
        self.state = f'{break_type}_break'
        self.total_time = 5 * 60 if break_type == 'short' else 15 * 60
        self.remaining_time = self.total_time
        self.is_running = True
        self.last_update = datetime.utcnow()
        
    def pause(self):
        self.is_running = False
        
    def resume(self):
        self.is_running = True
        self.last_update = datetime.utcnow()
        
    def reset(self):
        self.remaining_time = self.total_time
        self.is_running = False
        
    def update(self):
        if not self.is_running:
            return
            
        now = datetime.utcnow()
        elapsed = (now - self.last_update).total_seconds()
        self.last_update = now
        
        self.remaining_time = max(0, self.remaining_time - elapsed)
        if self.remaining_time == 0:
            self.is_running = False
            
    def get_state(self):
        return {
            'state': self.state,
            'remaining_time': int(self.remaining_time),
            'total_time': self.total_time,
            'is_running': self.is_running,
            'progress': (1 - self.remaining_time / self.total_time) * 100 if self.total_time > 0 else 0
        }
class TaskManager:
    def get_tasks(self):
        return Task.query.filter_by(user_id=current_user.id).all()

    def add_task(self, text: str) -> Task:
        if not text or not text.strip():
            raise ValueError("Task text cannot be empty")

        task = Task(text=text.strip(), user_id=current_user.id)
        db.session.add(task)
        db.session.commit()
        return task

    def update_task(self, task_id: int, text: str = None, completed: bool = None) -> Task:
        task = Task.query.filter_by(id=task_id, user_id=current_user.id).first()
        
        if not task:
            raise ValueError(f"Task with id {task_id} not found")
        
        if text is not None:
            task.text = text.strip()
        
        if completed is not None:
            task.completed = completed
        
        db.session.commit()
        return task

    def delete_task(self, task_id: int):
        task = Task.query.filter_by(id=task_id, user_id=current_user.id).first()
        
        if not task:
            raise ValueError(f"Task with id {task_id} not found")
        
        db.session.delete(task)
        db.session.commit()

#Instâncias globais
timer = PomodoroTimer()
task_manager = TaskManager()

# Configurações de Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Rotas de Autenticação
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        user = User.query.filter_by(username=data['username']).first()
        
        if user and bcrypt.check_password_hash(user.password, data['password']):
            login_user(user)
            return jsonify({'success': True})
        
        return jsonify({'success': False, 'message': 'Credenciais inválidas'}), 401
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.get_json()
        
        # Verificar se o usuário já existe
        existing_user = User.query.filter_by(username=data['username']).first()
        if existing_user:
            return jsonify({'success': False, 'message': 'Usuário já existe'}), 400
        
        # Hash da senha
        hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
        
        # Criar novo usuário
        new_user = User(username=data['username'], password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        
        return jsonify({'success': True})
    
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index.html'))

# Rotas protegidas por login
@app.route('/')
def index():
    return render_template('index.html')

# Rotas da API (adicionando proteção de login)
@app.route('/api/tasks', methods=['GET'])
@login_required
def get_tasks():
    tasks = task_manager.get_tasks()
    return jsonify([{
        'id': task.id, 
        'text': task.text, 
        'completed': task.completed,
        'created_at': task.created_at.isoformat()
    } for task in tasks])

# Outras rotas de API com login_required
# (Adicione @login_required a todas as rotas de API)
@app.route('/api/tasks', methods=['POST'])
@login_required
def add_task():
    data = request.get_json()
    
    if not data or 'text' not in data:
        abort(400, description="Task text is required")

    try:
        task = task_manager.add_task(data['text'])
        return jsonify({
            'id': task.id, 
            'text': task.text, 
            'completed': task.completed,
            'created_at': task.created_at.isoformat()
        }), 201
    except ValueError as e:
        abort(400, description=str(e))

# Repita o padrão para outras rotas de API

if __name__ == '__main__':
    # Cria o banco de dados se não existir
    with app.app_context():
        db.create_all()
    
    app.run(debug=True)