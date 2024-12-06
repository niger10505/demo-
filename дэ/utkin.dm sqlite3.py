import sqlite3
from datetime import datetime
conn = sqlite3.connect('service_requests.db')
cursor = conn.cursor()
cursor.execute('''
    CREATE TABLE IF NOT EXISTS requests (
        request_id INTEGER PRIMARY KEY,
        date_added TEXT,
        equipment_type TEXT,
        model TEXT,
        problem_description TEXT,
        customer_name TEXT,
        phone_number TEXT,
        status TEXT
    )
''')

def add_request(equipment_type, model, problem_description, customer_name, phone_number, status='Новая заявка'):
  
    date_added = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    cursor.execute('''
        INSERT INTO requests (date_added, equipment_type, model, problem_description, customer_name, phone_number, status)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (date_added, equipment_type, model, problem_description, customer_name, phone_number, status))

    conn.commit()

add_request('Принтер', 'HP LaserJet', 'Не печатает', 'Иванов Иван', '89001234567')
conn.close()
class Application:
    def __init__(self, id, status, description, responsible):
        self.id = id
        self.status = status  
        self.description = description  
        self.responsible = responsible  
    def update_status(self, new_status):
       
        self.status = new_status

    def update_description(self, new_description):
        
        self.description = new_description

    def update_responsible(self, new_responsible):
       
        self.responsible = new_responsible


application_1 = Application(1, 'в процессе ремонта', 'не работает экран', 'Иванов')
application_1.update_status('готова к выдаче')
application_1.update_description('заменён экран')
application_1.update_responsible('Петров')

print(vars(application_1)) 
class Application:
    def __init__(self, app_id, status):
        self.app_id = app_id
        self.status = status

class ApplicationTracker:
    def __init__(self):
        self.applications = []
        self.subscribers = []

    def add_application(self, application):
        self.applications.append(application)
        self.notify_subscribers(application)

    def update_status(self, app_id, new_status):
        for app in self.applications:
            if app.app_id == app_id:
                app.status = new_status
                self.notify_subscribers(app)
                break

    def notify_subscribers(self, application):
        for subscriber in self.subscribers:
            subscriber(application)

    def subscribe(self, callback):
        self.subscribers.append(callback)

    def list_applications(self):
        return [(app.app_id, app.status) for app in self.applications]

    def search_application(self, app_id=None, status=None):
        return [app for app in self.applications if
                (app_id is None or app.app_id == app_id) and
                (status is None or app.status == status)]
class Request:
    def __init__(self, request_id, client_name):
        self.request_id = request_id  
        self.client_name = client_name  
        self.master = None  
        self.status = 'Ожидает'  
        self.comments = [] 
        self.parts = []  

    def assign_master(self, master_name):
        self.master = master_name  
    def update_status(self, new_status):
        self.status = new_status  
        print(f"Статус заявки {self.request_id} обновлен на '{new_status}'.")

    def add_comment(self, comment):
        self.comments.append(comment) 
        print(f"Комментарий добавлен к заявке {self.request_id}: {comment}.")

    def order_part(self, part_name):
        self.parts.append(part_name)
        print(f"Запчасть '{part_name}' добавлена к заявке {self.request_id}.")

import pandas as pd

data = pd.read_csv('service_requests.csv')

completed_requests = data[data['status'] == 'completed']
total_completed_requests = completed_requests.shape[0]
completed_requests['time_taken'] = pd.to_datetime(completed_requests['end_time']) - pd.to_datetime(completed_requests['start_time'])
average_time = completed_requests['time_taken'].mean()
fault_statistics = completed_requests['fault_type'].value_counts()

print(f"Количество выполненных заявок: {total_completed_requests}")
print(f"Среднее время выполнения заявки: {average_time}")
print("Статистика по типам неисправностей:")
print(fault_statistics)
import platform

if platform.system() == "Windows":
    print("Программа запущена в Windows")
else:
    print("Программа запущена не в Windows")

app = Flask(__name__)
app.secret_key = 'your_secret_key' 
users = {
    'admin': {'password': 'adminpass', 'role': 'admin'},
    'user': {'password': 'userpass', 'role': 'user'}
}

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Вам нужно войти в систему, чтобы получить доступ к этой странице.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'username' not in session or users[session['username']]['role'] != role:
                flash('У вас нет прав для доступа к этой странице.')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username in users and users[username]['password'] == password:
            session['username'] = username
            flash('Вы успешно вошли в систему!')
            return redirect(url_for('dashboard'))
        else:
            flash('Неправильный логин или пароль.')

    return('login.html')

@app.route('/logout')
@login_required
def logout():
    session.pop('username', None)
    flash('Вы вышли из системы.')
    return (url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return "('dashboard.html', username=session['username'], role=users[session['username']]['role'])"
@app.route('/admin')
@login_required
@role_required('admin')
def admin_panel():
    return('admin.html')

@app.route('/user')
@login_required
@role_required('user')
def user_panel():
    return ('user.html')

if __name__ == '__main__':
    app.run(debug=True)
app = Flask(__name__)
app.secret_key = 'your_secret_key'

users = {
    'admin': {'password': 'adminpass', 'role': 'admin'},
    'user': {'password': 'userpass', 'role': 'user'}
}

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Вам нужно войти в систему, чтобы получить доступ к этой странице.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'username' not in session or users[session['username']]['role'] != role:
                flash('У вас нет прав для доступа к этой странице.', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username in users and users[username]['password'] == password:
            session['username'] = username
            flash('Вы успешно вошли в систему!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Неправильный логин или пароль.', 'danger')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    session.pop('username', None)
    flash('Вы вышли из системы.', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=session['username'], role=users[session['username']]['role'])

@app.route('/admin')
@login_required
@role_required('admin')
def admin_panel():
    return render_template('admin.html')

@app.route('/user')
@login_required
@role_required('user')
def user_panel():
    return render_template('user.html')

if __name__ == '__main__':
    app.run(debug=True)
    app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db' 
app.config['CACHE_TYPE'] = 'simple' 
app.secret_key = 'your_secret_key'

db = SQLAlchemy(app)
cache = Cache(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False)

@app.before_first_request
def create_tables():
    db.create_all()
    if User.query.count() == 0:  
        admin = User(username='admin', password='adminpass', role='admin')
        user = User(username='user', password='userpass', role='user')
        db.session.add(admin)
        db.session.add(user)
        db.session.commit()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Вам нужно войти в систему, чтобы получить доступ к этой странице.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'username' not in session or User.query.filter_by(username=session['username']).first().role != role:
                flash('У вас нет прав для доступа к этой странице.', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/login', methods=['GET', 'POST'])
@cache.cached(timeout=50)
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        if user and user.password == password:
            session['username'] = username
            flash('Вы успешно вошли в систему!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Неправильный логин или пароль.', 'danger')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    session.pop('username', None)
    flash('Вы вышли из системы.', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
@cache.cached(timeout=50)
def dashboard():
    return render_template('dashboard.html', username=session['username'], role=User.query.filter_by(username=session['username']).first().role)

@app.route('/admin')
@login_required
@role_required('admin')
def admin_panel():
    return render_template('admin.html')

@app.route('/user')
@login_required
@role_required('user')
def user_panel():
    return render_template('user.html')

if __name__ == '__main__':
    app.run(debug=True)
from flask import Flask, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from forms import LoginForm
from models import db, User
from config import Config

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.password == form.password.data:  
            login_user(user)
            flash('Вы успешно вошли в систему!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Неправильный логин или пароль.', 'danger')
    return render_template('login.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=current_user.username, role=current_user.role)

@app.route('/admin')
@login_required
def admin_panel():
    if current_user.role != 'admin':
        flash('У вас нет доступа к этой странице.', 'danger')
        return redirect(url_for('dashboard'))
    return render_template('admin.html')

@app.route('/user')
@login_required
def user_panel():
    return render_template('user.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы вышли из системы.', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all() 
    app.run(debug=True)