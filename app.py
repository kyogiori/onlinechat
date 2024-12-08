from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from flask_caching import Cache
from functools import wraps
from datetime import datetime


# Ініціалізація застосунку
app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat.db'
app.config['CACHE_TYPE'] = 'SimpleCache'
db = SQLAlchemy(app)
cache = Cache(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Модель User
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(10), default='user')


# Модель Message
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


# Завантаження користувача
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Декоратор для перевірки ролі адміністратора
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role != 'admin':
            flash('Access denied.')
            return redirect(url_for('chat'))
        return f(*args, **kwargs)
    return decorated_function


# Форма входу
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# Маршрут головної сторінки чату
@app.route('/chat')
def chat():
    messages = cache.get('messages')
    if not messages:
        messages = Message.query.order_by(Message.timestamp.desc()).all()
        cache.set('messages', messages, timeout=60)
    return render_template('chat.html', messages=messages)

# Маршрут адміністраторської панелі
@app.route('/admin')
@login_required
@admin_required
def admin_panel():
    messages = Message.query.all()
    return render_template('admin.html', messages=messages)

# Відправка повідомлення
@app.route('/send_message', methods=['POST'])
@login_required
def send_message():
    content = request.form['content']
    message = Message(content=content, user_id=current_user.id)
    db.session.add(message)
    db.session.commit()
    cache.delete('messages')  # Очищення кешу
    return redirect(url_for('chat'))

# Видалення повідомлення (адмін)
@app.route('/delete_message/<int:id>')
@login_required
@admin_required
def delete_message(id):
    message = Message.query.get_or_404(id)
    db.session.delete(message)
    db.session.commit()
    cache.delete('messages')  # Очищення кешу
    return redirect(url_for('admin_panel'))

# Маршрут для входу
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('Login successful!')
            return redirect(url_for('chat'))
        flash('Invalid username or password')
    return render_template('login.html', form=form)


class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Register')

from werkzeug.security import generate_password_hash, check_password_hash

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user is None:
            hashed_password = generate_password_hash(form.password.data)
            new_user = User(username=form.username.data, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! You can now log in.')
            return redirect(url_for('login'))
        flash('Username already exists. Please choose a different one.')
    return render_template('register.html', form=form)



# Маршрут для виходу
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))




# Запуск застосунку
if __name__ == '__main__':
    app.run(debug=True)