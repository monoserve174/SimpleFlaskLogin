from flask import Flask, render_template, url_for, request, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user  # 登入登出使用
import os  # 資料庫模型使用
from werkzeug.security import generate_password_hash, check_password_hash  # 資料庫模型使用

app = Flask(__name__)

app.config['SECRET_KEY'] = 'KevinSecretKey'
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'database.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"


# 資料庫模型使用
class User(UserMixin, db.Model):
    uid = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    _hash_pwd = db.Column(db.String(240), nullable=False)

    @property
    def pwd(self):
        raise Exception('密碼不可讀取')

    @pwd.setter
    def pwd(self, pwd):
        self._hash_pwd = generate_password_hash(pwd)

    def check_hash_pwd(self, pwd):
        return check_password_hash(self._hash_pwd, pwd)

    def __init__(self, username, pwd):
        self.username = username
        self.pwd = pwd

    def __repr__(self):
        return f'<User {self.id}: {self.username}>'

    @staticmethod
    def create(username, pwd='pass'):
        user = User(username=username,
                    pwd=pwd)
        db.session.add(user)
        db.session.commit()
        return User.query.filter_by(username=username).all()[-1]

    @staticmethod
    def read(uid):
        if uid:
            return User.query.get(uid)
        else:
            return User.query.all()

    @staticmethod
    def update(uid, org_pwd, username='', new_pwd=''):
        user = User.read(uid)
        if user.check_hash_pwd(org_pwd):
            if not username == '':
                user.username = username
            if not new_pwd == '':
                user.pwd = new_pwd
            db.session.add(user)
            db.session.commit()
            return User.read(uid)
        else:
            return 'Org Password Error.'

    @staticmethod
    def delete(uid):
        user = User.read(uid)
        db.session.delete(user)
        db.session.commit()
        return f'User {user.username} be deleted.'

    def get_id(self):
        return self.uid


# 路由及前端
@app.route('/', methods=['GET'])
@app.route('/index')
@login_required
def index():
    if current_user:
        user = current_user
    return render_template('index.html', user=user)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.values.get('username')
        user = User.query.filter_by(username=username).first()
        pwd = request.values.get('password')
        if not user is None:
            if user.check_hash_pwd(pwd):
                login_user(user)
                next_url = request.args.get('next')
                return redirect(next_url or url_for('index'))
        return 'User or Password Error'
    return render_template('login.html')


@app.route('/logout')
def logout():
    logout_user()  # 登出用戶
    return redirect(url_for('index'))


@login_manager.user_loader
def user_loader(uid):
    return User.query.get(uid)


if __name__ == '__main__':
    app.debug = True
    app.run()
