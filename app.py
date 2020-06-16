from flask import Flask, redirect, url_for, render_template
from datetime import datetime
from flask_wtf import FlaskForm
from flask_sqlalchemy import SQLAlchemy
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from flask_login import login_user, logout_user, UserMixin, login_required, LoginManager, current_user

app = Flask(__name__)
app.config['SECRET_KEY'] = '94jfkmnwojknkmpdfpe4wrpopoir-okviwipknkim'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///base.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
   return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(20), unique=True, nullable=False)
    gender = db.Column(db.String(10))
    password = db.Column(db.String(20), unique=True, nullable=False)
    post = db.relationship('Post', backref='author', lazy='dynamic')

    def __repr__(self):
        return f"User {self.username}, {self.email}"

class Post(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    datetime = db.Column(db.DateTime, nullable=False, default= datetime.utcnow)
    imgfile = db.Column(db.String(30), nullable=True, unique=False, default='default.jpg')
    textfile = db.Column(db.Text, nullable=True)
    user_Id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"User {self.file}"


class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=5, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(),Length(max=50)])
    submit = SubmitField('Submit')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()

        if user:
            raise ValidationError('This username is taken')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()

        if user:
            raise ValidationError('This email is taken')    


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(),Length(max=50)])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Submit')


class PostForm(FlaskForm):
    textfile = StringField('Post', validators=[DataRequired()])  
    submit = SubmitField('Submit')


@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html')

@app.route('/register', methods=['POST', 'GET'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('login'))
    form = RegisterForm()
    if form.validate_on_submit(): 
        hashed = generate_password_hash(form.password.data)
        user = User(username=form.username.data, email=form.email.data, password=hashed)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['POST', 'GET'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user, remember=True)
            return redirect(url_for('home'))
    return render_template('login.html', form=form)


@app.route('/home', methods=['POST', 'GET'])
def home():
    posts = Post.query.order_by(Post.datetime.desc())
    return render_template('home.html', posts=posts)

@app.route('/post',  methods=['POST', 'GET'])
def post():
    form=PostForm()
    if form.validate_on_submit():
        post = Post(textfile=form.textfile.data, author=current_user)
        db.session.add(post)
        db.session.commit()
        return redirect(url_for('home'))
    return render_template('post.html', form=form)


@app.route('/logout', methods=['POST', 'GET'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == "__main__":
    app.run(debug=True)
