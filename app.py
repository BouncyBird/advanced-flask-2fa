from flask import Flask, render_template, request, redirect, url_for, flash, session, abort, jsonify, send_file
from flask_otp import OTP
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm, RecaptchaField
from werkzeug.exceptions import default_exceptions
from wtforms import StringField, SubmitField, TextAreaField, PasswordField, BooleanField, DateTimeField
from wtforms.fields.core import IntegerField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, URL as URLval, NumberRange
import requests
import re
from datetime import datetime
from itsdangerous import URLSafeTimedSerializer, TimedJSONWebSignatureSerializer as Serializer
from flask_login import LoginManager, login_user, current_user, logout_user, login_required, UserMixin
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate, current
from flask_mail import Message, Mail

app = Flask(__name__)
otp = OTP()
otp.init_app(app)
app.config['SECRET_KEY'] = '09c4a587537f4059549a8f9ef485f284'
app.config['SECURITY_PASSWORD_SALT'] = '763fc88aac5bc2d8df654d351119ed39'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['MAIL_SERVER'] = "smtp.googlemail.com"
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'bouncybird.mailsender@gmail.com'
app.config['MAIL_PASSWORD'] = 'asdfghjkl!@#$%^&*()'
mail = Mail()
db = SQLAlchemy(app)
bcrypt = Bcrypt()
login_manager = LoginManager()
login_manager.login_message_category = 'info'
bcrypt.init_app(app)
mail.init_app(app)
login_manager.init_app(app)
migrate = Migrate(app, db, render_as_batch=True)
app.config["DOMAIN"] = "localhost"


def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])


def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(
            token,
            salt=app.config['SECURITY_PASSWORD_SALT'],
            max_age=expiration
        )
    except:
        return False
    return email


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    confirmed = db.Column(db.Boolean, nullable=False, default=False)
    staff = db.Column(db.Boolean, nullable=False, default=False)
    otpkey = db.Column(db.Text, nullable=False)

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.confirmed}')"


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
                           DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[
                             DataRequired(), Length(min=8, max=30)])
    confirm_password = PasswordField('Confirm Password', validators=[
                                     DataRequired(), Length(min=8, max=30), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):

        user = User.query.filter_by(username=username.data).first()

        if user:
            raise ValidationError(
                'That username is taken. Please choose a different username.')

    def validate_email(self, email):

        user = User.query.filter_by(email=email.data).first()

        if user:
            raise ValidationError(
                'That email is taken. Please choose a different email.')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[
                             DataRequired(), Length(min=8, max=30)])
    token = IntegerField('Token')
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')


class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

    def validate_email(self, email):

        user = User.query.filter_by(email=email.data).first()

        if user is None:
            raise ValidationError(
                'There is no account with that email. You must register first.')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[
                             DataRequired(), Length(min=8, max=30)])
    confirm_password = PasswordField('Confirm Password', validators=[
                                     DataRequired(), Length(min=8, max=30), EqualTo('password')])
    submit = SubmitField('Reset Password')


class AuthSetupForm(FlaskForm):
    token = IntegerField('Token')
    submit = SubmitField('Submit')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def send_confirm_email(user, token, confirm_url):
    msg = Message('Confirm Account', sender='noreply@demo.com',
                  recipients=[user.email])
    msg.body = f'''To confirm your account, visit the following link:
{url_for('confirm_email', token=token, _external=True)}

This link will expire in 1 hour for security reasons

'''
    mail.send(msg)


@app.route('/')
def home():
    return render_template('home.html')


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        flash("You are already logged in", "info")
        return redirect(url_for("home"))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(
            form.password.data).decode("utf-8")
        user = User(
            username=form.username.data,
            email=form.email.data,
            password=hashed_password,
            confirmed=False,
            staff=False,
            otpkey=otp.get_key()
        )
        db.session.add(user)
        db.session.commit()
        token = generate_confirmation_token(user.email)
        confirm_url = url_for("confirm_email",
                              token=token, _external=True)
        send_confirm_email(user, token, confirm_url)
        flash("An email has been sent to confirm your email", "info")
        return redirect(url_for("home"))
    return render_template("register.html", title="Register", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        flash("You are already logged in", "info")
        return redirect(url_for("home"))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user == None:
            flash("Login Unsuccessful. Please check email and password", "danger")
        elif not user.confirmed:
            token = generate_confirmation_token(user.email)
            confirm_url = url_for("confirm_email",
                                  token=token, _external=True)
            send_confirm_email(user, token, confirm_url)
            flash("An email has been sent to confirm your email", "info")
            return redirect(url_for("home"))
        elif user and bcrypt.check_password_hash(user.password, form.password.data) and otp.authenticate(user.otpkey, form.token.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get("next")
            flash("Login Successful. You have been logged in.", "success")
            return redirect(next_page) if next_page else redirect(url_for("home"))
        else:
            flash("Login Unsuccessful. Please check email and password", "danger")
    return render_template("login.html", title="Login", form=form)


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("home"))


def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request',
                  sender='noreply@demo.com', recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}

This link will expire in 30 minutes for security reasons

If you did not make this request simply ingore this email and no changes will be made.
'''
    mail.send(msg)


@app.route("/reset_password", methods=["GET", "POST"])
def reset_request():
    if current_user.is_authenticated:
        flash("You are already logged in", "info")
        return redirect(url_for("home"))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash("An email has been sent with instructions to reset your password", "info")
        return redirect(url_for("login"))
    return render_template("reset_request.html", title="Reset Password", form=form)


@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_token(token):
    if current_user.is_authenticated:
        flash("You are already logged in", "info")
        return redirect(url_for("home"))
    user = User.verify_reset_token(token)
    if user is None:
        flash("That is an invalid or expired token", "warning")
        return redirect(url_for("reset_request"))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode(
            "utf-8"
        )
        user.password = hashed_password
        db.session.commit()
        flash("Your password has been changed. You are now able to login.", "success")
        return redirect(url_for("login"))
    return render_template("reset_token.html", title="Reset Password", form=form)


@app.route("/confirm/<token>")
def confirm_email(token):
    try:
        email = confirm_token(token)
    except:
        flash("The confirmation link is invalid or has expired.", "warning")
    user = User.query.filter_by(email=email).first_or_404()
    if user.confirmed:
        flash("Account already confirmed. Please login.", "success")
    else:
        user.confirmed = True
        db.session.add(user)
        db.session.commit()
        login_user(user, remember=False)
        flash("You have confirmed your account. Thanks! You are now logged in!", "success")
        return redirect(url_for('auth_setup'))
    return redirect(url_for("home"))


@app.route('/auth_setup', methods=['GET', 'POST'])
@login_required
def auth_setup():
    form = AuthSetupForm()
    if form.validate_on_submit():
        if otp.authenticate(current_user.otpkey, form.token.data):
            flash(
                'Success! You will have to use this token every time you login', 'success')
            return redirect(url_for('home'))
        else:
            flash('Error authenticating', 'danger')
            return redirect(url_for('auth_setup'))
    return render_template('authsetup.html', form=form)


@app.route('/qr')
@login_required
def qr():
    """
    Return a QR code for the secret key
    The QR code is returned as file with MIME type image/png.
    """
    img = otp.qr(current_user.otpkey)
    return send_file(img, mimetype="image/png")


if __name__ == '__main__':
    app.run(debug=True)
