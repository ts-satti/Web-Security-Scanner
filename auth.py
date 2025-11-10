# auth.py
from flask import render_template, request, flash, redirect, url_for
from flask_login import LoginManager, login_user, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length
from models import User, db
from utils.validators import InputValidators

# Forms
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Register')

# Route functions (not blueprint routes)
def login_route():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash('Login successful!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        else:
            flash('Invalid email or password', 'error')
    
    return render_template('login.html', form=form)

def register_route():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = RegisterForm()
    if form.validate_on_submit():
        # Validate email
        is_valid, email_msg = InputValidators.validate_email(form.email.data)
        if not is_valid:
            flash(email_msg, 'error')
            return render_template('register.html', form=form)
        
        # Validate password
        is_valid, password_msg = InputValidators.validate_password(form.password.data)
        if not is_valid:
            flash(password_msg, 'error')
            return render_template('register.html', form=form)
        
        # Check if user exists
        if User.query.filter_by(email=form.email.data).first():
            flash('Email already registered', 'error')
            return render_template('register.html', form=form)
        
        # Create new user
        new_user = User(email=form.email.data)
        new_user.set_password(form.password.data)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login_route'))
    
    return render_template('register.html', form=form)

def logout_route():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

# Login manager setup
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))