# auth.py
from flask import render_template, request, flash, redirect, url_for
from flask_login import LoginManager, login_user, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length
from models import User, db
from utils.validators import InputValidators
import phonenumbers

# Forms
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    firstname = StringField('First Name', validators=[DataRequired(), Length(max=50)])
    lastname = StringField('Last Name', validators=[DataRequired(), Length(max=50)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    mobile = StringField('Mobile Number', validators=[DataRequired(), Length(max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), Length(min=6)])
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

        # Confirm password match
        if form.password.data != form.confirm_password.data:
            flash('Passwords do not match.', 'error')
            return render_template('register.html', form=form)

        # Check if user exists
        if User.query.filter((User.email == form.email.data) | (User.mobile == form.mobile.data)).first():
            flash('Email or mobile number already registered', 'error')
            return render_template('register.html', form=form)


        # Validate mobile number with country code
        country_code = request.form.get('country_code')
        mobile_number = form.mobile.data
        full_number = f"{country_code}{mobile_number}"
        try:
            parsed_number = phonenumbers.parse(full_number, None)
            if not phonenumbers.is_valid_number(parsed_number):
                flash('Invalid mobile number for the selected country code.', 'error')
                return render_template('register.html', form=form)
        except Exception:
            flash('Invalid mobile number format.', 'error')
            return render_template('register.html', form=form)

        # Check if mobile number already exists
        if User.query.filter_by(mobile=full_number).first():
            flash('This mobile number is already registered. Please use a different number.', 'error')
            return render_template('register.html', form=form)

        # Create new user with all fields and IP address
        ip_address = request.remote_addr

        from datetime import datetime
        new_user = User(
            firstname=form.firstname.data,
            lastname=form.lastname.data,
            email=form.email.data,
            mobile=full_number,
            ip_address=ip_address,
            agreed_privacy_policy=True,
            agreed_privacy_policy_at=datetime.utcnow()
        )
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
login_manager.login_view = 'login_route'
login_manager.login_message = 'Please log in to access this page.'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))