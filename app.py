from flask import Flask
from flask import render_template, url_for, flash, redirect, request
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.file import FileField, FileAllowed
from flask_bcrypt import Bcrypt
from flask import *
from flask_login import LoginManager, login_user, logout_user, login_required,UserMixin
from flask_migrate import Migrate
from flask_wtf import FlaskForm
import os
import re
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, IntegerField
from wtforms.validators import InputRequired, DataRequired, Length, EqualTo, ValidationError
import logging
import logging.config
import phonenumbers
from contextlib import suppress
import subprocess
#import subprocess1-3?
#import wtfforms import TextAreaField
from sqlalchemy.orm import *
from sqlalchemy.dialects.sqlite import *
from sqlalchemy import *
from sqlalchemy.ext.declarative import *
from flask_wtf import CSRFProtect 

debug = False
#using SQLite instead of dictionary to store users in database. Hopefully useful for assignment 3
dbLocation = 'sqlite:///users.db'
bcrypt = Bcrypt()
app = Flask(__name__)
app.config['SECRET_KEY'] = '6hu789iud4556tgre34ggh6y9o022wws'

# When writing your Web service, you must defend against common attacks against Web
#services such as:
#XSS
#CSRF
#Session hijacking
#command injection
csrf = CSRFProtect(app)
csrf.init_app(app)
app.config['SQLALCHEMY_DATABASE_URI'] = dbLocation
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = debug
engine = create_engine(dbLocation, echo=debug)
db = SQLAlchemy(app)
migrate = Migrate(app,db)
 
class User(db.Model):
	__tablename__ = "users"
	id = Column(db.Integer, primary_key=True)
	username = db.Column(String)
	password = db.Column(String)
	phone = db.Column(String)
	def __init__(self, username, password, phone):
		self.username = username
		self.password = bcrypt.generate_password_hash(password).decode('UTF-8')
		self.phone = phone
	@classmethod
	def checkUser(cls, username):
		found_user = cls.query.filter_by(username = username).first()
		if found_user:
			return False
		return True
	@classmethod
	def authUser(cls, username, password, phone):
		found_user = cls.query.filter_by(username = username).first()
		if found_user:
			authenticated_user = bcrypt.check_password_hash(found_user.password, password)
			if authenticated_user and found_user.phone == phone:
				return found_user			
		return False
	@classmethod
	def authUserPwd(cls, username, password):
		found_user = cls.query.filter_by(username = username).first()
		if found_user:
			authenticated_user = bcrypt.check_password_hash(found_user.password, password)
			if authenticated_user :
				return found_user			
		return False
	@classmethod
	def auth2FA(cls, username, phone):
		found_user = cls.query.filter_by(username = username).first()
		if found_user and found_user.phone == phone:
				return found_user			
		return False

db.Model.metadata.create_all(engine)
login_manager = LoginManager()
login_manager.init_app(app) 
login_manager.login_view = '.login'

class UserForm(FlaskForm):
    username = StringField(label= 'Username', id='uname',validators=[DataRequired()])                 
    password = PasswordField(label='password', id='pword', validators=[DataRequired()])
    phone = IntegerField(label='2 Factor', id='2fa',validators=[DataRequired()])

@app.route("/")
@app.route("/home/")  
def home():
    return render_template('home.html')

# REGISTER: Users must be registered in order to use your service. Your registration page is required to have
#the following forms for the user to fill in:
# A form for the user to enter a username, with id=uname.
# A form for the user to enter a password, with id=pword
# A form for the user to enter a two-factor authentication device, with id=2fa

@app.route("/register/", methods=['GET','POST'])
def register():
    form = UserForm()
    error = None
    success = "failure"
    if request.method == 'POST':
        if form.validate_on_submit():  
            username = request.form['username']
            password = request.form['password']	
            phone = request.form['phone']
            user = User(username,password, phone)
# Ensure multi factor authentication works and give error if the phone number if invalid.
# Validity check
            x= phonenumbers.parse(phone, "US")
            if not phonenumbers.is_valid_number(x):
                error = 'Failure: Invalid phone number - think of a new one!' 
            if User.checkUser(username):				
                db.session.add(user)
                db.session.commit()
                success = "success"
                error='Success : Registration Successful.'
            else:
                error= 'Failure: Username '+username+' user is already registered. Create new username.'
        else:
            error='Failure: Invalid Registration.'
        response = make_response(render_template('register.html',
                                                 error=error,
                                                 success=success,
                                                 form=form))

        response.headers['Content-Security-Policy'] = "default-src 'self'"
        return response
    return render_template('register.html',error=error,success=success, form=form)

# TEST SUBMISSION:
#After a user is logged in, he or she has the ability to submit bodies of text to check the spelling
#of the words in the text. The text should be submitted through a form with id=inputtext. Your
#Web service should then take this text and use the spell checker you wrote in Assignment 1 to
#determine which words are misspelled. The binary will exist with the name a.out. You do not
#need to submit this binary. It will already be on the gradescope autograder.
class SpellCheckForm(FlaskForm):
    inputtext = TextAreaField('text_to_check', id='inputtext', validators=[DataRequired()],render_kw={"rows": 5, "cols": 100})

@app.route("/spell_check/", methods=['GET','POST'])  
def spell_check():
    form = SpellCheckForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            text = form.inputtext.data
            f = open("tempUserInput", "w")
            f.write(text)
            f.close()

            process = subprocess.run(['./a.out', 'tempUserInput', 'wordlist.txt'], check=True, stdout=subprocess.PIPE, universal_newlines=True)
            output = process.stdout
            os.remove("tempUserInput")
            misspelledOut = output.replace("\n", ", ").strip().strip(',')
            return render_template('spell_check.html', misspelled=misspelledOut, textout=text,form=form)
    return render_template('spell_check.html', form=form)

# LOGIN: After a user registers, he or she should be able to login to your Web service. Your login page is
#required to have the following forms for the user to fill in:
# A form for a user to enter a username, with id=uname.
# A form for a user to enter a password, with id=pword.
# A form for the user to enter a two-factor authentication code, with id=2fa
# Instead of actual 2-factor, this field will just accept the phone number the user signed
# up with. Unfortunately, setting up a 2fa system requires more effort than can be
# alloted to this assignment.

@app.route("/login/", methods=['GET','POST']) 
def login():
    form = UserForm()
    error = None
    result = "failure"
    if request.method == 'POST':
        if form.validate_on_submit(): 
            username = request.form['username']
            password = request.form['password']	
            phone = request.form['phone']
            user = User(username,password, phone)
        if User.authUser(username, password, phone):
            session['logged_in'] = True
            result = "success"
            error = "Login Successful: Success"
        elif User.authUserPwd(username, password):
            if not User.auth2FA(username, phone):
                error = 'Two-Factor Authentication Failure: Failure'
        else:
            error = 'Incorrect credentials: Failure'
        response = make_response(render_template('login.html',
                                                 error=error,
                                                 result=result,
                                                 form=form))
        response.headers['Content-Security-Policy'] = "default-src 'self'"
        return response
    return render_template('login.html',error=error,result=result, form=form)

@app.route("/logout/")
def logout():
    logout_user()
    return render_template('home.html')

if __name__ == '__main__':
	app.run()
