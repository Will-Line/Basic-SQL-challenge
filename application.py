#Remember you have deprecated to Flask 2.3.3

from flask import Flask, redirect, url_for, request, render_template, jsonify, flash, send_file, Blueprint
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import text
from sqlalchemy import Integer, String, select
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, LoginManager, login_user, login_required, current_user, logout_user
import time
import boto3
from botocore.exceptions import ClientError
import mysql.connector

def get_secret():
   secret_name = "rds!db-5420f6d2-147d-4fdf-99ac-f9c4d879f542"
   region_name = "eu-west-2"

   # Create a Secrets Manager client
   session = boto3.session.Session()
   client = session.client(
      service_name='secretsmanager',
      region_name=region_name
   )

   try:
      get_secret_value_response = client.get_secret_value(
         SecretId=secret_name
      )
   except ClientError as e:
      # For a list of exceptions thrown, see
      # https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
      raise e

   secret = get_secret_value_response['SecretString']
   return secret.split("\"")[7]

mydb=mysql.connector.connect(host="localhost",user="root",password="",database="basicsql")


db = SQLAlchemy()

application = Flask(__name__)
application.secret_key = "super secret key" #DO NOT LEAVE THIS LIKE THIS

db_name = 'basicsql.db'

application.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:@localhost:3306/basicsql'
#application.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://involuntary:{get_secret()}@ctf-database.cv64kuysmh9b.eu-west-2.rds.amazonaws.com:3306/basicsql'

application.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

# initialize the app with Flask-SQLAlchemy
db.init_app(application)

login_manager = LoginManager()
login_manager.init_app(application)


@login_manager.user_loader
def load_user(user_id):
   # since the user_id is just the primary key of our user table, use it in the query for the user
   return Users.query.get(int(user_id))

class Users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(40), unique=True,nullable=False)
    password = db.Column(db.String(60), unique=False, nullable=False)
    admin = db.Column(db.Boolean)

with application.app_context():
    db.create_all()


@application.route('/')
def login():
   return render_template('index.html')

@application.route('/', methods=['POST'])
def login_post():
   name = request.form.get('inputUsername')
   password = request.form.get('inputPassword')

   user = Users.query.filter_by(name=name).first()

    # check if the user actually exists
    # take the user-supplied password, hash it, and compare it to the hashed password in the database
   if not user or not check_password_hash(user.password, password):
        flash('Please check your login details and try again.')
        return redirect('/') # if the user doesn't exist or password is wrong, reload the page

   login_user(user)
   return redirect('/user')

@application.route('/signup')
def signUp():
    return render_template('signup.html')

@application.route('/signup',methods=['POST'])
def signup_post():
   name = request.form.get('inputUsername')
   password = request.form.get('inputPassword')

   user = Users.query.filter_by(name=name).first() # if this returns a user, then the email already exists in database

   if user: # if a user is found, we want to redirect back to signup page so user can try again
      flash("User already exists. Pick a new username/email.")
      return redirect(url_for('signup'))

   # create a new user with the form data. Hash the password so the plaintext version isn't saved.
   new_user = Users(name=name, password=generate_password_hash(password, method='pbkdf2:sha256'),admin=False)

   db.session.add(new_user)
   db.session.commit()

   return redirect('/')

@application.route('/user')
@login_required
def userPage():
    mydb.reconnect()
    cursor=mydb.cursor()
    search=request.args.get('search')

    if search==None:
        queryText=f"SELECT * FROM items;"
    else:
        queryText=f"SELECT * FROM items WHERE name LIKE '%{search}%';"

    cursor.execute(queryText)
    items=cursor.fetchall()
    cursor.close()
    return render_template('userPage.html',items=items)

@application.route('/logout')
@login_required
def logout():
   logout_user()
   return redirect('/')

if __name__ == '__main__':
   website_url='basicsql.involuntaryCTF:5000'
   application.config['SERVER_NAME']=website_url
   application.run(debug=True)
