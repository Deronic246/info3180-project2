from flask import Flask
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect



app = Flask(__name__)

app.config['UPLOAD_FOLDER'] = "./app/static/uploads"
app.config['SECRET_KEY'] = "secret"
app.config['SQLALCHEMY_DATABASE_URI'] = "postgres://bnftelerivknuz:0f73dea9c0246000db210ace7f31f2321409691e4f9e014af91a2450aea3ab6c@ec2-54-197-234-117.compute-1.amazonaws.com:5432/d3qbffkqkggnbe"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True


db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

app.config.from_object(__name__)
csrf = CSRFProtect(app)
from app import views