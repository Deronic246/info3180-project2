from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, TextAreaField
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms.validators import InputRequired


class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    firstname = StringField('Firstname', validators=[InputRequired()])
    lastname = StringField('Lastname', validators=[InputRequired()])
    password = StringField('Password', validators=[InputRequired()])
    email = StringField('email', validators=[InputRequired()])
    location = StringField('location', validators=[InputRequired()])
    biography = TextAreaField('biography', validators=[InputRequired()])
    photo = FileField('Profile Picture', validators=[
        FileRequired(),
        FileAllowed(['jpg', 'png', 'Images only!'])
    ])
    
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = StringField('Password', validators=[InputRequired()])
    
class PostsForm(FlaskForm):
    photo = FileField('Picture', validators=[
        FileRequired(),
        FileAllowed(['jpg', 'png', 'Images only!'])
    ])
    caption = StringField('Username', validators=[InputRequired()])


