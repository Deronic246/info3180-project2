from . import db
from werkzeug.security import generate_password_hash, check_password_hash

#User table Stores user data
class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80))
    password = db.Column(db.String())
    firstname = db.Column(db.String(80))
    lastname = db.Column(db.String(80))
    email = db.Column(db.String(255))
    location = db.Column(db.String(255))
    biography = db.Column(db.String(255))
    profile_photo = db.Column(db.String(255))
    joined_on = db.Column(db.String(80))
    
    def __init__(self, uname,password, fname, lname, email, location, bio, pic, joined):
        self.username = uname
        self.password = generate_password_hash(password)
        self.firstname = fname
        self.lastname = lname
        self.email = email
        self.location = location
        self.biography = bio
        self.profile_photo = pic
        self.joined_on = joined
        
    def check_password(self, password):
        return check_password_hash(self.password, password)  

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        try:
            return unicode(self.id) 
        except NameError:
            return str(self.id) 

    def __repr__(self):
        return "<User (username = '%s', firstname= '%s' joined: '%s' )>" % (self.user_name, self.first_name, self.joined_on)

#Posts Table to store user posts information
class Posts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    photo = db.Column(db.String(255))
    caption = db.Column(db.String(255))
    created_on = db.Column(db.String(80))
    
    def __init__(self, userid, pic, caption, created):
        self.user_id = userid
        self.photo = pic
        self.caption = caption
        self.created_on = created

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        try:
            return unicode(self.id) 
        except NameError:
            return str(self.id)  

    def __repr__(self):
        return '<Post %r>' % (self.id)

##Likes Table to user likes information  
class Likes(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    post_id = db.Column(db.Integer)
    
    def __init__(self, userid, postid):
        self.user_id = userid
        self.post_id = postid

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        try:
            return unicode(self.id)  
        except NameError:
            return str(self.id)  

    def __repr__(self):
        return '<Like %r>' % (self.id)
 
 #Follows table Stores user follower data
class Follows(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    follow_id = db.Column(db.Integer)
    
    def __init__(self, following_id, followed_id):
        self.user_id = following_id
        self.follow_id = followed_id

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        try:
            return unicode(self.id)  
        except NameError:
            return str(self.id) 

    def __repr__(self):
        return '<Follows %r>' % (self.id)