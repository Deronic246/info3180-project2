"""
Flask Documentation:     http://flask.pocoo.org/docs/
Jinja2 Documentation:    http://jinja.pocoo.org/2/documentation/
Werkzeug Documentation:  http://werkzeug.pocoo.org/documentation/
This file creates your application.
"""

from app import app, db, login_manager,csrf
from werkzeug.utils import secure_filename
from flask import render_template, request, redirect, url_for, flash,jsonify,abort,g 
import os
from app.forms import RegisterForm, LoginForm, PostsForm
from datetime import datetime
from app.models import Users, Posts,Follows,Likes
from flask_login import login_user, logout_user, current_user, login_required
import jwt
from flask import _request_ctx_stack
from functools import wraps
import base64


def requires_auth(f):
  @wraps(f)
  def decorated(*args, **kwargs):
    secret = app.config['SECRET_KEY']
    auth = request.headers.get('Authorization', None)
    if not auth:
      return jsonify({'code': 'authorization_header_missing', 'description': 'Authorization header is expected'}), 401

    parts = auth.split()

    if parts[0].lower() != 'bearer':
      return jsonify({'code': 'invalid_header', 'description': 'Authorization header must start with Bearer'}), 401
    elif len(parts) == 1:
      return jsonify({'code': 'invalid_header', 'description': 'Token not found'}), 401
    elif len(parts) > 2:
      return jsonify({'code': 'invalid_header', 'description': 'Authorization header must be Bearer + \s + token'}), 401

    token = parts[1]
    try:
         payload = jwt.decode(token, secret)

    except jwt.ExpiredSignature:
        return jsonify({'code': 'token_expired', 'description': 'token is expired'}), 401
    except jwt.DecodeError:
        return jsonify({'code': 'token_invalid_signature: {}'.format(token), 'description': 'Token signature is invalid'}), 401

    g.current_user = user = payload
    return f(*args, **kwargs)

  return decorated

###
# Routing for your application.
###

@app.route('/')
def index():
    """Render the initial webpage and then let VueJS take control."""
    return render_template('index.html')
        
@app.route('/api/users/register', methods=['POST'])
def register():
    form = RegisterForm()
    if request.method == 'POST' and form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        firstname = form.firstname.data
        lastname = form.lastname.data
        email = form.email.data
        location = form.location.data
        biography = form.biography.data
        photo = form.photo.data
        joined = format_date_joined(datetime.now())
        
        usercheck = db.session.query(Users).filter_by(username=username).first()
        emailcheck = db.session.query(Users).filter_by(email=email).first()
        
        if usercheck is None and emailcheck is None:
            filename = secure_filename(photo.filename)
            photo.save(os.path.join(
            app.config['UPLOAD_FOLDER'], filename
            ))
            
            newuser = Users(username,password,firstname,lastname,email,location,biography,filename,joined)
            db.session.add(newuser)
            db.session.commit()
            
            er = None
            msg = "User Created Successfully"
            userData = {'id': newuser.id, 
            'email': newuser.email,
            'usernname': newuser.username, 
            'firstname': newuser.firstname, 
            'lastname': newuser.lastname, 
            'location': newuser.location, 
            'bio': newuser.biography, 
            'profile_pic': newuser.profile_photo, 
            'joined': newuser.joined_on}
            
            msg = "User was successfully added"
            
            return jsonify(error = er ,data = {"newuser": userData},message = msg),201
        else:
            msg = "Username and/or email already exist"
            return jsonify(error=[msg], message="Username and/or email already exist"),400
    else:
        return jsonify(errors = form_errors(form))

@app.route('/api/auth/login', methods=['POST'])
def login():
    form = LoginForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            username = form.username.data
            password = form.password.data
            
            user = db.session.query(Users).filter_by(username=username).first()
            
            if user is not None and user.check_password(password):
                login_user(user)
                
                er = None
                msg = "User was successfully logged in."
                
                return jsonify(errors = er , message = msg, id = user.id)
            else:
                er = True
                msg = 'Invalid username or password'
                return jsonify(errors = [msg], message = msg)
        else:
            return jsonify(errors = form_errors(form)),400
    else:
        abort (405)
        
@app.route('/api/auth/logout', methods=['POST'])
@requires_auth
def logout():
    if request.method == 'POST':
        logout_user()
        er =None
        msg = "User successfully logged out."
        return jsonify(errors = er, message = msg)
    else:
        abort(405)
        
@app.route('/api/posts/', methods=['GET'])
@requires_auth
def allPosts():
    if request.method == 'GET':
        allposts = Posts.query.all()
        plist = []
        user = current_user
        def check_if_current_user_likes(user,post):
            likes = Likes.query.all()
            for like in likes:
                if like.user_id == user.id and like.post_id == post.id:
                    return True
            return False
        if allposts is None:
            er=True
            msg ="There are no posts in the database"
            return jsonify(errors = er, message = msg),404
        for post in allposts:
            post_creator = Users.query.filter_by(id=post.user_id).first()
            profile_pic = post_creator.profile_photo
            likes_count = Likes.query.filter_by(post_id = post.id).count()
            post_dict ={
            "Post_creator":post_creator.username,
            "profile_pic": profile_pic,
            "id":post.id,
            "likes":likes_count,
            "userid":post.user_id,
            "pic":post.photo,
            "caption":post.caption,
            "created_on":post.created_on,
            "likes_by_current_user":check_if_current_user_likes(user,post)
            }
            
            plist.append(post_dict)
        er =None
        msg = "Users' Posts"
        return jsonify(errors = er, message = msg, posts=plist)
    else:
        abort(405)
        
@app.route('/api/users/<int:userid>/posts', methods=['GET','POST','DELETE'])
@requires_auth
def userPosts(userid):
    form = PostsForm()
    if request.method == 'GET':
        user = Users.query.filter_by(id = userid).first()
        if user is not None:
            userposts = Posts.query.filter_by(user_id = userid)
            if userposts is not None:
                plist=[]
                for post in userposts:
                    post_creator = Users.query.filter_by(id=post.user_id).first()
                    profile_pic = post_creator.profile_photo
                    likes_count = Likes.query.filter_by(post_id = post.id).count()
                    post_dict ={
                    "Post_creator":post_creator.username,
                    "profile_pic": profile_pic,
                    "id":post.id,
                    "likes":likes_count,
                    "userid":post.user_id,
                    "pic":post.photo,
                    "caption":post.caption,
                    "created_on":post.created_on
                    }
                    plist.append(post_dict)
                msg = "{} Posts found".format(user.username)
                er = None
                return jsonify(error=er,message=msg,posts=plist)
            else:
               er = True
               msg = "User has no posts"
               return jsonify(error=er,message=msg),404
        else:
            er=True
            msg = "User does not exist"
            return jsonify(error=er,message=msg),404
    elif request.method == 'POST':
        if form.validate_on_submit():
            if current_user.id == userid:
                pic = form.photo.data
                caption =  form.caption.data
                date = format_date_joined(datetime.now())
                filename = secure_filename(pic.filename)
                pic.save(os.path.join(
                app.config['UPLOAD_FOLDER'], filename
                ))
                newpost  =Posts(userid,filename,caption, date)
                db.session.add(newpost)
                db.session.commit()
                
                er = None
                msg = "Post created successfully"
                return jsonify(error=er, message=msg),201
            else:
                er=True
                msg = "You can only create posts for yourself. Your id is {} and you are trying to create a post for user with the id {}".format(current_user.id,userid)
                return jsonify(error=er , message = msg),401
                
@app.route('/api/users/<userid>/follow', methods = ['POST','PUT'])
@requires_auth
def follow(userid):
    if request.method == 'POST':
        current = current_user
        target = Users.query.filter_by(id = userid).first()
        if target is not None:
            new_follow_relationship = Follows(current.id,target.id)
            db.session.add(new_follow_relationship)
            db.session.commit()
            er = None
            msg ="{} is now following {}".format(current.username,target.username)
            return jsonify(error=er,message=msg),202
        else:
            er = True
            msg ="User doesn't exist"
            return jsonify(error=er,message=msg),404
    elif request.method == 'PUT':
        current = current_user
        target = Users.query.filter_by(id = userid).first()
        if target is not None:
            def check_if_currentuser_is_following(current,target):
                follows = Follows.query.all()
                for follow in follows:
                    if follow.user_id == current.id and follow.follow_id == target.id:
                        db.session.delete(follow)
                        db.session.commit()
                        return True
                return False
            if check_if_currentuser_is_following(current,target):
                er = None
                msg ="{} has unfollowed {}".format(current.username,target.username)
                return jsonify(error=er,message=msg),202
            else:
                er = True
                msg ="{} is not following {}, so he/she can't unfollow {}".format(current.username,target.username,target.username)
                return jsonify(error=er,message=msg),202
        else:
            er = True
            msg ="Target user doesn't exists"
            return jsonify(error=er,message=msg),404
    else:
        abort(405)

@app.route('/api/posts/<int:postid>/like', methods=['POST'])
@requires_auth
def like(postid):
    if request.method == 'POST':
        user = current_user
        post = Posts.query.filter_by(id = postid).first()
        def check_if_user_liked_already(user,post):
            likes = Likes.query.all()
            for like in likes:
                if like.user_id == user.id and like.post_id == post.id:
                    return True
            return False
        if post is not None:
            if check_if_user_liked_already(user,post):
                er =True
                msg = "{} already likes this post".format(user.username)
                return jsonify(error=er,message=msg),403
            new_like = Likes(user.id,post.id)
            db.session.add(new_like)
            db.session.commit()
        
            er=None
            msg ="{} liked this post".format(user.username)
            return jsonify(error=er,message=msg),202
        else:
            er=True
            msg ="Invalid post id"
            return jsonify(error=er,message=msg),404
    else:
        abort(405)
  
#returns user's information      
@app.route('/api/u/<int:id>', methods=['GET','POST'])
@requires_auth
def userInfo(id):
    if request.method == 'GET':
        user = Users.query.filter_by(id = id).first()
        if user is not None:
            posts_count = Posts.query.filter_by(user_id=id).count()
            follower_count = Follows.query.filter_by(follow_id=id).count()
            following_count = Follows.query.filter_by(user_id=id).count()
            userData = {
            'id': user.id, 
            'email': user.email,
            'username': user.username, 
            'firstname': user.firstname, 
            'lastname': user.lastname, 
            'location': user.location, 
            'bio': user.biography, 
            'profile_pic': user.profile_photo, 
            'joined': user.joined_on,
            'follower_count': follower_count,
            'following_count':following_count,
            'posts_count':posts_count
            }
            er = None
            msg= "Info for {} successfully fetched".format(user.username)
            return jsonify(error=er, message=msg , user_info = [userData])
        else:
            er = True
            msg= "User doesn't exist"
            return jsonify(error=er,message=msg),404
    else:
        abort(405)

#checks if the current user is following a specific user        
@app.route('/api/users/follows/<int:id>',methods=['GET','POST'])
@requires_auth
def followChecker(id):
    current = current_user
    target_user = Users.query.filter_by(id = id).first()
    
    if target_user is None:
        er=True
        msg="Target user with the id {} doesn't exist".format(id)
        return jsonify(error=er,message=msg),404
    
    
    if current.id == target_user.id:
        er=True
        msg="A User cannot follow themselves"
        current_following_target = False
        return jsonify(error=er,message=msg,current_following_target=current_following_target)
        
    def check_if_currentuser_is_following(current,target):
            follows = Follows.query.all()
            for follow in follows:
                if follow.user_id == current.id and follow.follow_id == target.id:
                    return True
            return False
    current_following_target= check_if_currentuser_is_following(current,target_user)
    er=None
    msg="Follow status successfully fetched"
    return jsonify(error=er,message=msg,current_following_target=current_following_target)
    
@app.route('/api/users/posts/<int:id>', methods=['DELETE'])
@requires_auth
def DeletePost(id):
    if request.method == 'DELETE':
        post = Posts.query.filter_by(user_id=id).first()
        if post is not None:
            user  = current_user
            if post.user_id == user.id:
                db.session.delete(post)
                db.session.commit()
                er=None
                msg= "{} deleted post titled {}".format(user.username,post.title)
                return jsonify(error=er,message=msg),202
            else:
                er=True
                msg="A user cannot delete a post that they didn't create"
                return jsonify(error=er,message=msg),404
        else:
            er=True
            msg="Post with the id of {} doesn't exist".format(id)
            return jsonify(error=er,message=msg),404   
    else:
        abort(405)
    
        
@app.route('/token',methods=['POST'])
@csrf.exempt
def generate_token():
    payload = request.get_json()
    secret = app.config['SECRET_KEY']
    token = jwt.encode(payload, secret, algorithm='HS256').decode('utf-8')

    return jsonify(error=None, data=[{'token': token}], message="Token Generated"),201


###
# The functions below should be applicable to all Flask apps.
###

def form_errors(form):
    error_messages = []
    """Collects form errors"""
    for field, errors in form.errors.items():
        for error in errors:
            message = u"Error in the %s field - %s" % (
                    getattr(form, field).label.text,
                    error
                )
            error_messages.append(message)

    return error_messages

def format_date_joined(d):
    return d.strftime("%d %b, %Y");


    
@login_manager.user_loader
def load_user(id):
    return db.session.query(Users).get(int(id))
    
    
@app.route('/<file_name>.txt')
def send_text_file(file_name):
    """Send your static text file."""
    file_dot_text = file_name + '.txt'
    return app.send_static_file(file_dot_text)


@app.after_request
def add_header(response):
    """
    Add headers to both force latest IE rendering engine or Chrome Frame,
    and also tell the browser not to cache the rendered page. If we wanted
    to we could change max-age to 600 seconds which would be 10 minutes.
    """
    response.headers['X-UA-Compatible'] = 'IE=Edge,chrome=1'
    response.headers['Cache-Control'] = 'public, max-age=0'
    return response


@app.errorhandler(404)
def page_not_found(error):
    """Custom 404 page."""
    return render_template('404.html'), 404

@app.errorhandler(405)
def method_not_allowed(error):
    """Custom 405 page."""
    return render_template('405.html'), 405


if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port="8080")
