from flask import Flask, render_template, redirect, url_for, request, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, emit
import os 

app = Flask(__name__, template_folder="haha")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SECRET_KEY"] = "helloguys"

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

socketio = SocketIO(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)  
    friends = db.relationship('Friend', backref='user', lazy=True)

    # Flask-Login required methods
    def is_active(self):
        return True  
    
    def is_authenticated(self):
        return True  

    def is_anonymous(self):
        return False  

    def get_id(self):
        return str(self.id)  

class Friend(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    friend_username = db.Column(db.String(100), nullable=False)

with app.app_context():
    db.create_all()

users_db = {}

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template("home.html")

@app.route('/signup', methods=["GET", "POST"])
def sign_up():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        name = request.form["name"]
        
        if not username or not password or not name:
            flash("Please fill in all fields.")
            return redirect(url_for("sign_up"))
        
        existing_user = User.query.filter_by(username=username).first()

        if existing_user:
            flash("User exists, please choose a different username.")
            return redirect(url_for("sign_up"))
        
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        
        new_user = User(username=username, password=hashed_password, name=name)
        db.session.add(new_user)
        db.session.commit()

        flash('Account created successfully!')
        login_user(new_user)
        
        return redirect(url_for("home"))
    return render_template("signup.html")

@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            session['username'] = username
            return redirect(url_for("chat", friend=username))  # Pass 'friend' parameter here
        else:
            flash("Invalid username or password.")
    
    return render_template("login.html")

@app.route('/logout')
def logout():
    logout_user(user)
    return redirect(url_for("home"))

@app.route('/add_friend', methods=["POST"])
def add_friend():
    if 'username' not in session:
        return redirect(url_for("login"))
    
    if request.method == "POST":
        friend_username = request.form["friend_username"]
        user = User.query.filter_by(username=session['username']).first()
        friend = User.query.filter_by(username=friend_username).first()

        if not friend:
            flash('Friend not found', 'error')
            return redirect(url_for('add_friend'))

        if friend_username == session['username']:
            flash('You cannot add yourself as a friend', 'error')
            return redirect(url_for('add_friend'))

        existing_friend = Friend.query.filter_by(user_id=user.id, friend_username=friend_username).first()
        if existing_friend:
            flash('Already friends', 'error')
            return redirect(url_for('add_friend'))

        new_friend = Friend(user_id=user.id, friend_username=friend_username)
        db.session.add(new_friend)
        db.session.commit()

        flash('Friend added successfully', 'success')
        return redirect(url_for('home'))
    return render_template('add_friend.html')


@app.route('/friends')
def get_friends():
    if 'username' not in session:
        return redirect(url_for('login'))

    user = User.query.filter_by(username=session['username']).first()
    friends = [friend.friend_username for friend in user.friends]
    return jsonify(friends)

@app.route('/chat/<friend>')
def chat(friend):
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('chat.html', friend=friend)

@socketio.on('join')
def handle_join(data):
    username = data['username']
    users_db[username] = request.sid
    emit('user_list', list(users_db.keys()), broadcast=True)

@socketio.on('message')
def handle_message(data):
    target_user_sid = users_db.get(data['target_user'])
    if target_user_sid:
        emit('message', data, room=target_user_sid)

@socketio.on('disconnect')
def handle_disconnect():
    for user, sid in list(users_db.items()):
        if sid == request.sid:
            del users_db[user]
            emit('user_list', list(users_db.keys()), broadcast=True)
            break

if __name__ == "__main__":
    socketio.run(app, debug=True)

