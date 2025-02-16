from flask import Flask, render_template, redirect, url_for, request, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, emit, join_room, leave_room

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
    name = db.Column(db.String(100), nullable=False)
    friends = db.relationship('Friend', backref='user', lazy=True)

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

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template("home.html")

@app.route('/signup', methods=["GET", "POST"])
def sign_up():
    error_message = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        name = request.form["name"]
        
        if not username or not password or not name:
            error_message = "Please fill in all fields."
        else:
            existing_user = User.query.filter_by(username=username).first()

            if existing_user:
                error_message = "User exists, please choose a different username."
            else:
                hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
                new_user = User(username=username, password=hashed_password, name=name)
                db.session.add(new_user)
                db.session.commit()
                login_user(new_user)
                session['username'] = username  
                return redirect(url_for("chat", friend=username))
    return render_template("signup.html", error_message=error_message)

@app.route('/login', methods=["GET", "POST"])
def login():
    error_message = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            session['username'] = user.username  
            return redirect(url_for("chat", friend=username))
        else:
            error_message = "Invalid username or password."
    
    return render_template("login.html", error_message=error_message)

@app.route('/logout')
def logout():
    logout_user()
    session.pop('username', None)  
    return redirect(url_for("home"))

@app.route('/add_friend', methods=["GET", "POST"])
@login_required
def add_friend():
    error_message = None
    if request.method == "POST":
        friend_username = request.form["friend_username"]
        user = User.query.filter_by(username=current_user.username).first()
        friend = User.query.filter_by(username=friend_username).first()

        if not friend:
            error_message = "Friend not found"
        elif friend_username == current_user.username:
            error_message = "You cannot add yourself as a friend."
        else:
            existing_friend = Friend.query.filter_by(user_id=user.id, friend_username=friend_username).first()
            if existing_friend:
                error_message = "Already friends."
            else:
                new_friend = Friend(user_id=user.id, friend_username=friend_username)
                db.session.add(new_friend)
                db.session.commit()
                return redirect(url_for('chat', friend=friend_username))

    return render_template('add_friend.html', error_message=error_message)

@app.route('/friends')
@login_required
def get_friends():
    user = User.query.filter_by(username=current_user.username).first()
    friends = [friend.friend_username for friend in user.friends]
    return jsonify(friends)

@app.route('/chat/<friend>')
@login_required
def chat(friend):
    return render_template('chat.html', friend=friend)

users_db = {}

@socketio.on('join')
def handle_join(data):
    username = data['username']
    users_db[username] = request.sid
    emit('user_list', list(users_db.keys()), broadcast=True)

@socketio.on('message')
def handle_message(data):
    sender_username = None
    for user, sid in users_db.items():
        if sid == request.sid:
            sender_username = user
            break

    target_user_sid = users_db.get(data['target_user'])
    if target_user_sid and sender_username != data['target_user']:
        emit('message', {
            'sender': sender_username,
            'message': data['message'],
            'target_user': data['target_user']
        }, room=target_user_sid)

@socketio.on('disconnect')
def handle_disconnect():
    for user, sid in list(users_db.items()):
        if sid == request.sid:
            del users_db[user]
            emit('user_list', list(users_db.keys()), broadcast=True)
            break

@socketio.on('webrtc_offer')
def handle_webrtc_offer(data):
    target_user_sid = users_db.get(data['target_user'])
    if target_user_sid:
        emit('webrtc_offer', data, room=target_user_sid)

@socketio.on('webrtc_answer')
def handle_webrtc_answer(data):
    target_user_sid = users_db.get(data['target_user'])
    if target_user_sid:
        emit('webrtc_answer', data, room=target_user_sid)

@socketio.on('webrtc_ice_candidate')
def handle_webrtc_ice_candidate(data):
    target_user_sid = users_db.get(data['target_user'])
    if target_user_sid:
        emit('webrtc_ice_candidate', data, room=target_user_sid)

if __name__ == "__main__":
    socketio.run(app, debug=True)