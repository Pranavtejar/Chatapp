from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__, template_folder = "haha")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SECRET_KEY"] = 'your_secret_key'
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    name = db.Column(db.String(50), unique=True, nullable=False)

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
            flash("Login successful!")
            return redirect(url_for("home"))
        else:
            flash("Invalid username or password.")
    
    return render_template("login.html")


if __name__ == '__main__':
    app.run(debug=True)

