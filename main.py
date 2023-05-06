import flask
from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from sqlalchemy import select

login_manager = LoginManager()
app = Flask(__name__)

app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
app.app_context().push()
login_manager.init_app(app)


##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template("index.html", logged_in=current_user.is_authenticated)

@app.route('/register', methods=["POST", "GET"])
def register():

    error = None
    if request.method == "POST":
        username_ = request.form.get("name")
        email_ = request.form.get("email")
        password_ = request.form.get("password")

        if User.query.filter_by(email=email_).first() != None:
            error = "Email already exists."
        else:
            new_entry = User(
                email=email_,
                password=generate_password_hash(password_, method="pbkdf2:sha256", salt_length=8),
                name=username_
            )
            db.session.add(new_entry)
            db.session.commit()
            return redirect(url_for("secrets", name=username_, logged_in=True))

    return render_template("register.html", error=error, logged_in=current_user.is_authenticated)


@app.route('/login', methods=["GET","POST"])
def login():

    error = None

    if request.method == "POST":
        email = request.form.get("email")
        passsword = request.form.get("password")

        user = User.query.filter_by(email=email).first()

        if user == None:
            error = "Invalid email."

        else:
            if check_password_hash(user.password, passsword):
                login_user(user)
                print("logged in")
                flash("Logged in successfully")
                return redirect(url_for("secrets", name=current_user.name, logged_in=True))
            else:
                error = "Invalid password."

    return render_template("login.html", error=error)


@app.route('/secrets/<name>')
@login_required
def secrets(name):
    return render_template("secrets.html", name=name, logged_in=True)

@app.route('/logout')
def logout():
    pass

@app.route('/download', methods=["GET"])
@login_required
def download():
    return send_from_directory("static/files", "cheat_sheet.pdf", as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)
