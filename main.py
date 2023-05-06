import flask
from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)

app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
app.app_context().push()

##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))


@app.route('/')
def home():
    return render_template("index.html")

@app.route('/register', methods=["POST", "GET"])
def register():

    if request.method == "POST":
        username_ = request.form.get("name")
        email_ = request.form.get("email")
        password_ = request.form.get("password")

        new_entry = User(
            email=email_,
            password=generate_password_hash(password_, method="pbkdf2:sha256", salt_length=8),
            name=username_
        )
        db.session.add(new_entry)
        db.session.commit()
        return redirect(url_for("secrets", name=username_))

    return render_template("register.html")


@app.route('/login')
def login():
    return render_template("login.html")


@app.route('/secrets/<name>')
def secrets(name):

    return render_template("secrets.html", name=name)

@app.route('/logout')
def logout():
    pass

@app.route('/download', methods=["GET"])
def download():
    return send_from_directory("static/files", "cheat_sheet.pdf", as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)
