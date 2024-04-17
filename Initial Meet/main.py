# Import necessary modules from flask
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, EmailField
from wtforms.validators import DataRequired, Length, Regexp
from flask_sqlalchemy import SQLAlchemy
from flask_login import login_user, LoginManager, login_required, current_user, logout_user

# Initialize SQLAlchemy
db = SQLAlchemy()

# Initialize Flask
app = Flask(__name__)

# Configure Flask app
app.config['SECRET_KEY'] = "mystery-key"
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///initial-meet.db"

# Initialize SQLAlchemy with this Flask app
db.init_app(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

# User loader callback for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return Register.query.get(int(user_id))

# Define User model
class Register(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(50), unique=True, nullable=False)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

    def is_active(self):
        return True
    
    def get_id(self):
        return str(self.id)
    
    def is_authenticated(self):
        return True

# Create all database tables
with app.app_context():
    db.create_all()

# Define RegistrationForm
class RegistrationForm(FlaskForm):
    email = EmailField(label='Email', validators=[DataRequired()])
    username = StringField(label="Username", validators=[DataRequired(), Length(min=3, max=20)])
    password = PasswordField(label="Password", validators=[DataRequired(), Length(min=8, max=120), Regexp('^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$',
               message="Password should have at least one uppercase letter, one lowercase letter, one number, and one special character")])

# Define LoginForm
class LoginForm(FlaskForm):
    email = EmailField(label='Email', validators=[DataRequired()])
    password = PasswordField(label="Password", validators=[DataRequired()])

# Define route for homepage
@app.route("/")
def home():
    return redirect(url_for("login"))

# Define route for login page
@app.route("/login", methods=["POST", "GET"])
def login():
    form = LoginForm()
    if request.method == "POST" and form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = Register.query.filter_by(email=email, password=password).first()
        if user:
            login_user(user)
            return redirect(url_for("dashboard"))
        
    return render_template("login.html", form=form)

# Define route for logout
@app.route("/logout", methods=["GET"])
@login_required
def logout():
    logout_user()
    flash("You have been logged out successfully! Thank you for using Initial Meet!", "info")
    return redirect(url_for("login"))

# Define route for registration page
@app.route("/register", methods=["POST", "GET"])
def register():
    form = RegistrationForm()
    if request.method == "POST" and form.validate_on_submit():
        new_user = Register(
            email = form.email.data,
            username = form.username.data,
            password = form.password.data
        )
        db.session.add(new_user)
        db.session.commit()
        flash("Account created Successfully! <br>Now you can log in.", "success")
        return redirect(url_for("login"))
    else:
            for field, errors in form.errors.items():
                for error in errors:
                    flash(f"{error}", "danger")


    return render_template("register.html", form=form)

# Define route for dashboard
@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", username=current_user.username)

# Define route for meeting
@app.route("/meeting")
@login_required
def meeting():
    return render_template("meeting.html", username=current_user.username)

# Define route for join
@app.route("/join", methods=['GET', 'POST'])
@login_required
def join():
    if request.method == "POST":
        room_id = request.form.get("roomID")
        return redirect(f"/meeting?roomID={room_id}")
    return render_template("join.html")

# Run the Flask app
if __name__ == "__main__":
    app.run(debug=True)
