from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash
from flask import session

app = Flask(__name__)

app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# login config
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
#Line below only required once, when creating DB. 
# db.create_all()

@app.route('/')
def home():
    return render_template("index.html", logged_in=current_user.is_authenticated)

@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # Check if email is already in use
        if User.query.filter_by(email=request.form.get('email')).first():
            #User already exists
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))

        hash_and_salted_password = generate_password_hash(
            request.form.get('password'),
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            email=request.form.get('email'),
            name=request.form.get('name'),
            password=hash_and_salted_password,
        )
        db.session.add(new_user)
        db.session.commit()
        # Added before every login_user()
        session['logged_in'] = True
        login_user(new_user)
        return redirect(url_for("secrets"))

    return render_template("register.html", logged_in=current_user.is_authenticated)
        # new_user=User()
        # new_user.email=request.form['email']
        # new_user.name=request.form['name']
        # new_user.password=generate_password_hash(request.form['password'], method='pbkdf2:sha256', salt_length=8)
        # db.session.add(new_user)
        # db.session.commit()
        
        #Log in and authenticate user after adding details to database.
        # login_user(new_user)

        # user_name = User.query.get(new_user.id).name
        # return redirect(url_for("secrets", name=user_name))
    # return render_template("register.html")


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')
        print(email,password)
        # try:
        #Find user by email entered.
        user = User.query.filter_by(email=email).first()
        print(user.name)
        print(user.password)
        print(user.email)

        #Check if user password does not match hash on db or if user does not exist
        if user.email==email and check_password_hash(user.password, password):
            print("password and email Match")
            login_user(user)
            return redirect(url_for('secrets', name=user.name))
        
        else:
            print("Please enter correct Email/Password")
            flash("Please enter correct Email/password")

            return redirect(url_for('login'))
        
    return render_template("login.html", logged_in=current_user.is_authenticated)

# def login():
#     if request.method == "POST":
#         passw = request.form['password']
#         login_mail = request.form['email']
#         try:
#             user_data_from_db = User.query.filter_by(email=login_mail).first()
#             user_info = User(
#                 email=user_data_from_db.email,
#                 password=user_data_from_db.password,
#                 name = user_data_from_db.name)
#             compare_passw = check_password_hash(user_info.password, passw)
#             if compare_passw:
#                 return render_template("secrets.html", user=user_info)
#             else:
#                 return redirect(url_for('register'))
#         except AttributeError: # If user does not exist in DB, then no records will be found and Attribute Error will appear. So instead user will be redirected to register page.
#             return redirect(url_for('register'))
#     return render_template("login.html")

@app.route('/secrets')
@login_required
def secrets():
    print(current_user.name)
    return render_template("secrets.html", name=current_user.name, logged_in=True)
    # get_name = request.args.get("name")
    # if not get_name:
    #     user_name = None
    # user_name = get_name
    # return render_template("secrets.html", name=user_name)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/download')
@login_required
def download():
    return send_from_directory(path='cheat_sheet.pdf', directory="static/files")

if __name__ == "__main__":
    app.run(debug=True)
