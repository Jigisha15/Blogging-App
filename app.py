from flask import Flask, render_template, request, redirect, flash, url_for, session
from flask_sqlalchemy import SQLAlchemy
import datetime
import bcrypt

# initialize flask app
app = Flask(__name__)

# initialize db
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.secret_key="jigishasecretkey"
db = SQLAlchemy(app)

# USER MODEL
class User(db.Model):
    # __tablename__='Users'
    user_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(500), unique=True)
    date_joined = db.Column(db.Date, default = datetime.datetime.utcnow())
    password = db.Column(db.String(100), nullable=False)
    relation = db.relationship('Blog', backref='user', lazy=True)

    def __init__(self, name, email, password):
        self.name = name
        self.email = email
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))


class Blog(db.Model):
    # __tablename__ = 'Posts'
    blog_id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(500), nullable=False)
    blog = db.Column(db.Text, nullable=False)
    time = db.Column(db.Date, default=datetime.datetime.now)
    u_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)

    def __init__(self, blog_id, title, blog, time, u_id):
        self.blog_id = blog_id
        self.title = title
        self.blog = blog
        self.time = time
        self.u_id = u_id


# CREATE ALL DBs
with app.app_context():
    db.create_all()

def is_logged_in():
    return 'logged_in' in session

def get_logged_in_user():
    if 'logged_in' in session and 'email' in session:
        return {'email': session['email'], 'name': session['name']}
    return None

#  Use a context processor to pass logged_in status to all templates
@app.context_processor
def inject_user():
    return dict(logged_in=is_logged_in(), user=get_logged_in_user())

# HOME ROUTE
@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html')

# CREATE
@app.route('/register', methods=['GET', 'POST'])
def register():
    user = None
    print(user)
    if request.method == 'POST':
        name=request.form['name']
        email=request.form['email']
        password=request.form['password']

        user = User(name=name, email=email, password=password)
        db.session.add(user)
        db.session.commit()
        flash("User Created Successfully!", "success")
    return render_template('register.html')

# LOGIN
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()

        if email and user.check_password(password):
            session['logged_in'] = True
            session['email'] = user.email
            session['name'] = user.name
            # flash("Successfully Logged In!", 'success')
            return redirect('dashboard')
        else:
            flash('Invalid Credentials', 'danger')
    return render_template('login.html')

# LOGOUT
@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    flash('Logged out', 'success')
    return redirect('login')

# READ
@app.route('/read', methods=['GET', 'POST'])
def read():
    data = User.query.all()
    if request.method == 'POST':
        user_id = request.form.get('update')
        if user_id:
            return redirect(url_for('update', user_id=user_id))
    return render_template('read.html', data=data)

# DELETE
@app.route('/delete', methods=['GET', 'POST'])
def delete():
    user_id = request.form.get('delete')
    if request.method == 'POST':
            user = User.query.filter_by(user_id=user_id).first()
            db.session.delete(user)
            db.session.commit()
            session.clear()
            flash("User Deleted Successfully", 'danger')
            return redirect('register')
    return "delete"

# UPDATE
@app.route('/update', methods=['GET', 'POST'])
def update():
    user_id = request.args.get('user_id')
    user = User.query.filter_by(user_id=user_id).first()

    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('read'))

    if request.method =='POST':
        updated_name = request.form['uname']
        updated_email = request.form['uemail']
        updated_password = request.form['upassword']
        hashed_password  = bcrypt.hashpw(updated_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        user.name = updated_name
        user.email = updated_email
        user.password = hashed_password

        db.session.commit()
        flash('User Details Updated Successfully!', 'success')
    return render_template("update.html", user=user)

# DASHBOARD
@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

# ABOUT US
@app.route('/aboutus')
def aboutus():
    return render_template('aboutus.html')

# PROFILE
@app.route('/profile')
def profile():
    if get_logged_in_user():
        user = User.query.filter_by(email=session['email']).first()
        return render_template('profile.html', user=user)
    return render_template('profile.html')

if __name__ == "__main__":
    app.run(debug=True)