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
    user_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(500), unique=True)
    date_joined = db.Column(db.Date, default = datetime.datetime.utcnow())
    password = db.Column(db.String(100), nullable=False)

    def __init__(self, name, email, password):
        self.name = name
        self.email = email
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))

# CREATE ALL DBs
with app.app_context():
    db.create_all()

def is_logged_in():
    return 'logged_in' in session

# HOME ROUTE
@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html', logged_in=is_logged_in())

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
            flash("Successfully Logged In!", 'success')
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
    # action = request.form.get('action')
    if request.method == 'POST':
        # if action == 'delete':
            user = User.query.filter_by(user_id=user_id).first()
            db.session.delete(user)
            db.session.commit()
            flash("User Deleted Successfully", 'danger')
            return redirect('read')
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

        user.name = updated_name
        user.email = updated_email
        user.password = updated_password

        db.session.commit()
        flash('User Details Updated Successfully!', 'success')
    return render_template("update.html", user=user)



if __name__ == "__main__":
    app.run(debug=True)