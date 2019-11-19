from flask import(Flask,Blueprint,render_template,redirect,request,flash,url_for,session,logging)
from flask_mysqldb import MySQL
import os
from passlib.hash import sha256_crypt
from wtforms import Form, StringField, TextAreaField, PasswordField, validators, SelectField,SubmitField,IntegerField
from functools import wraps

SECURITY_PASSWORD_SALT = 'my_precious_two'

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

app = Flask(__name__)

mysql = MySQL(app)

app.config['SECRET_KEY'] = 'fjfjkfkjssmdjdjdmdm'
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'eReportdb'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

@app.route("/")
def hompage():
    return render_template("index.html")

class MyForm(Form):
    firstname = StringField(u'First_Name', validators=[validators.input_required(),validators.Length(min=3, max=50)])
    lastname = StringField(u'Last_Name', validators=[validators.input_required(),validators.Length(min=3, max=50)])
    email = StringField(u'Email', validators=[validators.input_required(),validators.Length(min=3, max=50),
    validators.regexp('^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,4}$', message="email must contain mixture of alphabets,@ and numbers")])
    username = StringField(u'Username', validators=[validators.input_required(),validators.Length(min=3, max=50),
    validators.regexp('^\w+$', message="Username must contain only letters numbers or underscore")
    ])
    phone = StringField('Phone_No', validators=[validators.input_required(),validators.Length(min=11, max=11),
    validators.regexp("^[0-9*#+]+$", message="phone number should be only numbers and special characters")])
    is_admin = IntegerField("Is_admin", validators=[validators.input_required(),])
    
    password = PasswordField('Password',[
        validators.DataRequired(), 
        validators.regexp("^(?=.*?[A-Z])(?=(.*[a-z]){1,})(?=(.*[\d]){1,})(?=(.*[\W]){1,})(?!.*\s).{5,}$",message="Password should contain uppercase,lowercase,digits and special characters "),
        validators.Length(min=5,max=50,message="Password must be between 5 & 50 characters"),
       
        validators.EqualTo('confirm', message='Password do not match')
       
    ])
    confirm = PasswordField('Confirm Password')
    submit = SubmitField('Sign_Up')

@app.route("/sign_up", methods =['GET','POST'])
def sign_up():
    form = MyForm(request.form)
    if request.method == 'POST' and form.validate():
        firstname = form.firstname.data
        lastname = form.lastname.data
        email = form.email.data
        username = form.username.data
        phone = form.phone.data
        is_admin = form.is_admin.data
        password = sha256_crypt.encrypt(str(form.password.data))
        #  Create Cursor
        cur = mysql.connection.cursor()

        
        verify = cur.execute("SELECT * FROM users WHERE username=%s or email =%s",(username,email))

        if verify:
            flash("you are already registered","danger")
            return redirect(url_for('sign_in'))
          
        else:
                
            # cur.close()
            # execute Query
            cur.execute("INSERT INTO users (firstname, lastname, email, username, phone, is_admin, password)  VALUES (%s, %s, %s, %s, %s, %s, %s)", (firstname, lastname, email, username, phone, is_admin, password ))
                        
            # commit to db
            mysql.connection.commit()

            # close connection
            cur.close()
             # flash message
            flash('Thanks for registering, go ahead Sign_In','success')
            return redirect(url_for('sign_in'))


    return render_template("sign_up.html",form=form) 
 

@app.route("/sign_in", methods=["GET","POST"])   
def sign_in():
    if request.method == "POST":
        username = request.form['username'] 
        password_candidate = request.form['password']

        # creat cursor
        cur = mysql.connection.cursor()

        result = cur.execute("SELECT * FROM users WHERE username = %s",[username])

        if result:
            # get the hash
            data = cur.fetchone()
            password = data['password']
            # commit to db

            # compare passwords
            if sha256_crypt.verify(password_candidate, password):
                # app.logger.info('password matched')
                session['logged_in'] = True
                session['username'] = username
                flash('successfully logged_in','success')
                if data['is_admin']== 1:
                    return redirect(url_for("dashboard"))
                else:
                    return redirect(url_for("userdashboard"))    
            
            else:
                # app.logger.info('password mismatch')
                error='invalid login Credentials'
                return render_template("sign_in.html", error=error)
        else:
            # app.logger.info('user not found') 
            error='User not found' 
            return render_template("sign_in.html", error=error)  
    return render_template("sign_in.html")    

def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please sign_in','danger')
        return redirect(url_for('sign_in'))
    return wrap  

@app.route("/dashboard", methods=["GET","POST"])
@is_logged_in
def dashboard():
    return render_template("dashboard.html")

@app.route("/userdashboard", methods=["GET","POST"])
@is_logged_in
def userdashboard():
    return render_template("userdashboard.html")

@app.route("/logout", methods=["GET","POST"])
@is_logged_in
def logout():  
    session.clear()
    flash("succesfully logged out","success")
    return redirect(url_for("sign_in"))


      

if  __name__ == "__main__":
    app.run(debug=True)
