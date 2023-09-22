'''Handles routes, dictionary functions, login, registration, and logging out.

Along with the course material, there's a really good tutorial for setting these
things up on YouTube that I watched by the user Arpan Neupane:
https://www.youtube.com/watch?v=71EU8gnZqZQ&t=694s. Having never
used a database with Python before, I used almost everything he
had talked about in the video, and modified for my own needs.
'''
from datetime import datetime
import re
import logging
from secrets import token_hex
from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user
from flask_login import LoginManager, login_required, logout_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, Regexp, ValidationError, EqualTo
from passlib.hash import sha256_crypt

app = Flask(__name__)
log = logging.getLogger(__name__)

with app.app_context():
    '''Removes the default log handlers and sets the handler to the desired log level to suppress
    output from the debug and info messages.
    '''
    log_level = logging.WARNING
    default_formatter = logging.Formatter('From %(name)s %(asctime)s %(levelname)s: %(message)s')
    for handler in log.handlers:
        log.removeHandler(handler)

    warning_handler = logging.FileHandler('app_warnings.log')
    warning_handler.setFormatter(default_formatter)
    log.addHandler(warning_handler)
    log.setLevel(log_level)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///../database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
#random secure key for sessions. If the app reloads, users
#are logged out.
app.config['SECRET_KEY'] = token_hex(20)
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

def flash_errors(form):
    """Flashes form errors
    """
#Quick solution to pulling messages from forms and
#flashing messages.
#Source: https://stackoverflow.com/questions/13585663/flask-wtfform-flash-does-not-display-errors
    for field, errors in form.errors.items():
        for error in errors:
            flash(f"Error in the {field} field - {error}", "error")

@login_manager.user_loader
def load_user(user_id):
    '''Reloads the user from the database for the session.
    '''
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    '''Creates the table for the database in 3 columns.
    id, username(max 20 characters), password(max 80 characters)
    '''
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


class RegisterForm(FlaskForm):
    '''Child of FlaskForm that contains a pattern for password complexity,
    username and password fields (with validators), and a custom validator
    that gets passed to validate_on_submit() when called in the register app route.
    '''
    #Broken up into sections to keep the line short enough for the linter.
    #First section validates the requirement for a number.
    #Second section validates for a special character
    #Third section validates for a lowercase letter
    #Fourth section validates for an uppercase letter, and requires 12
    #characters.
    pw_pattern = re.compile(
        r"(?=(.*[0-9]))" +\
        r"(?=.*[\!@#$%^&*()\[\]\{\}\-_+=~`\|:;\"\'<>,./?])" +\
        r"(?=.*[a-z])" +\
        r"(?=(.*[A-Z]))(?=(.*)).{12}"
        )
    #Username field definition. Between 4 and 20 characters long, and required field.
    username = StringField(validators=[
        InputRequired(),
        Length(min=4, max=20)
        ],
        render_kw={"placeholder": "Username"})
    #Password field definition. Between 12 and 20 characters long. Also required.
    #Uses regexp to match complexity requirements and has an error messgage.
    password = PasswordField(validators=[
        InputRequired(),
        Length(min=8, max=20),
        Regexp(
            pw_pattern,
            0,
            message="Password must have at least: " +\
                "1 uppercase, 1 lowercase, 1 number, and 1 special character"
            ),
        EqualTo('confirm', message="Passwords must match")
        ],
        render_kw={"placeholder": "Password"}
    )
    confirm = PasswordField(validators=[
        InputRequired(),
        Length(min=8, max=20)
        ],
        render_kw={"placeholder": "Confirm"}
    )
    #Submit the form
    submit = SubmitField()

    def validate_username(self, field):
        '''Class method that gets passed to validate_on_submit() as a validator.
        Checks the database for an instance of the username being registered and
        raises a ValidationError if it's found.
        '''
        username_exists = User.query.filter_by(
            username=field.data).first()
        if username_exists:
            raise ValidationError(
                "That username already exists. Please choose a different one."
            )

    def validate_password(self, field):
        '''Validates password field isn't using a common password and handles password
        length requirements
        '''
        with open('commonPassword.txt', encoding='utf-8') as temp_file:
            common_passwords = [line.rstrip('\n') for line in temp_file]

        if field.data in common_passwords:
            raise ValidationError(
                "That password is too common. Try another."
            )
        if len(field.data) < 12:
            raise ValidationError(
                "Password must be at least 12 characters."
            )

class LoginForm(FlaskForm):
    '''Child of FlaskForm that just contains fields for logging in.
    No custom validation needed, since just username and password are
    being matched to the database.
    '''
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(
        min=1, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")

class PasswordResetForm(FlaskForm):
    '''Variation of the RegistrationForm. Still checks for pattern matching and handles validation,
    but field names are different.
    '''
    pw_pattern = re.compile(
        r"(?=(.*[0-9]))" +\
        r"(?=.*[\!@#$%^&*()\[\]\{\}\-_+=~`\|:;\"\'<>,./?])" +\
        r"(?=.*[a-z])" +\
        r"(?=(.*[A-Z]))(?=(.*)).{12}"
        )

    old_password = PasswordField(validators=[InputRequired(), Length(
        min=1, max=20)],
        render_kw={"placeholder": "Old Password"})
    password = PasswordField(validators=[InputRequired(), Length(
        min=1, max=20),
        Regexp(
            pw_pattern,
            0,
            message="Password must have at least: " +\
                "1 uppercase, 1 lowercase, 1 number, and 1 special character"),
        EqualTo('confirm'),
        ],
        render_kw={"placeholder": "New Password"})
    confirm = PasswordField(validators=[
        InputRequired(),
        Length(min=8, max=20)
        ],
        render_kw={"placeholder": "Confirm"})

    submit = SubmitField("Change Password")

    def validate_password(self, field):
        '''Validates password field isn't using a common password and handles password
        length requirements
        '''
        with open('commonPassword.txt', encoding='utf-8') as temp_file:
            common_passwords = [line.rstrip('\n') for line in temp_file]

        if field.data in common_passwords:
            raise ValidationError(
                "That password is too common. Try another."
            )
        if len(field.data) < 12:
            raise ValidationError(
                "Password must be at least 12 characters."
            )

@app.errorhandler(403)
def forbidden(err):
    '''Handles error routing for access control.
    '''
    return render_template('403.html', err = err)

@app.errorhandler(404)
def not_found(err):
    '''Handles error routing for page_not_found.
    '''
    return render_template('404.html', err = err)

@app.errorhandler(405)
def not_allowed(err):
    '''Handles error routing for page_not_found.
    '''
    return render_template('405.html', err = err)

@app.errorhandler(500)
def server_error(err):
    '''Handles error routing for internal server errors.
    '''
    return render_template('500.html', err = err)

@app.context_processor
def inject_date():
    '''Formats the date and time for display in the footer.
    '''
    date_time = datetime.strftime(datetime.now(), "%Y-%m-%d %H:%M:%S")
    return {'date_time': date_time}

@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    '''Creates an instance of LoginForm() and uses the validate_on_submit()
    method to determine whether to continue with login functionality. Checks
    the database for the username and corresponding password hash and redirects to
    the home page if valid. If it's not valid, redirects to login.
    '''
    form = LoginForm()
    #Form has valid data according to the validators
    if form.validate_on_submit():
        #query the database for the username to see if that matches.
        user = User.query.filter_by(username=form.username.data).first()
        #database returned a match, so check the password.
        if user:
            #Use the verify method to compare the user supplied password with the database hash.
            if sha256_crypt.verify(form.password.data, user.password):
                #finally log the user in and return the home page
                login_user(user)
                session['Username'] = form.username.data
                return redirect(url_for('index'))
        flash("Invalid username or password", "error")
        r_address = str(request.remote_addr)
        login_name = form.username.data
        log.warning(
            "Invalid login attempt from remote Address: %s Username: %s",
            r_address, login_name)
    return render_template('login.html', form=form)

@app.route('/logout', methods=['GET', 'POST'])
#Need to be logged in to log out.
@login_required
def logout():
    '''Logs the user out when selected and redirects back to the login page.
    '''
    flash("Successfully logged out!", "message")
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    '''Creates an instance of RegisterForm() and determines whether or not
    the supplied data is valid, then registers the user and redirects to the
    login page.
    '''
    form = RegisterForm()

    if form.validate_on_submit():
        #Hash the user supplied password.
        hashed_password = sha256_crypt.hash(form.password.data)
        #Create a new user entry in the table with a username and password hash
        new_user = User(username=form.username.data, password=hashed_password)
        #add and commit the changes to the db.
        db.session.add(new_user)
        db.session.commit()
        flash("Registration Successful!", "message")
        return redirect(url_for('login'))
    flash_errors(form)
    return render_template('register.html', form=form)

@app.route('/dashboard/', methods=['GET', 'POST'])
@login_required
def dashboard():
    '''All the functions required for password reset. Takes username from the session
    and uses that to reference the database. Compares the old password to the hash
    stored in the database, and if they match, allows the user to proceed with the
    reset. If the old and new password fields match, disallows the user from re-using
    the same password. Keeps the rules intact for registration, such as 1 upper, 1 lower,
    1 special char, and 12 characters. Checks against the common passwords file and
    disallows them in the password.
    '''
    #get username from session and instantiate the pwresetform.
    name = session['Username']
    form = PasswordResetForm()
    #Form has valid data according to the validators
    if form.validate_on_submit():
        #query the database for the username to see if that matches.
        user = User.query.filter_by(username=name).first()
        #database returned a match, so check the password.
        if user:
            #Use the verify method to compare the user supplied password with the database hash.
            if sha256_crypt.verify(form.old_password.data, user.password):
                if form.old_password.data == form.password.data:
                    flash("New password must be different from the old one", "error")
                else:
                    #All the conditions are met. Change the password.
                    flash("Password update successful!", "message")
                    hashed_password = sha256_crypt.hash(form.password.data)
                    user.password = hashed_password
                    db.session.commit()
            else:
                #User did not supply the correct password.
                flash("Old Password was incorrect", "error")
        else:
            #User was logged out. Session either expired, or the server reset.
            flash("Something went wrong", "error")
            return render_template('500.html')
    flash_errors(form)
    return render_template('dashboard.html', name = name, form = form)



@app.route('/index')
@login_required
def index():
    '''Default route. Goes to index.
    '''
    return render_template('index.html')


@app.route('/brew/')
@login_required
def brew():
    '''Routes to my brew page
    '''
    return render_template('brewday.html')


@app.route('/links/')
@login_required
def links():
    '''Route to show the page of links of brewing suppliers.
    '''
    return render_template('links.html', terms=get_links())


def get_links():
    '''Takes the provided list and returns a sorted dictionary.
    '''
    unsorted_links = {
        "https://www.northernbrewer.com": "Northern Brewer",
        "https://www.amazon.com/s?k=brew+supplies": "Amazon",
        "https://ballastpoint.com/location/home-brew-mart/": "Ballast Point Home Brew Mart",
        "https://www.morebeer.com": "More Beer",
        "https://www.mancrates.com/store/products/home-brewed-kit-5-gal": "Mancrates"
    }
    sorted_links = dict(sorted(unsorted_links.items()))
    return sorted_links


@app.route('/glossary/')
@login_required
def glossary():
    '''Routes to glossary page, with terms and definitions related
    to brewing.
    '''
    return render_template('glossary.html', terms=get_terms())


def get_terms():
    '''Takes the dictionary provided and returns a sorted dict for formatting
    with templates.
    '''
    unsorted_glossary = {
        "Beer": "The stuff you drink",
        "Yeast": "Microscopic fungi we use to convert sugar to alcohol",
        "Sugar Source": "Malt, Barley, or other grains that feed the yeast.",
        "Barley": "A grain",
        "Grain": "Yeast food, unprepared",
        "Malt": "A type of sugar that is ready for yeast to eat, sans-sanitation",
        "Fermentation": "The process of yeast converting sugar into different alcohols",
        "Wort": "The sweet infusion of ground malt or other grain before fermentation," +\
        " used to produce beer and distilled malt liquors",
        "Mash": "The mixture of water and grains used while steeping",
        "Sparge Water": "Water heated to bring the mash back to temperature as" +\
        " adding grains will cause the temperature of the mash to decrease.",
        "Fermentation Vessel": "Where the fermentation is taking place." +\
        "Usually in a carboy, or brew bucket",
        "Specific Gravity": "A density measurement that tells us how much" +\
        " sugar has been \"converted\"",
        "Airlock": "Prevents air from getting in the fermentation vessel." +\
        " Keeps foreign microbes out.",
        "Hops": "Impart flavor and aroma; inhibit the growth of bacteria"
    }
    sorted_glossary = dict(sorted(unsorted_glossary.items()))
    return sorted_glossary

@app.route('/brews/')
@login_required
def brews():
    '''Routes to the page showing my small amount of brewing images.
    '''
    return render_template('my_brews.html')

if __name__ == "__main__":
    app.run(debug=True)
