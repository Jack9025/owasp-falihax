import os
import random
import re
import time
from functools import wraps
from typing import Callable, Optional, List, Dict
import bcrypt
import flask_login
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import current_user, login_required
from flask_simple_captcha import CAPTCHA
from models import User, db, BankAccount, Transaction
from dotenv import load_dotenv
from flask_wtf.csrf import CSRFProtect

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

# Database
if os.getenv('DB_POSTGRESQL') == "True":
    app.config["SQLALCHEMY_DATABASE_URI"] = f"postgresql://{os.getenv('DB_USER')}:" \
                                            f"{os.getenv('DB_PASS')}@localhost:5432/falihax"
else:
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///falihax.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db.init_app(app)

# CAPTCHA
CAPTCHA_CONFIG = {'SECRET_CAPTCHA_KEY': os.getenv('SECRET_CAPTCHA_KEY')}
CAPTCHA = CAPTCHA(config=CAPTCHA_CONFIG)
app = CAPTCHA.init_app(app)

# CSRF Token
csrf = CSRFProtect()
csrf.init_app(app)

login_manager = flask_login.LoginManager()
login_manager.init_app(app)
navbar_page_names = dict()


@login_manager.user_loader
def user_loader(username):
    """This tells flask_login how to reload a user object from the user ID stored in the session"""
    return db.session.get(User, username)


@app.context_processor
def define_name_constants() -> dict:
    """
    We'll define some name constants here in case we want to change them in the future.
    The `context_processor` decorator means they're accessible to all templates/pages by default.
    They're used like any other template variable, like {{ company_name }}.

    :rtype: dict
    :return: a dictionary of name constants
    """
    return dict(company_name="Falihax",
                navbar_page_names=navbar_page_names)


def add_to_navbar(name: str, side: Optional[str] = None, condition: Optional[Callable[[], bool]] = None):
    """
    A decorator to add a page to the navbar. You don't need to edit this.
    """

    def __inner(f):
        global navbar_page_names
        navbar_page_names[name] = {"view": f,
                                   "side": (side if side else "left"),
                                   "condition": (condition if condition is not None else (lambda: True))}
        return f

    return __inner


def admin_required(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            return render_template("error.html",
                                   error_msg="You must be an admin to access this page"), 401

        return func(*args, **kwargs)

    return decorated_view


def amount_format(amount: int) -> str:
    """
    A helper function to take a signed amount in pence and render as a string.
    i.e. -15058 becomes "£150.58"
    :param amount: the signed integer amount in pence
    :return: the rendered amount string
    """
    return f"{'-' if amount < 0 else ''}£{(abs(amount) // 100):,}.{(abs(amount) % 100):02}"


def valid_username(username: str) -> bool:
    """
    Checks if a username meets the requirements of being between 3-16 characters or more in length and only
    contain letters and numbers
    :param username: username to be checked
    :return: if the username was valid
    """
    if len(username) < 3 or len(username) > 16:
        # Username must be between 3-16 characters
        return False
    elif re.search(r'[^A-Za-z0-9 ]', username):
        # Username contains characters not allowed
        return False
    else:
        return True


def valid_password(password: str) -> bool:
    """
    Checks if a password is at least 8 characters and contains at least one capital, lowercase, number and
    special character
    :param password: password to be checked
    :return: if the password was valid
    """
    if len(password) < 8:
        # Must be at least 8 characters
        return False
    elif not re.search(r'[A-Z]', password):
        # Must contain a capital
        return False
    elif not re.search(r'[a-z]', password):
        # Must contain a lower case
        return False
    elif not re.search(r'[0-9]', password):
        # Must contain a number
        return False
    elif not re.search(r'[^A-Za-z0-9]', password):
        # Must contain a special character
        return False
    else:
        return True


@app.route("/")
@add_to_navbar("Home")
def homepage():
    return render_template("home.html", title="Homepage")


@app.route("/login", methods=['GET', 'POST'])
@add_to_navbar("Login", condition=lambda: not current_user.is_authenticated, side="right")
def login():
    """Used to login a user"""
    # Returns a login form when the user navigates to the page
    if request.method == 'GET':
        return render_template("login.html")

    # Check if user had 5 failed login attempts
    if session.get('attempts', 0) >= 5:
        waiting = session.get('failed_time', 0) + 300 - time.time()
        if waiting > 0:
            # Time still remaining
            flash(f'You must wait {round(waiting)} second(s) before attempting to login again', 'danger')
            return render_template("login.html")
        else:
            # Time expired
            session['attempts'] = 0
            session['failed_time'] = 0

    # Retrieves the username from the form
    username = str(request.form.get('username', ''))

    # Tries to retrieve a corresponding password from the DATABASE
    user = db.session.get(User, username)

    password_form = str(request.form.get('password', ''))

    # Checks that the password has been retrieved and whether it matches the password entered by the user
    if user is not None and bcrypt.checkpw(password_form.encode('utf-8'), user.password):
        # Logs the user in if the details are correct
        flask_login.login_user(user)
        session['attempts'] = 0
        # Redirects to dashboard
        flash('Welcome!', 'primary')
        return redirect(url_for('dashboard'))

    # Returns a failure message if the details are incorrect and update attempt counter
    session['attempts'] = session.get('attempts', 0) + 1
    session['failed_time'] = time.time()
    if session['attempts'] == 5:
        flash('You have exceeded the number of failed login attempts. You must wait 5 minutes before trying again.',
              'danger')
    else:
        flash(f"Login failed. {5 - session['attempts']} attempt(s) remaining", 'danger')
    return render_template("login.html")


@app.route('/logout')
@login_required
@add_to_navbar("Logout", condition=lambda: current_user.is_authenticated, side="right")
def logout():
    """Used to log out a user"""
    # Logs out the current user
    flask_login.logout_user()
    flash('Goodbye!', 'primary')
    return redirect(url_for('homepage'))


@app.route('/signup', methods=['GET', 'POST'])
@add_to_navbar("Sign Up", condition=lambda: not current_user.is_authenticated, side="right")
def signup():
    """Used for creating a user account"""
    # Returns a sign up form when the user navigates to the page
    captcha = CAPTCHA.create()
    if request.method == 'GET':
        return render_template("signup.html", captcha=captcha)

    c_hash = request.form.get('captcha-hash')
    c_text = request.form.get('captcha-text')
    if not CAPTCHA.verify(c_text, c_hash):
        captcha = CAPTCHA.create()
        flash('CAPTCHA failed.', 'danger')
        return render_template("signup.html", captcha=captcha)

    # Retrieves the username from the form
    username = str(request.form.get('username', ''))

    # Tries to retrieve a user from the DATABASE with the entered username
    user = db.session.get(User, username)

    # If a row is retrieved then the username is already taken
    if user is not None:
        flash('An account with this username already exists. Please try again.', 'warning')
        return render_template("signup.html", captcha=captcha)

    # Check if username is valid
    if not valid_username(username):
        flash('Username must be between 3-16 characters long and only contain letters and numbers.', 'warning')
        return render_template("signup.html", captcha=captcha)

    # Retrieves the password and name from the form
    password = str(request.form.get('password', ''))
    password2 = str(request.form.get('password2', ''))
    fullname = str(request.form.get('fullname', ''))

    if password != password2:
        flash('Passwords did not match.', 'warning')
        return render_template("signup.html", captcha=captcha)

    if not valid_password(password):
        flash('Password did not meet requirements', 'warning')
        return render_template("signup.html", captcha=captcha)

    # Inserts the new account details into the DATABASE
    user = User()
    user.id = username
    user.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    user.fullname = fullname
    user.credit_score = 0
    db.session.add(user)
    db.session.commit()

    # Redirects to login page
    flash('Sign up successful!', 'success')
    return redirect(url_for('login'))


COMPANY_NAME = define_name_constants()['company_name']
ACCOUNT_NAMES = [
    f"{COMPANY_NAME} Super Saver",
    f"{COMPANY_NAME} Credit Card",
    f"{COMPANY_NAME} Help to Buy ISA",
    f"{COMPANY_NAME} Current Account",
    f"My First {COMPANY_NAME} Current Account (for children)",
    f"My First {COMPANY_NAME} Pension Fund (for children)"
]


@app.route('/open_account', methods=['GET', 'POST'])
@login_required
@add_to_navbar("Open an Account", condition=lambda: current_user.is_authenticated)
def open_account():
    """Used to open a bank account for the current user"""
    # Returns an account selection form when the user navigates to the page
    if request.method == 'GET':
        return render_template("open_account.html", account_names=ACCOUNT_NAMES)

    # Retrieves the account type from the form
    account = request.form.get('account')

    # Check if account name is valid
    if account not in ACCOUNT_NAMES:
        flash('Invalid account name selected.', 'danger')
        return render_template("open_account.html", account_names=ACCOUNT_NAMES)

    # Flag for sort code/account number generation
    unique = False
    while not unique:
        # Generates two numbers for the sort code
        sortnum1 = random.randrange(0, 100)
        sortnum2 = random.randrange(0, 100)

        # Creates the sort code in the correct format
        sort = "06-" + str(sortnum1).zfill(2) + "-" + str(sortnum2).zfill(2)

        # Generates a number for the account number
        accnum = random.randrange(0, 100000000)

        # Creates the account number in the correct format
        acc = str(accnum).zfill(8)

        # Tries to retrieve a bank account from the DATABASE with the same sort code or account number
        found_account = db.session.get(BankAccount, (sort, acc))

        # If no account is found then the numbers are unique
        if found_account is None:
            unique = True

    # Retrieves the current user's username from the session
    user = flask_login.current_user
    username = user.id

    # Inserts the new bank account details into the DATABASE
    new_account = BankAccount()
    new_account.username = username
    new_account.sort_code = sort
    new_account.account_number = acc
    new_account.account_name = account
    db.session.add(new_account)
    db.session.commit()

    # Redirects to homepage
    flash('Account opened successfully.', 'success')
    return redirect(url_for('account', sort_code=sort, account_number=acc))


@app.route('/make_transaction', methods=['GET', 'POST'])
@login_required
@add_to_navbar("Make Transaction", condition=lambda: current_user.is_authenticated)
def make_transaction():
    """Used to make a transaction"""
    # Returns a transaction form when the user navigates to the page
    if request.method == 'GET':
        return render_template("make_transaction.html", accounts=get_accounts(flask_login.current_user.id))

    # Retrieves the infomation from the form
    sort = request.form.get('tosortcode')
    acc = request.form.get('toaccountnumber')
    usersort = request.form.get('fromsortcode')
    useracc = request.form.get('fromaccountnumber')

    if sort == usersort and acc == useracc:
        flash('Cannot transfer money to same account', 'danger')
        return render_template("make_transaction.html", accounts=get_accounts(flask_login.current_user.id))

    # convert the amount to pence
    try:
        amount = int(float(request.form.get('amount')) * 100)
    except ValueError:
        # Invalid amount
        flash('Invalid amount to transfer given.', 'danger')
        return render_template("make_transaction.html", accounts=get_accounts(flask_login.current_user.id))

    if amount <= 0:
        flash('Amount given to transfer needs to larger than £0.', 'danger')
        return render_template("make_transaction.html", accounts=get_accounts(flask_login.current_user.id))

    # Attempts to retrieve a bank account from the DATABASE which matches the 'to' details entered
    to_account = db.session.get(BankAccount, (sort, acc))

    # If nothing is retrieved then the details are incorrect
    if to_account is None:
        flash('Recipient account details are incorrect.', 'danger')
        return render_template("make_transaction.html", accounts=get_accounts(flask_login.current_user.id))

    # Retrieves the current user's username from the session
    user = flask_login.current_user
    username = user.id

    # Attempts to retrieve a bank account from the DATABASE which matches the 'from' details entered
    from_account = db.session.get(BankAccount, (usersort, useracc))

    # If nothing is retrieved or account is not owned by user then the details are incorrect
    if from_account is None or from_account.username != username:
        flash('"From" account details are incorrect.', 'danger')
        return render_template("make_transaction.html", accounts=get_accounts(flask_login.current_user.id))

    # Inserts the transaction details into the DATABASE
    transaction = Transaction()
    transaction.from_sort_code = usersort
    transaction.from_account_number = useracc
    transaction.to_sort_code = sort
    transaction.to_account_number = acc
    transaction.amount = amount
    db.session.add(transaction)
    db.session.commit()

    flash('Transaction complete.', 'success')
    # Redirects to the transactions page
    return redirect(url_for('account', sort_code=usersort, account_number=useracc))


@app.route('/admin', methods=['GET', 'POST'])
@login_required
@admin_required
@add_to_navbar("Admin", condition=lambda: current_user.is_authenticated and current_user.is_admin)
def admin():
    """Allows admins to adjust users' credit scores"""
    # Returns a credit score form when the user navigates to the page
    if request.method == 'GET':
        return render_template("admin.html")

    # Retrieves the information from the form
    username = request.form.get('username')
    score = request.form.get('score')

    # Check credit score is integer and is between 0 and 999
    try:
        score = int(score)
    except ValueError:
        flash('Invalid credit score entered.', 'danger')
        return render_template("admin.html")

    if score > 999 or score < 0:
        flash('Credit score must be between 0 to 999', 'danger')
        return render_template("admin.html")

    # Attempts to retrieve a user from the DATABASE with the username entered
    user = db.session.get(User, username)

    # If nothing is retrieved then the username is incorrect
    if user is None:
        flash('User does not exist.', 'danger')
        return render_template("admin.html")

    # Updates the user's credit score in the DATABASE
    user.credit_score = score
    db.session.commit()

    flash('Credit score set successfully.', 'success')
    return render_template("admin.html")


def get_accounts(username: str) -> List[Dict[str, str]]:
    """
    A helper function to get a list of bank accounts for a particular username.
    :param username: the username of the user
    :return: a list of accounts
    """
    # Attempts to retrieve any bank accounts that belong to the user
    accounts = db.session.query(BankAccount).where(BankAccount.username == username)

    accounts_format = []

    # If nothing is retrieved then the user does not have a bank account
    if accounts:
        for account in accounts:
            # Adds up all transactions sent to the bank account
            balance = amount_format(account.get_balance())

            accounts_format.append({
                "sort": account.sort_code,
                "account": account.account_number,
                "name": account.account_name,
                "balance": balance
            })
    return accounts_format


@app.route('/dashboard')
@login_required
@add_to_navbar("Dashboard", condition=lambda: current_user.is_authenticated)
def dashboard():
    """Allows the user to view their accounts"""
    # Retrieves the current user's username from the session and gets their accounts
    return render_template("dashboard.html",
                           accounts=get_accounts(flask_login.current_user.id),
                           credit_score=current_user.credit_score)


@app.route('/account/<sort_code>/<account_number>')
@login_required
def account(sort_code: str, account_number: str):
    """Allows the user to view the statements for an account"""
    # Retrieves the current user's username from the session
    user = flask_login.current_user
    username = user.id

    # Check that user has the account that they can view
    account = db.session.get(BankAccount, (sort_code, account_number))

    if not account or account.username != username:
        return render_template("error.html",
                               error_msg="Unable to show account - Check you are logged in as correct user"), 401

    # Attempts to retrieve any bank accounts that belong to the current user
    transactions = db.session.query(Transaction).where(((Transaction.to_sort_code == account.sort_code) &
                                                        (Transaction.to_account_number == account.account_number)) |
                                                       ((Transaction.from_sort_code == account.sort_code) &
                                                        (Transaction.from_account_number == account.account_number))
                                                       )

    balance = amount_format(account.get_balance())

    transactions_format = []

    # For each transaction
    for transaction in transactions:
        # reverse the displayed amount if this wasn't incoming
        display_account = transaction.to_account_number
        display_sort = transaction.to_sort_code
        display_amount = transaction.amount
        if not (display_account == account_number and display_sort == sort_code):
            display_amount *= -1
            display_account = transaction.from_account_number
            display_sort = transaction.from_sort_code
        # store transaction info
        transactions_format.append({
            "id": transaction.id,
            "timestamp": transaction.timestamp,
            # a null sort code and account number means it was a cash deposit or withdrawal
            "sort": (display_sort if display_sort else "CASH"),
            "account": (display_account if display_account else "CASH"),
            "amount": amount_format(display_amount),
            "direction": ("in" if display_amount >= 0 else "out")
        })

    return render_template("account.html", transactions=transactions_format, balance=balance)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    # run this code on app start
    login_manager.init_app(app)
    # run the app with debug mode on to show full error messages
    app.run(debug=True)
