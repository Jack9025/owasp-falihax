import time
from pathlib import Path
from typing import Callable, Optional, List, Dict
import bcrypt
from flask import Flask, render_template, request, redirect, url_for, flash, session
import flask_login
import sqlite3
import random
from flask_login import current_user, login_required
from werkzeug.exceptions import BadRequestKeyError
from flask_simple_captcha import CAPTCHA

app = Flask(__name__)
app.secret_key = 'hello'

CAPTCHA_CONFIG = {'SECRET_CAPTCHA_KEY':'wMmeltW4mhwidorQRli6Oijuhygtfgybunxx9VPXldz'}
CAPTCHA = CAPTCHA(config=CAPTCHA_CONFIG)
app = CAPTCHA.init_app(app)

login_manager = flask_login.LoginManager()
navbar_page_names = dict()

BASE_DIR = Path(__file__).resolve().parent
DATABASE_FILE = BASE_DIR / "falihax.db"


class User(flask_login.UserMixin):
    """"A user class which is needed for flask_login"""
    pass


@login_manager.user_loader
def user_loader(username):
    """This tells flask_login how to reload a user object from the user ID stored in the session"""
    connection = sqlite3.connect(DATABASE_FILE)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()
    cursor.execute("select * from users where username = ?", [str(username)])
    account = cursor.fetchone()
    connection.close()
    if not account:
        return

    user = User()
    user.id = username
    return user


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


def amount_format(amount: int) -> str:
    """
    A helper function to take a signed amount in pence and render as a string.
    i.e. -15058 becomes "£150.58"
    :param amount: the signed integer amount in pence
    :return: the rendered amount string
    """
    return f"{'-' if amount < 0 else ''}£{(abs(amount) // 100):,}.{(abs(amount) % 100):02}"


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
    username = request.form.get('username')

    # Tries to retrieve a corresponding password from the DATABASE
    connection = sqlite3.connect(DATABASE_FILE)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()
    cursor.execute("select password from users where username = ?", [username])
    password_row = cursor.fetchone()
    connection.close()

    password_form = request.form.get('password')

    # Checks that the password has been retrieved and whether it matches the password entered by the user
    if password_row is not None and bcrypt.checkpw(password_form.encode('utf-8'), password_row[0]):
        # Logs the user in if the details are correct
        user = User()
        user.id = username
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
    if request.method == 'GET':
        captcha = CAPTCHA.create()
        return render_template("signup.html", captcha=captcha)

    c_hash = request.form.get('captcha-hash')
    c_text = request.form.get('captcha-text')
    if not CAPTCHA.verify(c_text, c_hash):
        captcha = CAPTCHA.create()
        flash('CAPTCHA failed.', 'danger')
        return render_template("signup.html", captcha=captcha)

    # Retrieves the username from the form
    username = request.form.get('username')

    # Tries to retrieve a user from the DATABASE with the entered username
    connection = sqlite3.connect(DATABASE_FILE)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()
    cursor.execute("select * from users where username = ?", [str(username)])
    row = cursor.fetchone()
    connection.close()

    # If a row is retrieved then the username is already taken
    if row is not None:
        flash('An account with this username already exists. Please try again.', 'warning')
        return render_template("signup.html")

    # Retrieves the password and name from the form
    password = request.form.get('password')
    password2 = request.form.get('password2')
    fullname = request.form.get('fullname')

    if password != password2:
        flash('Passwords did not match.', 'warning')
        return render_template("signup.html")

    # Inserts the new account details into the DATABASE
    connection = sqlite3.connect(DATABASE_FILE)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()
    # encrypt the password with rot-13 cryptography
    cursor.execute("insert into users (username, password, fullname) values (?, ?, ?)",
                   [username, bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()), fullname])
    connection.commit()
    connection.close()
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
        company_name = define_name_constants()['company_name']
        return render_template("open_account.html", account_names=ACCOUNT_NAMES)

    # Retrieves the account type from the form
    try:
        account = request.form.get('account')
    except BadRequestKeyError:
        account = None

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
        connection = sqlite3.connect(DATABASE_FILE)
        connection.row_factory = sqlite3.Row
        cursor = connection.cursor()
        cursor.execute("select * from bank_accounts where sort_code = ? or account_number = ?", [sort, acc])
        row = cursor.fetchone()
        connection.close()

        # If no account is found then the numbers are unique
        if row is None:
            unique = True

    # Retrieves the current user's username from the session
    user = flask_login.current_user
    username = user.id

    # Inserts the new bank account details into the DATABASE
    connection = sqlite3.connect(DATABASE_FILE)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()
    cursor.execute("insert into bank_accounts (username, sort_code, account_number, account_name) values (?,?,?,?)",
                   [username, sort, acc, account])
    connection.commit()
    connection.close()

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
    connection = sqlite3.connect(DATABASE_FILE)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()
    cursor.execute("select * from bank_accounts where sort_code = ? and account_number = ?", [sort, acc])
    row = cursor.fetchone()
    connection.close()

    # If nothing is retrieved then the details are incorrect
    if row is None:
        flash('Recipient account details are incorrect.', 'danger')
        return render_template("make_transaction.html", accounts=get_accounts(flask_login.current_user.id))

    # Retrieves the current user's username from the session
    user = flask_login.current_user
    username = user.id

    # Attempts to retrieve a bank account from the DATABASE which matches the 'from' details entered and belongs to the current user
    connection = sqlite3.connect(DATABASE_FILE)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()
    cursor.execute("select * from bank_accounts where username = ? and sort_code = ? and account_number = ?",
                   [username, usersort, useracc])
    row = cursor.fetchone()
    connection.close()

    # If nothing is retrieved then the details are incorrect
    if row is None:
        flash('"From" account details are incorrect.', 'danger')
        return render_template("make_transaction.html", accounts=get_accounts(flask_login.current_user.id))

    # Inserts the transaction details into the DATABASE
    connection = sqlite3.connect(DATABASE_FILE)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()
    cursor.execute("insert into transactions (from_sort_code, from_account_number, to_sort_code, to_account_number, "
                   "amount) values (?,?,?,?,?)", [usersort, useracc, sort, acc, amount])
    connection.commit()
    connection.close()

    flash('Transaction complete.', 'success')
    # Redirects to the transactions page
    return redirect(url_for('account', sort_code=usersort, account_number=useracc))


@app.route('/admin', methods=['GET', 'POST'])
@login_required
@add_to_navbar("Admin", condition=lambda: current_user.is_authenticated and current_user.id == "admin")
def admin():
    """Allows admins to adjust users' credit scores"""
    # Check user can access the admin page
    user = flask_login.current_user
    username = user.id
    if username != "admin":
        return render_template("error.html",
                               error_msg="You must be an admin to access this page"), 401

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
    connection = sqlite3.connect(DATABASE_FILE)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()
    cursor.execute("select * from users where username = ?", [username])
    row = cursor.fetchone()
    connection.close()

    # If nothing is retrieved then the username is incorrect
    if row is None:
        flash('User does not exist.', 'danger')
        return render_template("admin.html")

    # Updates the user's credit score in the DATABASE
    connection = sqlite3.connect(DATABASE_FILE)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()
    cursor.execute("update users set credit_score = ? where username = ?", [score, username])
    connection.commit()
    connection.close()

    flash('Credit score set successfully.', 'success')
    return render_template("admin.html")


def get_accounts(username: str) -> List[Dict[str, str]]:
    """
    A helper function to get a list of bank accounts for a particular username.
    :param username: the username of the user
    :return: a list of accounts
    """
    # Attempts to retrieve any bank accounts that belong to the user
    connection = sqlite3.connect(DATABASE_FILE)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()
    cursor.execute(
        "select sort_code, account_number, account_name from bank_accounts where username = ?", [str(username)])
    rows = cursor.fetchall()
    connection.close()

    accounts = []

    # If nothing is retrieved then the user does not have a bank account
    if rows:
        for row in rows:
            # Retrieves sort code, account number and name
            sort_code = row[0]
            account_number = row[1]
            name = row[2]

            # Adds up all transactions sent to the bank account
            connection = sqlite3.connect(DATABASE_FILE)
            connection.row_factory = sqlite3.Row
            cursor = connection.cursor()
            cursor.execute(
                "SELECT"
                "(SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE to_sort_code = ? AND to_account_number = ?)"
                "-"
                "(SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE from_sort_code = ? AND from_account_number = ?)"
                "AS total;",
                [sort_code, account_number, sort_code, account_number]
            )
            balance = amount_format(cursor.fetchone()[0])
            connection.close()

            accounts.append({
                "sort": sort_code,
                "account": account_number,
                "name": name,
                "balance": balance
            })
    return accounts


@app.route('/dashboard')
@login_required
@add_to_navbar("Dashboard", condition=lambda: current_user.is_authenticated)
def dashboard():
    """Allows the user to view their accounts"""
    username = flask_login.current_user.id
    # get the users credit score
    connection = sqlite3.connect(DATABASE_FILE)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()
    credit_score = cursor.execute("select credit_score from users where username = ?", [username]).fetchone()[0]
    connection.close()
    if not credit_score:
        credit_score = 0

    # Retrieves the current user's username from the session and gets their accounts
    return render_template("dashboard.html",
                           accounts=get_accounts(flask_login.current_user.id),
                           credit_score=credit_score)


@app.route('/account/<sort_code>/<account_number>')
@login_required
def account(sort_code: str, account_number: str):
    """Allows the user to view the statements for an account"""
    # Retrieves the current user's username from the session
    user = flask_login.current_user
    username = user.id

    # Check that user has the account that they can view
    connection = sqlite3.connect(DATABASE_FILE)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()
    cursor.execute("select * from bank_accounts where sort_code = ? and account_number = ? and username = ?",
                   [sort_code, account_number, username])
    row = cursor.fetchone()
    connection.close()

    if not row:
        return render_template("error.html",
                               error_msg="Unable to show account - Check you are logged in as correct user"), 401

    # Attempts to retrieve any bank accounts that belong to the current user
    connection = sqlite3.connect(DATABASE_FILE)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()
    cursor.execute(
        "select * from transactions where (to_account_number = ? and to_sort_code = ?) "
        "or (from_account_number = ? and from_sort_code = ?) order by timestamp desc;",
        [account_number, sort_code, account_number, sort_code])
    rows = cursor.fetchall()
    cursor.execute(
        "SELECT"
        "(SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE to_sort_code = ? AND to_account_number = ?)"
        "-"
        "(SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE from_sort_code = ? AND from_account_number = ?)"
        "AS total;",
        [sort_code, account_number, sort_code, account_number]
    )
    balance = amount_format(cursor.fetchone()[0])
    connection.close()

    transactions = []

    # For each transaction
    for table_row in rows:
        row = list(table_row)  # make it mutable
        # reverse the displayed amount if this wasn't incoming
        display_account = row[3]
        display_sort = row[2]
        if not (row[4] == sort_code and row[5] == account_number):
            row[6] *= -1
            display_account = row[5]
            display_sort = row[4]
        # store transaction info
        transactions.append({
            "id": row[0],
            "timestamp": row[1],
            # a null sort code and account number means it was a cash deposit or withdrawal
            "sort": (display_sort if display_sort else "CASH"),
            "account": (display_account if display_account else "CASH"),
            "amount": amount_format(row[6]),
            "direction": ("in" if row[6] >= 0 else "out")
        })

    return render_template("account.html", transactions=transactions, balance=balance)


if __name__ == '__main__':
    # run this code on app start
    login_manager.init_app(app)
    # run the app with debug mode on to show full error messages
    app.run(debug=True)
