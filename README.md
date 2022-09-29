<img src="static/falihax.png" width="200" alt="Falihax logo"/>

# Falihax OWASP Hackathon

## Contents
- [Introduction](#Introduction)
- [Changelog](#Changelog)
- [Getting Started](#Getting-Started)
  - [Requirements](#Requirements)
  - [Running Postgresql (optional but recommended)](#Running-postgresql-optional-but-recommended)
  - [Running the Flask application](#Running-the-Flask-application)
  - [Creating an admin account](#Creating-an-admin-account)

## Introduction
Falihax is a fictional bank created as part of a hackathon run by [CyberSoc](https://cybersoc.org.uk/), 
which was designed to include security vulnerabilities that needed to be fixed. This is a Flask application 
in Python, which allows users to open a bank account, make bank transfers and view transactions from 
bank accounts. The task was to find and fix as many security vulnerabilities as possible. 

The premise for this hackathon from CyberSoc was:
> Falihax is a brand new, 100%* real and secure banking company. Last year, they
contracted a group of computer science students to build a website for them -
unfortunately, none of these students
were [CyberSoc](https://cybersoc.org.uk/?r=falihax) members and so didn't know
how to build a web app securely.
> Recently, they have experienced a number of
attacks on their website. They are insistent that their website is very safe and
not at all vulnerable, but nevertheless they have asked you to help them improve
their security!
> **percentage expressed in binary. 4% margin of error.*

[View the original repository](https://github.com/CyberSoc-Newcastle/owasp-falihax)

## Changelog
These are the changes that have been made from the original repository:
- **General changes**
  - Updated SQL statements to avoid SQL injection
  - Added access control to: open account, view account, make transaction, admin and dashboard pages
  - Updated pages to use get method when accessed data submitted by forms
  - Changed SQL library from sqlite to SQLAlchemy
  - Added secret environment file (hide secret details from repository such as Flask key)
  - Added Postgresql support (with env file username and password to provide security)
  - Added database files to gitignore (to prevent them being pushed to repository)
  - Added CSRF token to forms


- **User management**
  - Updated password hashing to use bcrypt with salt
  - Added double check of password to signup form
  - Added an attempted login counter to prevent the user trying to log in for 5 minutes to limit failed login attempts
  - Removed login_manager.request_loader (it allowed user to pass username to form to be authenticated without password)
  - Added captcha for user signup (to prevent bots from signing up)
  - Added requirement that usernames must be between 3-16 characters and only contain letters and numbers
  - Added requirement that passwords must be at least 8 characters and contain a capital, lowercase, number and special character
  - Added specific admin role (using database column) instead of allowing user with username of 'admin' to access admin page
  - Added script to grant pre-existing user with role of admin


- **Make transaction page** 
  - Added requirement that user must be logged in to access page
  - Added validation on amount is a float and number is above 0
  - Added validation to stop account from being able to transfer money to itself


- **Open account page**
  - Added requirement that user must be logged in to access page
  - Added validation to account name to ensure that only account names defined by the server are accepted


- **View account page**
  - Added requirement that user must be logged in to access page
  - Added validation to check that account exists
  - Added validation to allow only the account owner to view transactions for the account

  
- **Dashboard page**
  - Added requirement that user must be logged in to access page


- **Admin page**
  - Added requirement that user must be logged in and has role admin to access admin page
  - Added validation of credit score is an integer and be in range of 0 and 999

## Getting Started

### Requirements
To use this application, you will need:
- Python 3.10

If using the Postgresql database provided, you will also need:
- Docker
- Docker-compose

### Creating environment file
Before attempting to run the server, you will need to create a file with the filename `.env` with the following contents:
```.env
# Keys
SECRET_FLASK_KEY="YOUR_SECRET_FLASK_KEY"
SECRET_CAPTCHA_KEY="YOUR_SECRET_CAPTCHA_KEY"
```
Replace `YOUR_SECRET_FLASK_KEY` and `YOUR_SECRET_CAPTCHA_KEY` with long random keys that contain 
a mixture of upper and lowercase letter, numbers and special characters.

### Running Postgresql (optional but recommended)
If the Postgresql database is not used, the Flask application will default to using a sqlite database.

To use Postgresql, using the docker compose file provided, add the following to your `.env` file:
```.env
# Database settings
DB_POSTGRESQL=True
DB_USER="YOUR_USERNAME"
DB_PASS="YOUR_PASSWORD"
```
Replace `YOUR_USERNAME` and `YOUR_PASSWORD` with a secure username/password combination
for the Postgresql database.

Before running the Flask application, run the following command to create/start the database:
```
docker-compose up
```

When finished with the database, run the following command to close the database:
```
docker-compose down
```

### Running the Flask application
Install the required Python libraries using the terminal command:
```
pip install -r requirements.txt
```
To run the Flask server, type in the terminal:
```
python app.py
```
In your web browser, navigate to `127.0.0.1:5000` to access the web application.

### Creating an admin account
An admin account will be able to set the credit score of users within the application. 
To create an account within the application you will need to have already created an account within
the application. (Available at: `127.0.0.1:5000/signup`)

You will need to run the admin script in terminal by running the following command and follow the 
prompt:
```
python create_admin.py
```