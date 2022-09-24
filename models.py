import flask_login
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func

db = SQLAlchemy()


class User(db.Model, flask_login.UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Text, primary_key=True)
    password = db.Column(db.Text, nullable=False)
    fullname = db.Column(db.Text, nullable=False)
    credit_score = db.Column(db.Integer, nullable=False)


class Transaction(db.Model):
    __tablename__ = 'transactions'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    timestamp = db.Column(db.TIMESTAMP, nullable=False, server_default=func.now())
    from_sort_code = db.Column(db.VARCHAR(8))
    from_account_number = db.Column(db.VARCHAR(8))
    to_sort_code = db.Column(db.VARCHAR(8))
    to_account_number = db.Column(db.VARCHAR(8))
    amount = db.Column(db.Integer, nullable=False)

    __table_args__ = (
        db.ForeignKeyConstraint(
            ('from_sort_code', 'from_account_number'),
            ('bank_accounts.sort_code', 'bank_accounts.account_number'),
        ),
        db.ForeignKeyConstraint(
            ('to_sort_code', 'to_account_number'),
            ('bank_accounts.sort_code', 'bank_accounts.account_number'),
        ),
    )


class BankAccount(db.Model):
    __tablename__ = 'bank_accounts'

    username = db.Column(db.Text, db.ForeignKey('users.id'))
    sort_code = db.Column(db.VARCHAR(8), primary_key=True)
    account_number = db.Column(db.VARCHAR(8), primary_key=True)
    account_name = db.Column(db.Text, nullable=False)

    def get_balance(self):
        amount_sent = db.session.query(func.coalesce(func.sum(Transaction.amount), 0)) \
            .where(Transaction.from_sort_code == self.sort_code,
                   Transaction.from_account_number == self.account_number).scalar()

        amount_received = db.session.query(func.coalesce(func.sum(Transaction.amount), 0)) \
            .where(Transaction.to_sort_code == self.sort_code,
                   Transaction.to_account_number == self.account_number).scalar()

        return amount_received - amount_sent
