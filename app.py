from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, DecimalField, IntegerField
from wtforms.validators import DataRequired, Email, EqualTo, NumberRange, Length

app = Flask(__name__, static_url_path='/static')
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

bcrypt = Bcrypt(app)
db = SQLAlchemy(app)

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

# Registration Form
class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

# Login Form
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# Budget Form
class BudgetForm(FlaskForm):
    income = DecimalField('Monthly Income', validators=[DataRequired(), NumberRange(min=0)])
    rent = DecimalField('Rent/Mortgage', validators=[DataRequired(), NumberRange(min=0)])
    utilities = DecimalField('Utilities', validators=[DataRequired(), NumberRange(min=0)])
    groceries = DecimalField('Groceries', validators=[DataRequired(), NumberRange(min=0)])
    savings = DecimalField('Savings Goal', validators=[DataRequired(), NumberRange(min=0)])
    other = DecimalField('Other Expenses', validators=[DataRequired(), NumberRange(min=0)])
    submit = SubmitField('Calculate Budget')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Account created successfully! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            session['user_id'] = user.id
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Login failed. Check your email and password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please log in to access the dashboard.', 'danger')
        return redirect(url_for('login'))
    return render_template('dashboard.html')

@app.route('/budget', methods=['GET', 'POST'])
def budget():
    if 'user_id' not in session:
        flash('Please log in to access the budget form.', 'danger')
        return redirect(url_for('login'))
    form = BudgetForm()
    if form.validate_on_submit():
        income = form.income.data
        total_expenses = form.rent.data + form.utilities.data + form.groceries.data + form.savings.data + form.other.data
        remaining = income - total_expenses
        return render_template('budget_result.html', income=income, total_expenses=total_expenses, remaining=remaining)
    return render_template('budget.html', form=form)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Initialize the database tables
    app.run(debug=True)
