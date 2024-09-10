import numpy as np
from flask import Flask, render_template, request, url_for, redirect, flash
import pandas as pd
import pickle
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt

# Load the trained model
with open('RandomForestRegressor.pkl', 'rb') as f:
    model = pickle.load(f)

# Load the DataFrame
df = pd.read_csv("Cleaned df.csv")

app = Flask(__name__, template_folder='templates')

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Define User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


class RegisterForm(FlaskForm):
    username = StringField(validators=[
        InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
        InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')


class LoginForm(FlaskForm):
    username = StringField(validators=[
        InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
        InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    print("login code")
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash("Failed to login", 'error')
            render_template('login.html', form=form)

    return render_template('login.html', form=form)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    overall_rating = sorted(df['overall_rating'].unique())
    position = sorted(df['position'].unique())
    skill_moves = sorted(df['skill_moves'].unique())
    attacking_workrate = sorted(df['attacking_workrate'].unique())
    defensive_workrate = sorted(df['defensive_workrate'].unique())
    pace = sorted(df['pace'].unique())
    shooting = sorted(df['shooting'].unique())
    passing = sorted(df['passing'].unique())
    dribbling = sorted(df['dribbling'].unique())
    defending = sorted(df['defending'].unique())
    physicality = sorted(df['physicality'].unique())
    crossing = sorted(df['crossing'].unique())
    finishing = sorted(df['finishing'].unique())
    Curve = sorted(df['Curve'].unique())
    freekick_accuracy = sorted(df['freekick_accuracy'].unique())
    ballcontrol = sorted(df['ballcontrol'].unique())
    sprint_speed = sorted(df['sprint_speed'].unique())
    agility = sorted(df['agility'].unique())
    reactions = sorted(df['reactions'].unique())
    balance = sorted(df['balance'].unique())
    shot_power = sorted(df['shot_power'].unique())
    stamina = sorted(df['stamina'].unique())
    aggression = sorted(df['aggression'].unique())
    interceptions = sorted(df['interceptions'].unique())
    positioning = sorted(df['positioning'].unique())
    vision = sorted(df['vision'].unique())
    composure = sorted(df['composure'].unique())
    marking = sorted(df['marking'].unique())

    return render_template('dashboard.html', overall_rating=overall_rating, position=position, skill_moves=skill_moves,
                           attacking_workrate=attacking_workrate, defensive_workrate=defensive_workrate, pace=pace,
                           shooting=shooting,
                           passing=passing, dribbling=dribbling, defending=defending, physicality=physicality,
                           crossing=crossing,
                           finishing=finishing, Curve=Curve, freekick_accuracy=freekick_accuracy,
                           ballcontrol=ballcontrol, sprint_speed=sprint_speed,
                           agility=agility, reactions=reactions, balance=balance, shot_power=shot_power,
                           stamina=stamina, aggression=aggression,
                           interceptions=interceptions, positioning=positioning, vision=vision, composure=composure,
                           marking=marking)


@app.route('/predict', methods=['POST'])
def predict():
    overall_rating = int(request.form.get('overall_rating'))
    position = (request.form.get('position'))
    skill_moves = (request.form.get('skill_moves'))
    attacking_workrate = (request.form.get('attacking_workrate'))
    defensive_workrate = (request.form.get('defensive_workrate'))
    pace = (request.form.get('pace'))
    shooting = (request.form.get('shooting'))
    passing = (request.form.get('passing'))
    dribbling = (request.form.get('dribbling'))
    defending = (request.form.get('defending'))
    physicality = (request.form.get('physicality'))
    crossing = (request.form.get('crossing'))
    finishing = (request.form.get('finishing'))
    Curve = (request.form.get('Curve'))
    freekick_accuracy = (request.form.get('freekick_accuracy'))
    ballcontrol = (request.form.get('ballcontrol'))
    sprint_speed = (request.form.get('sprint_speed'))
    agility = (request.form.get('agility'))
    reactions = (request.form.get('reactions'))
    balance = (request.form.get('balance'))
    shot_power = (request.form.get('shot_power'))
    stamina = (request.form.get('stamina'))
    aggression = (request.form.get('aggression'))
    interceptions = (request.form.get('interceptions'))
    positioning = (request.form.get('positioning'))
    vision = (request.form.get('vision'))
    composure = (request.form.get('composure'))
    marking = (request.form.get('marking'))

    # Make prediction
    prediction = model.predict([[overall_rating, position, skill_moves, attacking_workrate, defensive_workrate, pace,
                                 shooting, passing, dribbling, defending, physicality, crossing, finishing, Curve,
                                 freekick_accuracy,
                                 ballcontrol, sprint_speed, agility, reactions, balance, shot_power, stamina,
                                 aggression, interceptions,
                                 positioning, vision, composure, marking]])

    # Return the prediction as a string
    return str(np.round(prediction[0], 2))


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'danger')
            print("Flashed message: Username already exists")
        else:
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            new_user = User(username=form.username.data, password=hashed_password)

            try:
                db.session.add(new_user)
                db.session.commit()
                flash('User has been successfully registered!', 'success')
                print("Flashed message: User successfully registered")
                return redirect(url_for('login'))
            except Exception as e:
                db.session.rollback()
                print(f"Error occurred: {e}")
                flash('There was an issue adding the user to the database. Please try again later.', 'danger')
                print("Flashed message: Issue adding user to database")

    return render_template('register.html', form=form)


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, use_reloader=False)
