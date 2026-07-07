import os
import json
import random
import numpy as np
import pandas as pd
import pickle
from datetime import datetime
from functools import wraps

from flask import Flask, render_template, request, url_for, redirect, flash, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, TelField
from wtforms.validators import InputRequired, Length, ValidationError, Email, EqualTo, Optional
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv

# Try to import Flask-Dance for Google OAuth
try:
    from flask_dance.contrib.google import make_google_blueprint, google as google_oauth
    GOOGLE_OAUTH_AVAILABLE = True
except ImportError:
    GOOGLE_OAUTH_AVAILABLE = False

load_dotenv()

# ─── Load ML Model & Data ─────────────────────────────────────────────────────
with open('RandomForestRegressor.pkl', 'rb') as f:
    model = pickle.load(f)

df = pd.read_csv("Cleaned df.csv")

# ─── App Setup ────────────────────────────────────────────────────────────────
app = Flask(__name__, template_folder='templates')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'vdp-dev-secret-2025-change-me')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Google OAuth setup
if GOOGLE_OAUTH_AVAILABLE and os.environ.get("GOOGLE_CLIENT_ID"):
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # Dev only; remove in production
    google_bp = make_google_blueprint(
        client_id=os.environ.get("GOOGLE_CLIENT_ID"),
        client_secret=os.environ.get("GOOGLE_CLIENT_SECRET"),
        scope=["profile", "email"],
    )
    app.register_blueprint(google_bp, url_prefix="/auth")

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'warning'

# ─── Football Trivia ──────────────────────────────────────────────────────────
FOOTBALL_TRIVIA = [
    {"emoji": "🐐", "fact": "Lionel Messi has won 8 Ballon d'Or awards — the most in football history."},
    {"emoji": "⚽", "fact": "Cristiano Ronaldo is the all-time top scorer in men's international football with 130+ goals."},
    {"emoji": "🏆", "fact": "Brazil is the only nation to have participated in every FIFA World Cup since 1930."},
    {"emoji": "🧤", "fact": "Gianluigi Buffon played professionally for over 28 years — one of the longest careers in history."},
    {"emoji": "👑", "fact": "Pelé is the only player to have won three FIFA World Cups (1958, 1962, 1970)."},
    {"emoji": "🌍", "fact": "South Africa was the first African nation to host the FIFA World Cup in 2010."},
    {"emoji": "🎯", "fact": "Miroslav Klose holds the World Cup all-time scoring record with 16 goals across 4 tournaments."},
    {"emoji": "🦁", "fact": "Leicester City won the Premier League in 2015/16 at pre-season odds of 5000-to-1!"},
    {"emoji": "🏟️", "fact": "The Rungrado 1st of May Stadium in North Korea is the world's largest football stadium — 114,000 capacity."},
    {"emoji": "🌟", "fact": "Ronaldinho won FIFA World Player of the Year twice (2004 & 2005) and is widely considered the most skillful player ever."},
    {"emoji": "🔴", "fact": "Sir Alex Ferguson managed Manchester United for 27 years and won 38 trophies — the greatest manager of all time."},
    {"emoji": "💛", "fact": "Brazil holds the record for most World Cup wins with 5 titles (1958, 1962, 1970, 1994, 2002)."},
    {"emoji": "🎽", "fact": "The first FIFA World Cup was held in Uruguay in 1930 — Uruguay won the inaugural tournament on home soil."},
    {"emoji": "🦅", "fact": "Arsenal went the entire 2003/04 Premier League season unbeaten — earning the immortal nickname 'The Invincibles'."},
    {"emoji": "👑", "fact": "Real Madrid has won the UEFA Champions League a record 15 times as of 2024."},
    {"emoji": "🔵", "fact": "Pep Guardiola's Barcelona (2008–2012) is considered the greatest club team in football history, winning everything in sight."},
    {"emoji": "⚡", "fact": "The fastest goal ever recorded in football was scored by Nawaf Al-Abed in just 2.4 seconds in 2009."},
    {"emoji": "🌐", "fact": "Football is played in over 200 countries — making it the most popular sport on the planet."},
    {"emoji": "🏅", "fact": "Zinedine Zidane is the only man to win the UEFA Champions League 3 consecutive times as a manager (2016–2018)."},
    {"emoji": "⭐", "fact": "Ronaldo Nazário (The Phenomenon) scored 15 World Cup goals in just 19 games across three tournaments."},
    {"emoji": "🌙", "fact": "Mohamed Salah scored in 24 consecutive Premier League home games for Liverpool — a club record."},
    {"emoji": "🤩", "fact": "At 17 years, 41 days, Wayne Rooney became the youngest Premier League goalscorer in 2002 for Everton."},
    {"emoji": "🎪", "fact": "Only 6 clubs have NEVER been relegated from the Premier League since its founding in 1992."},
    {"emoji": "🦊", "fact": "Oliver Kahn is the only goalkeeper ever to win the FIFA World Cup Golden Ball award (2002)."},
    {"emoji": "🔥", "fact": "In 2020, Robert Lewandowski scored 41 Bundesliga goals in a single season — breaking Gerd Müller's 49-year-old record."},
]

# ─── Database Models ──────────────────────────────────────────────────────────
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    email = db.Column(db.String(120), nullable=True, unique=True)
    full_name = db.Column(db.String(100), nullable=True)
    phone_number = db.Column(db.String(20), nullable=True)
    password = db.Column(db.String(80), nullable=True)  # Nullable for OAuth users
    role = db.Column(db.String(10), default='fan')      # 'fan' or 'admin'
    is_active_account = db.Column(db.Boolean, default=True)
    google_id = db.Column(db.String(100), nullable=True, unique=True)
    avatar_url = db.Column(db.String(200), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    predictions = db.relationship('PredictionHistory', backref='user', lazy=True)

    def get_id(self):
        return str(self.id)


class PredictionHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    position = db.Column(db.String(20))
    overall_rating = db.Column(db.Integer)
    predicted_value = db.Column(db.Float)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    input_data = db.Column(db.Text)  # JSON string of all inputs


# ─── Forms ────────────────────────────────────────────────────────────────────
class RegisterForm(FlaskForm):
    full_name = StringField('Full Name', validators=[InputRequired(), Length(min=2, max=100)],
                            render_kw={"placeholder": "e.g. Vuyelwa Mguni", "id": "full_name"})
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)],
                           render_kw={"placeholder": "Choose a username", "id": "username"})
    email = StringField('Email Address', validators=[InputRequired(), Email()],
                        render_kw={"placeholder": "your@email.com", "id": "email", "type": "email"})
    phone_number = TelField('Phone Number', validators=[Optional(), Length(max=20)],
                            render_kw={"placeholder": "+27 XX XXX XXXX", "id": "phone_number"})
    role = SelectField('Account Type', choices=[('fan', 'Football Fan'), ('admin', 'Administrator')],
                       default='fan', id="role")
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)],
                             render_kw={"placeholder": "Min 8 characters", "id": "password"})
    confirm_password = PasswordField('Confirm Password',
                                     validators=[InputRequired(), EqualTo('password', message='Passwords must match')],
                                     render_kw={"placeholder": "Repeat your password", "id": "confirm_password"})
    submit = SubmitField('Create Account')

    def validate_username(self, username):
        if User.query.filter_by(username=username.data).first():
            raise ValidationError('That username is already taken.')

    def validate_email(self, email):
        if User.query.filter_by(email=email.data).first():
            raise ValidationError('That email is already registered.')


class LoginForm(FlaskForm):
    identifier = StringField('Email or Username', validators=[InputRequired(), Length(min=3, max=120)],
                             render_kw={"placeholder": "Email or username", "id": "identifier"})
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)],
                             render_kw={"placeholder": "Password", "id": "password"})
    submit = SubmitField('Login')


# ─── Decorators ───────────────────────────────────────────────────────────────
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


# ─── Routes ───────────────────────────────────────────────────────────────────
@app.route('/')
def home():
    trivia = random.sample(FOOTBALL_TRIVIA, min(6, len(FOOTBALL_TRIVIA)))
    return render_template('home.html', trivia=trivia)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        identifier = form.identifier.data.strip()
        user = User.query.filter(
            (User.email == identifier) | (User.username == identifier)
        ).first()
        if user and user.password and bcrypt.check_password_hash(user.password, form.password.data):
            if not user.is_active_account:
                flash('Your account has been deactivated. Please contact an administrator.', 'error')
            else:
                login_user(user)
                flash(f'Welcome back, {user.full_name or user.username}! ⚽', 'success')
                next_page = request.args.get('next')
                return redirect(next_page or url_for('dashboard'))
        else:
            flash('Invalid email/username or password. Please try again.', 'error')
    google_configured = GOOGLE_OAUTH_AVAILABLE and bool(os.environ.get("GOOGLE_CLIENT_ID"))
    return render_template('login.html', form=form, google_configured=google_configured)


@app.route('/google-login')
def google_login():
    if not GOOGLE_OAUTH_AVAILABLE or not os.environ.get("GOOGLE_CLIENT_ID"):
        flash('Google login is not yet configured. Please use email/password login or set up Google OAuth credentials.', 'warning')
        return redirect(url_for('login'))
    return redirect(url_for('google.login'))


@app.route('/auth/google/authorized')
def google_login_callback():
    if not GOOGLE_OAUTH_AVAILABLE:
        return redirect(url_for('login'))
    if not google_oauth.authorized:
        flash('Google authentication was cancelled or failed.', 'error')
        return redirect(url_for('login'))
    resp = google_oauth.get("/oauth2/v2/userinfo")
    if not resp.ok:
        flash('Failed to retrieve your Google account info.', 'error')
        return redirect(url_for('login'))
    info = resp.json()
    google_id = info["id"]
    email = info.get("email", "")
    full_name = info.get("name", "")
    avatar_url = info.get("picture", "")

    user = User.query.filter_by(google_id=google_id).first()
    if not user:
        user = User.query.filter_by(email=email).first()
        if user:
            user.google_id = google_id
            user.avatar_url = avatar_url
        else:
            base = email.split('@')[0].replace('.', '_')[:15]
            username = base
            n = 1
            while User.query.filter_by(username=username).first():
                username = f"{base}{n}"; n += 1
            user = User(username=username, email=email, full_name=full_name,
                        google_id=google_id, avatar_url=avatar_url, role='fan')
            db.session.add(user)
        db.session.commit()

    if not user.is_active_account:
        flash('Your account has been deactivated. Contact an admin.', 'error')
        return redirect(url_for('login'))
    login_user(user)
    flash(f'Welcome, {full_name or user.username}! ⚽', 'success')
    return redirect(url_for('dashboard'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = RegisterForm()
    if form.validate_on_submit():
        hashed = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(
            username=form.username.data,
            email=form.email.data,
            full_name=form.full_name.data,
            phone_number=form.phone_number.data,
            password=hashed,
            role=form.role.data
        )
        try:
            db.session.add(user)
            db.session.commit()
            flash('Account created! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred. Please try again.', 'error')
    google_configured = GOOGLE_OAUTH_AVAILABLE and bool(os.environ.get("GOOGLE_CLIENT_ID"))
    return render_template('register.html', form=form, google_configured=google_configured)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    data = {
        'overall_rating':     sorted(df['overall_rating'].unique()),
        'position':           sorted(df['position'].unique()),
        'skill_moves':        sorted(df['skill_moves'].unique()),
        'attacking_workrate': sorted(df['attacking_workrate'].unique()),
        'defensive_workrate': sorted(df['defensive_workrate'].unique()),
        'pace':               sorted(df['pace'].unique()),
        'shooting':           sorted(df['shooting'].unique()),
        'passing':            sorted(df['passing'].unique()),
        'dribbling':          sorted(df['dribbling'].unique()),
        'defending':          sorted(df['defending'].unique()),
        'physicality':        sorted(df['physicality'].unique()),
        'crossing':           sorted(df['crossing'].unique()),
        'finishing':          sorted(df['finishing'].unique()),
        'Curve':              sorted(df['Curve'].unique()),
        'freekick_accuracy':  sorted(df['freekick_accuracy'].unique()),
        'ballcontrol':        sorted(df['ballcontrol'].unique()),
        'sprint_speed':       sorted(df['sprint_speed'].unique()),
        'agility':            sorted(df['agility'].unique()),
        'reactions':          sorted(df['reactions'].unique()),
        'balance':            sorted(df['balance'].unique()),
        'shot_power':         sorted(df['shot_power'].unique()),
        'stamina':            sorted(df['stamina'].unique()),
        'aggression':         sorted(df['aggression'].unique()),
        'interceptions':      sorted(df['interceptions'].unique()),
        'positioning':        sorted(df['positioning'].unique()),
        'vision':             sorted(df['vision'].unique()),
        'composure':          sorted(df['composure'].unique()),
        'marking':            sorted(df['marking'].unique()),
    }
    trivia_fact = random.choice(FOOTBALL_TRIVIA)
    return render_template('dashboard.html', data=data, trivia=trivia_fact)


@app.route('/predict', methods=['POST'])
@login_required
def predict():
    try:
        fields = ['overall_rating', 'position', 'skill_moves', 'attacking_workrate',
                  'defensive_workrate', 'pace', 'shooting', 'passing', 'dribbling',
                  'defending', 'physicality', 'crossing', 'finishing', 'Curve',
                  'freekick_accuracy', 'ballcontrol', 'sprint_speed', 'agility',
                  'reactions', 'balance', 'shot_power', 'stamina', 'aggression',
                  'interceptions', 'positioning', 'vision', 'composure', 'marking']

        values = [request.form.get(f) for f in fields]
        prediction = model.predict([values])
        predicted_value = float(np.round(prediction[0], 2))

        # Save to history
        entry = PredictionHistory(
            user_id=current_user.id,
            position=str(request.form.get('position')),
            overall_rating=int(request.form.get('overall_rating')),
            predicted_value=predicted_value,
            input_data=json.dumps(dict(request.form))
        )
        db.session.add(entry)
        db.session.commit()

        return jsonify({'value': predicted_value,
                        'formatted': f'€ {predicted_value:,.0f}'})
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@app.route('/history')
@login_required
def history():
    predictions = PredictionHistory.query.filter_by(user_id=current_user.id)\
                    .order_by(PredictionHistory.timestamp.desc()).all()
    return render_template('history.html', predictions=predictions)


@app.route('/trivia')
def trivia():
    return render_template('trivia.html', trivia=FOOTBALL_TRIVIA)


@app.route('/admin')
@login_required
@admin_required
def admin():
    from sqlalchemy import func
    users = User.query.order_by(User.created_at.desc()).all()
    total_predictions = PredictionHistory.query.count()
    avg_value = db.session.query(func.avg(PredictionHistory.predicted_value)).scalar()
    top_pos = db.session.query(
        PredictionHistory.position,
        func.count(PredictionHistory.position).label('cnt')
    ).group_by(PredictionHistory.position)\
     .order_by(func.count(PredictionHistory.position).desc()).first()
    recent_preds = PredictionHistory.query\
                    .order_by(PredictionHistory.timestamp.desc()).limit(20).all()
    stats = {
        'total_users': User.query.count(),
        'fan_count': User.query.filter_by(role='fan').count(),
        'admin_count': User.query.filter_by(role='admin').count(),
        'active_count': User.query.filter_by(is_active_account=True).count(),
        'total_predictions': total_predictions,
        'top_position': top_pos[0] if top_pos else 'N/A',
        'avg_value': round(avg_value, 2) if avg_value else 0
    }
    return render_template('admin.html', users=users, stats=stats, recent_predictions=recent_preds)


@app.route('/admin/toggle-user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def toggle_user(user_id):
    if user_id == current_user.id:
        return jsonify({'error': 'You cannot deactivate your own account.'}), 400
    user = User.query.get_or_404(user_id)
    user.is_active_account = not user.is_active_account
    db.session.commit()
    return jsonify({'success': True,
                    'is_active': user.is_active_account,
                    'status': 'active' if user.is_active_account else 'deactivated'})


@app.route('/admin/delete-user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    if user_id == current_user.id:
        return jsonify({'error': 'You cannot delete your own account.'}), 400
    user = User.query.get_or_404(user_id)
    PredictionHistory.query.filter_by(user_id=user_id).delete()
    db.session.delete(user)
    db.session.commit()
    return jsonify({'success': True})


@app.route('/api/trivia/random')
def random_trivia_api():
    return jsonify(random.choice(FOOTBALL_TRIVIA))


@app.route('/api/check-username')
def check_username():
    username = request.args.get('username', '')
    exists = User.query.filter_by(username=username).first() is not None
    return jsonify({'available': not exists})


@app.route('/api/check-email')
def check_email():
    email = request.args.get('email', '')
    exists = User.query.filter_by(email=email).first() is not None
    return jsonify({'available': not exists})


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out. See you on the pitch! ⚽', 'info')
    return redirect(url_for('login'))


@app.errorhandler(403)
def forbidden(e):
    return render_template('error.html', code=403,
                           title="Access Denied",
                           message="You don't have permission to access this page."), 403


@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', code=404,
                           title="Page Not Found",
                           message="The page you're looking for doesn't exist."), 404


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, use_reloader=False)
