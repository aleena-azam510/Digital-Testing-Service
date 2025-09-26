import os
import json
import random
from collections import defaultdict
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_migrate import Migrate
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Optional
import pymysql

# -----------------------------
# MySQLdb compatibility
# -----------------------------
pymysql.install_as_MySQLdb()

# -----------------------------
# Flask app config
# -----------------------------
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "supersecretkey")
UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# -----------------------------
# Database configuration
# -----------------------------
database_url = os.environ.get("DATABASE_URL")
db_cert = os.environ.get("MYSQL_CERT_CA")  # PEM string if hosted on Vercel

if database_url:
    connect_args = {"ssl": {"ssl_mode": "REQUIRED"}}
    if db_cert:
        ca_path = "/tmp/ca.pem"
        with open(ca_path, "w") as f:
            f.write(db_cert)
        connect_args["ssl"]["ca"] = ca_path
    app.config["SQLALCHEMY_DATABASE_URI"] = database_url
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"connect_args": connect_args}
else:
    app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://root:password@localhost/dts_db"

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config['SQLALCHEMY_ECHO'] = True

db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

# -----------------------------
# Database Models
# -----------------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default='participant')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Test(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    time_limit_minutes = db.Column(db.Integer, default=0)
    topic = db.Column(db.String(100), nullable=False, default='Uncategorized')
    difficulty = db.Column(db.String(20), nullable=False, default='easy')
    category = db.Column(db.String(50), nullable=False, default='Uncategorized')
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    questions = db.relationship('Question', backref='test', lazy=True, cascade="all, delete-orphan")
    submissions = db.relationship('Submission', lazy='dynamic', cascade="all, delete-orphan")

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    test_id = db.Column(db.Integer, db.ForeignKey('test.id'), nullable=False)
    question_text = db.Column(db.Text, nullable=False)
    is_open_ended = db.Column(db.Boolean, default=False)
    options = db.Column(db.Text)
    correct_option = db.Column(db.String(100))
    correct_answer_text = db.Column(db.Text)
    topic = db.Column(db.String(100), default='General')

class Submission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    test_id = db.Column(db.Integer, db.ForeignKey('test.id'))
    participant_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    answers = db.Column(db.Text)
    score = db.Column(db.Integer)
    ai_feedback = db.Column(db.Text)
    test = db.relationship('Test')

# -----------------------------
# Flask-Admin
# -----------------------------
admin = Admin(app, name='DTS Admin Panel', template_mode='bootstrap3')
class CustomModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.role == 'admin'
    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login', next=request.url))

admin.add_view(CustomModelView(User, db.session))
admin.add_view(CustomModelView(Test, db.session))
admin.add_view(CustomModelView(Question, db.session))
admin.add_view(CustomModelView(Submission, db.session))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# -----------------------------
# Forms
# -----------------------------
class CreateTestForm(FlaskForm):
    title = StringField('Test Title', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[Optional()])
    submit = SubmitField('Create Test')

# -----------------------------
# Helper
# -----------------------------
def get_external_resource(topic):
    resources = {
        'Python Basics': {'text': 'W3Schools Python Tutorial', 'url': 'https://www.w3schools.com/python/'},
        'List Comprehensions': {'text': 'Python List Comprehensions Explained', 'url': 'https://www.youtube.com/watch?v=AhvQk8-r0_g'},
        'Decorators': {'text': 'Real Python: Primer on Python Decorators', 'url': 'https://realpython.com/primer-on-python-decorators/'},
    }
    default_text = f"Google Search for: '{topic}' tutorial"
    default_url = f"https://www.google.com/search?q={topic.replace(' ', '+')}+tutorial"
    return resources.get(topic, {'text': default_text, 'url': default_url})

# -----------------------------
# Initialize DB & default users
# -----------------------------
with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        u = User(username='admin', role='admin'); u.set_password('adminpassword'); db.session.add(u)
    if not User.query.filter_by(username='test_creator').first():
        u = User(username='test_creator', role='creator'); u.set_password('creatorpassword123@'); db.session.add(u)
    db.session.commit()

# -----------------------------
# Routes: Home, Login, Register, Logout
# -----------------------------
@app.route('/')
def index(): return render_template('index.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('dashboard_redirect'))
    if request.method=='POST':
        username = request.form.get('username'); password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password): login_user(user); return redirect(url_for('dashboard_redirect'))
        flash('Invalid username or password', 'error')
    return render_template('login.html')

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method=='POST':
        username = request.form.get('username'); password = request.form.get('password')
        if User.query.filter_by(username=username).first(): flash('Username exists', 'error'); return redirect(url_for('register'))
        u = User(username=username, role='participant'); u.set_password(password); db.session.add(u); db.session.commit()
        flash('Registration successful', 'success'); return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout(): logout_user(); flash('Logged out', 'success'); return redirect(url_for('index'))

# -----------------------------
# Dashboard redirect by role
# -----------------------------
@app.route('/dashboard')
@login_required
def dashboard_redirect():
    if current_user.role=='admin': return redirect(url_for('admin_dashboard'))
    elif current_user.role=='creator': return redirect(url_for('creator_dashboard'))
    else: return redirect(url_for('participant_dashboard'))

@app.route('/dashboard/admin')
@login_required
def admin_dashboard():
    if current_user.role!='admin': flash("Unauthorized", 'error'); return redirect(url_for('dashboard_redirect'))
    return render_template('dashboard_admin.html',
        total_users=User.query.count(),
        total_tests=Test.query.count(),
        total_submissions=Submission.query.count(),
        admin_count=User.query.filter_by(role='admin').count(),
        creator_count=User.query.filter_by(role='creator').count(),
        participant_count=User.query.filter_by(role='participant').count()
    )

@app.route('/dashboard/creator')
@login_required
def creator_dashboard():
    if current_user.role!='creator': flash("Unauthorized", 'error'); return redirect(url_for('dashboard_redirect'))
    my_tests = Test.query.filter_by(creator_id=current_user.id).all()
    return render_template('dashboard_creator.html', my_tests=my_tests)

@app.route('/dashboard/participant')
@login_required
def participant_dashboard():
    if current_user.role!='participant': flash("Unauthorized", 'error'); return redirect(url_for('dashboard_redirect'))
    topics = [t for (t,) in Test.query.with_entities(Test.topic).distinct().all()]
    recent_subs = Submission.query.filter_by(participant_id=current_user.id).order_by(Submission.id.desc()).limit(5).all()
    return render_template('dashboard_participant.html', available_topics=topics, recent_submissions=recent_subs)

# -----------------------------
# Test creation, upload, delete
# -----------------------------
@app.route('/create_test', methods=['GET','POST'])
@login_required
def create_test():
    if current_user.role!='creator': flash("Unauthorized", 'error'); return redirect(url_for('dashboard_redirect'))
    form = CreateTestForm()
    if form.validate_on_submit():
        t = Test(title=form.title.data, description=form.description.data, creator_id=current_user.id)
        db.session.add(t); db.session.commit()
        flash('Test created', 'success'); return redirect(url_for('creator_dashboard'))
    return render_template('create_test.html', form=form)

@app.route('/delete_test/<int:test_id>', methods=['POST'])
@login_required
def delete_test(test_id):
    t = Test.query.get_or_404(test_id)
    if t.creator_id!=current_user.id: flash("Unauthorized", 'error'); return redirect(url_for('creator_dashboard'))
    db.session.delete(t); db.session.commit()
    flash("Test deleted", 'success'); return redirect(url_for('creator_dashboard'))

# -----------------------------
# JSON upload test
# -----------------------------
@app.route('/upload_json_test', methods=['GET','POST'])
@login_required
def upload_json_test():
    if current_user.role!='creator': flash("Unauthorized", 'error'); return redirect(url_for('dashboard_redirect'))
    if request.method=='POST':
        file = request.files.get('json_file')
        if file and file.filename.endswith('.json'):
            data = json.load(file)
            test = Test(title=data['title'], description=data.get('description',''), creator_id=current_user.id,
                        topic=data.get('topic','General'), difficulty=data.get('difficulty','easy'),
                        category=data.get('category','Uncategorized'))
            db.session.add(test); db.session.commit()
            for q in data.get('questions',[]):
                question = Question(
                    test_id=test.id,
                    question_text=q.get('question_text',''),
                    is_open_ended=q.get('is_open_ended',False),
                    options=json.dumps(q.get('options',[])),
                    correct_option=q.get('correct_option'),
                    correct_answer_text=q.get('correct_answer_text'),
                    topic=q.get('topic','General')
                )
                db.session.add(question)
            db.session.commit(); flash('JSON test uploaded', 'success'); return redirect(url_for('creator_dashboard'))
        flash('Invalid file', 'error')
    return render_template('upload_json_test.html')

# -----------------------------
# Take test
# -----------------------------
@app.route('/take_test/<int:test_id>', methods=['GET'])
@login_required
def take_test(test_id):
    if current_user.role!='participant': flash("Unauthorized", 'error'); return redirect(url_for('dashboard_redirect'))
    test = Test.query.get_or_404(test_id)
    questions = Question.query.filter_by(test_id=test.id).all()
    if not questions: flash("No questions found", 'error'); return redirect(url_for('participant_dashboard'))
    questions = random.sample(questions, min(20,len(questions))); random.shuffle(questions)
    return render_template('take_test.html', test=test, questions=questions, time_limit=test.time_limit_minutes)

@app.route('/submit_test/<int:test_id>', methods=['POST'])
@login_required
def submit_test(test_id):
    if current_user.role!='participant': return jsonify({'message':'Unauthorized'}), 403
    answers = request.json.get('answers', {})
    test = Test.query.get_or_404(test_id)
    questions = {q.id:q for q in test.questions}
    score = 0; feedback = {}
    for qid_str, ans in answers.items():
        try: qid=int(qid_str)
        except: continue
        q = questions.get(qid); 
        if not q: continue
        if q.is_open_ended:
            if (ans or '').strip().lower()==(q.correct_answer_text or '').strip().lower() and q.correct_answer_text: score+=1; feedback[q.id]="Correct!"
            else: feedback[q.id]="Submitted for review."
        else:
            if (ans or '').strip().lower()==(q.correct_option or '').strip().lower() and q.correct_option: score+=1; feedback[q.id]="Correct!"
            else: feedback[q.id]=f"Incorrect. Correct: {q.correct_option or 'N/A'}."
    sub = Submission(test_id=test.id, participant_id=current_user.id, answers=json.dumps(answers), score=score, ai_feedback=json.dumps(feedback))
    db.session.add(sub); db.session.commit()
    return jsonify({'message':'Test submitted','redirect_url':url_for('show_results',submission_id=sub.id)})

# -----------------------------
# Results page
# -----------------------------
@app.route('/results/<int:submission_id>')
@login_required
def show_results(submission_id):
    sub = Submission.query.get_or_404(submission_id)
    if sub.participant_id!=current_user.id: flash("Unauthorized",'error'); return redirect(url_for('participant_dashboard'))
    test = Test.query.get_or_404(sub.test_id)
    answers_data = json.loads(sub.answers or "{}"); feedback_data = json.loads(sub.ai_feedback or "{}")
    score = sub.score or 0; total_attempted=len(answers_data)
    percentage = (score/total_attempted)*100 if total_attempted else 0; passed = percentage>=60
    msg = "Good job! Keep practicing." if passed else "Needs improvement. Review weak topics."
    return render_template('results.html', submission=sub, test=test, total_attempted=total_attempted,
                           total_available=len(test.questions), score=score, percentage_score=round(percentage,1),
                           message=msg, question_feedback=feedback_data, passed=passed)

# -----------------------------
# Static pages
# -----------------------------
@app.route('/features')
def features(): 
    return render_template('features.html')
@app.route('/about')
def about():
    return render_template('about.html')
@app.route('/contact', methods=['GET','POST'])
def contact():
    if request.method=='POST': flash("Thanks for message", 'success'); return redirect(url_for('contact'))
    return render_template('contact.html')

# -----------------------------
# Run
# -----------------------------
if __name__ == '__main__':
    app.run(debug=True)
