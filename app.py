import os
import json
import joblib
import numpy as np
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from collections import defaultdict
from werkzeug.utils import secure_filename
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_migrate import Migrate
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Optional
import pymysql

# This is a crucial line for some environments, let's keep it.
pymysql.install_as_MySQLdb()

# Load environment variables from .env file
load_dotenv()

# ==============================================================================
# APP AND DATABASE CONFIGURATION
# ==============================================================================
app = Flask(__name__)

# Register the custom filter
def from_json_filter(value):
    """Jinja2 filter to load a JSON string."""
    if value:
        return json.loads(value)
    return {}

app.jinja_env.filters['from_json'] = from_json_filter

# ==============================================================================
# CONDITIONAL DATABASE CONFIGURATION
# ==============================================================================
database_url = os.environ.get('DATABASE_URL')
db_cert = os.environ.get('MYSQL_CERT_CA') # Added to get the certificate content from Vercel

if database_url:
    # Aiven requires the SSL certificate content to be passed in the connection arguments.
    # We create a dictionary to hold the arguments.
    connect_args = {
        'ssl': {
            'ssl_mode': 'REQUIRED'
        }
    }
    
    # If the certificate environment variable exists, add it to the connect_args.
    if db_cert:
        # The 'ca' key is used to pass the certificate authority content.
        connect_args['ssl']['ca'] = db_cert

    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {'connect_args': connect_args}

else:
    # Fallback for local development
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:password@localhost/dts_db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Initialize the SQLAlchemy object after setting the config
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'



# ==============================================================================
# DATABASE MODELS
# ==============================================================================
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
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(500), nullable=True)
    category = db.Column(db.String(50), nullable=False, default='Uncategorized')
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'))
class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    test_id = db.Column(db.Integer, db.ForeignKey('test.id'))
    question_text = db.Column(db.Text, nullable=False)
    is_open_ended = db.Column(db.Boolean, default=False)
    options = db.Column(db.Text)
    correct_option = db.Column(db.String(100))
    correct_answer_text = db.Column(db.Text)

class Submission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    test_id = db.Column(db.Integer, db.ForeignKey('test.id'))
    participant_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    answers = db.Column(db.Text)
    score = db.Column(db.Integer)
    ai_feedback = db.Column(db.Text)

# ==============================================================================
# FLASK-ADMIN AND FLASK-LOGIN SETUP
# ==============================================================================
admin = Admin(app, name='DTS Admin Panel', template_mode='bootstrap3')
class CustomModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.role == 'admin'

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login'))

admin.add_view(CustomModelView(User, db.session))
admin.add_view(CustomModelView(Test, db.session))
admin.add_view(CustomModelView(Question, db.session))
admin.add_view(CustomModelView(Submission, db.session))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ==============================================================================
# FLASK FORMS
# ==============================================================================
class CreateTestForm(FlaskForm):
    title = StringField('Test Title', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[Optional()])
    submit = SubmitField('Create Test')

# ==============================================================================
# ROUTES
# ==============================================================================
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard_redirect'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard_redirect'))
        else:
            flash('Invalid username or password', 'error')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = 'participant'
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'error')
            return redirect(url_for('register'))
        new_user = User(username=username, role=role)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard_redirect():
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    elif current_user.role == 'creator':
        return redirect(url_for('creator_dashboard'))
    else:
        return redirect(url_for('participant_dashboard'))

@app.route('/dashboard/admin')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash("Unauthorized access.", 'error')
        return redirect(url_for('dashboard_redirect'))
    total_users = User.query.count()
    total_tests = Test.query.count()
    total_submissions = Submission.query.count()
    admin_count = User.query.filter_by(role='admin').count()
    creator_count = User.query.filter_by(role='creator').count()
    participant_count = User.query.filter_by(role='participant').count()
    return render_template('dashboard_admin.html',
                            total_users=total_users,
                            total_tests=total_tests,
                            total_submissions=total_submissions,
                            admin_count=admin_count,
                            creator_count=creator_count,
                            participant_count=participant_count)

@app.route('/dashboard/creator')
@login_required
def creator_dashboard():
    if current_user.role != 'creator':
        flash("Unauthorized access.", 'error')
        return redirect(url_for('dashboard_redirect'))
    my_tests = Test.query.filter_by(creator_id=current_user.id).all()
    return render_template('dashboard_creator.html', my_tests=my_tests)

class CreateTestForm(FlaskForm):
    title = StringField('Test Title', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[Optional()])
    submit = SubmitField('Create Test')

@app.route('/create_test', methods=['GET', 'POST'])
@login_required
def create_test():
    if current_user.role != 'creator':
        flash("Unauthorized access.", "error")
        return redirect(url_for('dashboard_redirect'))
    form = CreateTestForm()
    if form.validate_on_submit():
        new_test = Test(
            title=form.title.data,
            description=form.description.data,
            creator_id=current_user.id
        )
        db.session.add(new_test)
        db.session.commit()
        flash('Test created successfully!', 'success')
        return redirect(url_for('creator_dashboard'))
    return render_template('create_test.html', form=form)

@app.route('/upload_json_test', methods=['GET', 'POST'])
@login_required
def upload_json_test():
    if current_user.role != 'creator':
        flash("Unauthorized access.", "error")
        return redirect(url_for('dashboard_redirect'))
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'error')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'error')
            return redirect(request.url)
        if file and file.filename.endswith('.json'):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            if not os.path.exists(app.config['UPLOAD_FOLDER']):
                os.makedirs(app.config['UPLOAD_FOLDER'])
            file.save(filepath)
            try:
                with open(filepath, 'r') as json_file:
                    data = json.load(json_file)
                if 'test_title' not in data or 'questions' not in data:
                    flash("Invalid JSON format. 'test_title' and 'questions' are required.", 'error')
                    return redirect(request.url)
                test_title = data['test_title']
                questions_data = data['questions']

                # The description field is already handled here.
                # It reads the 'test_description' field from the JSON.
                test_description = data.get('test_description', '')

                new_test = Test(
                    creator_id=current_user.id,
                    title=test_title,
                    description=test_description  # <-- This line already uses the description
                )
                db.session.add(new_test)
                db.session.commit()

                for q_data in questions_data:
                    is_open_ended = q_data.get('is_open_ended', False)
                    if is_open_ended:
                        new_question = Question(
                            test_id=new_test.id,
                            question_text=q_data['question_text'],
                            is_open_ended=True,
                            correct_answer_text=q_data.get('correct_answer_text')
                        )
                    else:
                        options = json.dumps(q_data.get('options', {}))
                        correct_option = q_data.get('correct_option')
                        new_question = Question(
                            test_id=new_test.id,
                            question_text=q_data['question_text'],
                            is_open_ended=False,
                            options=options,
                            correct_option=correct_option
                        )
                    db.session.add(new_question)
                db.session.commit()
                flash("Test created successfully from JSON file!", "success")
                return redirect(url_for('creator_dashboard'))
            except json.JSONDecodeError:
                flash('Invalid JSON file.', 'error')
                db.session.rollback()
                return redirect(request.url)
            except Exception as e:
                db.session.rollback()
                flash(f'An error occurred: {e}', 'error')
                return redirect(request.url)
    return render_template('upload_json_test.html')

@app.route('/delete_test/<int:test_id>', methods=['POST'])
@login_required
def delete_test(test_id):
    test = Test.query.get_or_404(test_id)
    if test.creator_id != current_user.id:
        flash("Unauthorized access.", "error")
        return redirect(url_for('creator_dashboard'))
    Question.query.filter_by(test_id=test_id).delete()
    Submission.query.filter_by(test_id=test_id).delete()
    db.session.delete(test)
    db.session.commit()
    flash("Test and all associated data have been deleted.", "success")
    return redirect(url_for('creator_dashboard'))

@app.route('/dashboard/participant')
@login_required
def participant_dashboard():
    if current_user.role != 'participant':
        flash("Unauthorized access.", 'error')
        return redirect(url_for('dashboard_redirect'))
    all_tests = Test.query.all()
    return render_template('dashboard_participant.html', all_tests=all_tests)

@app.route('/take_test/<int:test_id>', methods=['GET'])
@login_required
def take_test(test_id):
    if current_user.role != 'participant':
        flash("Unauthorized access.", 'error')
        return redirect(url_for('dashboard_redirect'))
    test = Test.query.get_or_404(test_id)
    questions = Question.query.filter_by(test_id=test_id).all()
    return render_template('take_test.html', test=test, questions=questions)

@app.route('/submit_test/<int:test_id>', methods=['POST'])
@login_required
def submit_test(test_id):
    if current_user.role != 'participant':
        return jsonify({'message': 'Unauthorized'}), 403
    answers = request.json.get('answers', {})
    test = Test.query.get_or_404(test_id)
    questions = Question.query.filter_by(test_id=test_id).all()
    total_score = 0
    feedback = {}
    for q in questions:
        submitted_answer = answers.get(str(q.id))
        if not submitted_answer:
            feedback[q.id] = "No answer provided."
            continue
        if q.is_open_ended:
            correct_text = q.correct_answer_text.strip().lower()
            submitted_text = submitted_answer.strip().lower()
            if submitted_text == correct_text:
                total_score += 1
                feedback[q.id] = "AI: Your answer seems to be correct."
            else:
                feedback[q.id] = "AI: Your answer needs more detail."
        else:
            if submitted_answer == q.correct_option:
                total_score += 1
                feedback[q.id] = "Correct."
            else:
                feedback[q.id] = "Incorrect."
    new_submission = Submission(
        test_id=test_id,
        participant_id=current_user.id,
        answers=json.dumps(answers),
        score=total_score,
        ai_feedback=json.dumps(feedback)
    )
    db.session.add(new_submission)
    db.session.commit()
    return jsonify({
        'message': 'Test submitted successfully!',
        'score': total_score,
        'redirect_url': url_for('show_results', submission_id=new_submission.id)
    })

@app.route('/results/<int:submission_id>')
@login_required
def show_results(submission_id):
    submission = Submission.query.get_or_404(submission_id)
    if submission.participant_id != current_user.id:
        flash("You do not have permission to view this submission.", "error")
        return redirect(url_for('dashboard_participant'))
    test = Test.query.get_or_404(submission.test_id)
    questions = Question.query.filter_by(test_id=test.id).all()
    return render_template('results.html', submission=submission, test=test, questions=questions)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

@app.route('/features')
def features():
    return render_template('features.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        flash("Thank you for your message! We'll get back to you shortly.", 'success')
        return redirect(url_for('contact'))
    return render_template('contact.html')

if __name__ == '__main__':
    with app.app_context():
        # db.create_all()  # <-- Comment this out before deployment
        pass  # <-- Add a pass statement to keep the code valid
    app.run(debug=True)