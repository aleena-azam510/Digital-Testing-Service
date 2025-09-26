import os
import json
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
@app.template_filter('from_json')
def from_json_filter(value):
    try:
        return json.loads(value)
    except Exception:
        return {}

app.secret_key = os.environ.get("SECRET_KEY", "supersecretkey")

UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# -----------------------------
# Database configuration
# -----------------------------
database_url = os.environ.get("DATABASE_URL")
db_cert = os.environ.get("MYSQL_CERT_CA")  # PEM string from Vercel

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
app.config['SQLALCHEMY_ECHO'] = True  # logs all SQL queries
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
    submissions = db.relationship('Submission', lazy='dynamic')

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
# Flask Forms
# -----------------------------
class CreateTestForm(FlaskForm):
    title = StringField('Test Title', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[Optional()])
    submit = SubmitField('Create Test')

# -----------------------------
# Helper Functions
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
# Create tables & default users
# -----------------------------
with app.app_context():
    db.create_all()
    
    # Default admin
    if not User.query.filter_by(username='admin').first():
        admin_user = User(username='admin', role='admin')
        admin_user.set_password('adminpassword')  # Change in production
        db.session.add(admin_user)
        print("Default admin user created")
    
    # Default creator
    if not User.query.filter_by(username='test_creator').first():
        creator_user = User(username='test_creator', role='creator')
        creator_user.set_password('creatorpassword123@')  # Change in production
        db.session.add(creator_user)
        print("Default creator user created")
    
    # Temporary superadmin for testing
    if not User.query.filter_by(username='superadmin').first():
        super_admin = User(username='superadmin', role='admin')
        super_admin.set_password('adminpassword')
        db.session.add(super_admin)
        print("Temporary superadmin user created for testing")
    
    db.session.commit()

# -----------------------------
# Routes (Login, Register, Dashboards, Tests)
# -----------------------------
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

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard_redirect():
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    elif current_user.role == 'creator':
        return redirect(url_for('creator_dashboard'))
    else:
        return redirect(url_for('participant_dashboard'))

# -----------------------------
# Admin Dashboard
# -----------------------------
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

# -----------------------------
# Creator Dashboard
# -----------------------------
@app.route('/dashboard/creator')
@login_required
def creator_dashboard():
    if current_user.role != 'creator':
        flash("Unauthorized access.", 'error')
        return redirect(url_for('dashboard_redirect'))
    my_tests = Test.query.filter_by(creator_id=current_user.id).all()
    return render_template('dashboard_creator.html', my_tests=my_tests)

# -----------------------------
# Participant Dashboard
# -----------------------------
from sqlalchemy.orm import joinedload

@app.route('/dashboard/participant')
@login_required
def participant_dashboard():
    if current_user.role != 'participant':
        flash("Unauthorized access.", 'error')
        return redirect(url_for('dashboard_redirect'))

    raw_available_topics = Test.query.with_entities(Test.topic) \
                              .filter(Test.topic != '') \
                              .distinct() \
                              .all()
    available_topics = [topic for (topic,) in raw_available_topics]

    recent_submissions = Submission.query.filter_by(participant_id=current_user.id) \
        .options(joinedload(Submission.test)) \
        .order_by(Submission.id.desc()) \
        .limit(5).all()

    return render_template('dashboard_participant.html',
                           available_topics=available_topics,
                           recent_submissions=recent_submissions)

# -----------------------------
# Create / Upload / Delete Test
# -----------------------------
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
        flash('Test created successfully! Now add questions (ideally using the JSON upload).', 'success')
        return redirect(url_for('creator_dashboard'))
    return render_template('create_test.html', form=form)

@app.route('/delete_test/<int:test_id>', methods=['POST'])
@login_required
def delete_test(test_id):
    test = Test.query.get_or_404(test_id)
    if test.creator_id != current_user.id:
        flash("Unauthorized access.", "error")
        return redirect(url_for('creator_dashboard'))
    db.session.delete(test)
    db.session.commit()
    flash("Test and all associated data have been deleted.", "success")
    return redirect(url_for('creator_dashboard'))

# -----------------------------
# JSON Upload Route
# -----------------------------
@app.route('/upload_json_test', methods=['GET', 'POST'])
@login_required
def upload_json_test():
    if current_user.role != 'creator':
        flash("Unauthorized access.", "error")
        return redirect(url_for('dashboard_redirect'))
        
    if request.method == 'POST':
        if 'file' not in request.files or not request.files['file'].filename:
            flash('No JSON file selected.', 'danger')
            return redirect(request.url) 
        
        file = request.files['file']
        if not file.filename.endswith('.json'):
            flash('Invalid file type. Please upload a JSON file.', 'danger')
            return redirect(request.url)

        try:
            json_data = json.loads(file.read())
            required_test_fields = ['title', 'questions', 'topic', 'difficulty']
            if not all(k in json_data for k in required_test_fields):
                flash('JSON must contain "title", "questions", "topic", and "difficulty" fields.', 'danger')
                return redirect(request.url)

            existing_test = Test.query.filter_by(
                topic=json_data['topic'], 
                difficulty=json_data['difficulty']
            ).first()
            
            if existing_test:
                flash(f'A test for Topic: "{json_data["topic"]}" at Difficulty: "{json_data["difficulty"]}" already exists.', 'warning')
                return redirect(request.url)

            new_test = Test(
                creator_id=current_user.id,
                title=json_data['title'],
                description=json_data.get('description', 'No description provided.'),
                time_limit_minutes=json_data.get('time_limit_minutes', 0), 
                topic=json_data['topic'],
                difficulty=json_data['difficulty']
            )
            db.session.add(new_test)
            db.session.commit()

            questions_to_add = []
            for q_data in json_data['questions']:
                q_type = q_data.get('type', 'mcq').lower()
                is_open_ended = (q_type == 'open_ended')

                options_data = {}
                correct_option = ''
                correct_answer_text = ''
                
                if not is_open_ended:
                    options_data = q_data.get('options', {})
                    correct_option = q_data.get('correct_answer', '')
                else:
                    correct_answer_text = q_data.get('correct_answer_text', '')

                new_question = Question(
                    test_id=new_test.id,
                    question_text=q_data['text'],
                    is_open_ended=is_open_ended,
                    options=json.dumps(options_data), 
                    correct_option=correct_option,
                    correct_answer_text=correct_answer_text,
                    topic=q_data.get('topic', json_data['topic'])
                )
                questions_to_add.append(new_question)

            db.session.add_all(questions_to_add)
            db.session.commit()

            flash(f'Test "{new_test.title}" ({new_test.difficulty}) uploaded successfully with {len(questions_to_add)} questions!', 'success')
            return redirect(url_for('creator_dashboard'))

        except json.JSONDecodeError:
            db.session.rollback()
            flash('Invalid JSON format in the uploaded file. Please check for syntax errors.', 'danger')
            return redirect(request.url)
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred during processing. Error: {str(e)}', 'danger')
            return redirect(request.url)

    return render_template('upload_json_test.html')


# Delete Test
@app.route('/delete_test/<int:test_id>', methods=['POST'])
@login_required
def delete_test(test_id):
    test = Test.query.get_or_404(test_id)
    if test.creator_id != current_user.id:
        flash("Unauthorized access.", 'error')
        return redirect(url_for('creator_dashboard'))
    Question.query.filter_by(test_id=test_id).delete()
    Submission.query.filter_by(test_id=test_id).delete()
    db.session.delete(test)
    db.session.commit()
    flash("Test and all associated data have been deleted.", "success")
    return redirect(url_for('creator_dashboard'))

# Take Test
@app.route('/take_test/<int:test_id>', methods=['GET'])
@login_required
def take_test(test_id):
    if current_user.role != 'participant':
        flash("Unauthorized access.", 'error')
        return redirect(url_for('dashboard_redirect'))
    test = Test.query.get_or_404(test_id)
    questions = Question.query.filter_by(test_id=test_id).all()
    return render_template('take_test.html', test=test, questions=questions)

# Submit Test
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
            correct_text = (q.correct_answer_text or "").strip().lower()
            submitted_text = submitted_answer.strip().lower()
            if submitted_text == correct_text:
                total_score += 1
                feedback[q.id] = "AI: Your answer seems correct."
            else:
                feedback[q.id] = "AI: Your answer needs more detail."
        else:
            if submitted_answer == q.correct_option:
                total_score += 1
                feedback[q.id] = "Correct."
            else:
                feedback[q.id] = "Incorrect."
    new_submission = Submission(test_id=test_id,
                                participant_id=current_user.id,
                                answers=json.dumps(answers),
                                score=total_score,
                                ai_feedback=json.dumps(feedback))
    db.session.add(new_submission)
    db.session.commit()
    return jsonify({'message': 'Test submitted successfully!',
                    'score': total_score,
                    'redirect_url': url_for('show_results', submission_id=new_submission.id)})

from sqlalchemy.orm import joinedload 
# ... (other imports) ...

# --- UPDATED PARTICIPANT DASHBOARD ROUTE ---
@app.route('/dashboard/participant')
@login_required
def participant_dashboard():
    if current_user.role != 'participant':
        flash("Unauthorized access.", 'error')
        return redirect(url_for('dashboard_redirect'))
        
    # Get unique topics
    raw_available_topics = Test.query.with_entities(Test.topic) \
                              .filter(Test.topic != '') \
                              .distinct() \
                              .all()
    available_topics = [topic for (topic,) in raw_available_topics]

    # Recent submissions
    recent_submissions = Submission.query.filter_by(participant_id=current_user.id) \
        .options(joinedload(Submission.test)) \
        .order_by(Submission.id.desc()) \
        .limit(5).all()

    return render_template(
        'dashboard_participant.html',
        available_topics=available_topics,
        recent_submissions=recent_submissions
    )


@app.route('/dashboard/topic/<topic>')
@login_required
def topic_detail(topic):
    if current_user.role != 'participant':
        flash("Unauthorized access.", 'error')
        return redirect(url_for('dashboard_redirect'))

    # Fetch tests for this topic (all difficulties)
    tests = Test.query.filter_by(topic=topic).all()

    if not tests:
        flash("No tests available for this topic yet.", "warning")

    return render_template(
        'topic_detail.html',
        topic=topic,
        tests=tests
    )


# -------------------------------------------

# --- NEW ROUTE to START the TEST based on selection ---
@app.route('/start_test/<string:topic>/<string:difficulty_level>', methods=['GET'])
@login_required
def start_test(topic, difficulty_level):
    if current_user.role != 'participant':
        flash("Unauthorized access.", 'error')
        return redirect(url_for('dashboard_redirect'))
        
    # Find the specific test instance defined by the unique topic and difficulty
    test_to_start = Test.query.filter_by(topic=topic, difficulty=difficulty_level).first()
    
    if test_to_start:
        # Redirect to the main 'take_test' route using the test's ID
        return redirect(url_for('take_test', test_id=test_to_start.id))
    else:
        flash(f'No test found for Topic: {topic} at {difficulty_level} difficulty.', 'danger')
        return redirect(url_for('participant_dashboard'))
# ------------------------------------------------------


# --- UPDATED TAKE TEST ROUTE (SIMPLIFIED QUESTION SELECTION) ---
@app.route('/take_test/<int:test_id>', methods=['GET'])
@login_required
def take_test(test_id):
    if current_user.role != 'participant':
        flash("Unauthorized access.", 'error')
        return redirect(url_for('dashboard_redirect'))
    
    # Get the test by ID
    test = Test.query.get_or_404(test_id)

    TARGET_QUESTIONS = 20
    
    # Get all questions for this test
    questions_pool = Question.query.filter_by(test_id=test.id).all()
    
    if not questions_pool:
        flash("No questions found for this test.", "error")
        return redirect(url_for("topic_detail", topic=test.topic))
    
    # Select up to TARGET_QUESTIONS questions
    if len(questions_pool) >= TARGET_QUESTIONS:
        questions = random.sample(questions_pool, TARGET_QUESTIONS)
        flash(f"Loaded {TARGET_QUESTIONS} questions for {test.difficulty.title()} difficulty. Good luck! 👍", "info")
    else:
        questions = questions_pool
        flash(f"Only {len(questions)} questions available for this test (less than {TARGET_QUESTIONS}).", "warning")

    # Shuffle questions order
    random.shuffle(questions)

    return render_template(
        "take_test.html",
        test=test,
        questions=questions,
        time_limit=test.time_limit_minutes,
        difficulty=test.difficulty.title(),
    )

# ----------------------------------------------------------------

# (submit_test, adaptive_recommendations, show_results, etc., remain mostly unchanged)

@app.route('/submit_test/<int:test_id>', methods=['POST'])
@login_required
def submit_test(test_id):
    if current_user.role != 'participant':
        return jsonify({'message': 'Unauthorized'}), 403

    # Grab submitted answers
    answers = request.json.get('answers', {})
    test = Test.query.get_or_404(test_id)
    questions = {q.id: q for q in test.questions}

    total_score = 0
    feedback = {}
    topic_perf = defaultdict(lambda: {'correct': 0, 'incorrect': 0, 'total': 0})

    for q_id_str, submitted_answer in answers.items():
        try:
            q_id = int(q_id_str)
        except ValueError:
            continue

        q = questions.get(q_id)
        if not q:
            continue

        # Normalize answers
        question_topic = q.topic if q.topic else 'Unknown Topic'
        is_correct = False

        if q.is_open_ended:
            submitted_text = (submitted_answer or '').strip().lower()
            correct_text = (q.correct_answer_text or '').strip().lower()
            if submitted_text == correct_text and correct_text != '':
                is_correct = True
                total_score += 1
                feedback[q.id] = "Correct!"
            else:
                feedback[q.id] = "Submitted for review."
        else:
            submitted_opt = (submitted_answer or '').strip().lower()
            correct_opt = (q.correct_option or '').strip().lower()
            if submitted_opt == correct_opt and correct_opt != '':
                is_correct = True
                total_score += 1
                feedback[q.id] = "Correct!"
            else:
                feedback[q.id] = f"Incorrect. Correct: {q.correct_option.upper() if q.correct_option else 'N/A'}."

        # Update topic performance
        topic_perf[question_topic]['total'] += 1
        if is_correct:
            topic_perf[question_topic]['correct'] += 1
        else:
            topic_perf[question_topic]['incorrect'] += 1

    # Determine weak topics (mastery < 60%)
    weak_topics = {}
    for topic, stats in topic_perf.items():
        if stats['total'] == 0:
            continue
        mastery = (stats['correct'] / stats['total']) * 100
        if mastery < 60:
            weak_topics[topic] = round(mastery, 1)

    # Save submission
    ai_feedback = json.dumps({
        'topic_performance': topic_perf,
        'question_feedback': feedback,
        'weak_topics': weak_topics
    })

    submission = Submission(
        test_id=test.id,
        participant_id=current_user.id,
        answers=json.dumps(answers),
        score=total_score,
        ai_feedback=ai_feedback
    )

    db.session.add(submission)
    db.session.commit()

    # Debug logs
    print(f"DEBUG: Submission ID: {submission.id}, Total Score: {total_score}")
    print(f"DEBUG: Weak Topics: {weak_topics}")
    print(f"DEBUG: Question Feedback: {feedback}")

    return jsonify({
        'message': 'Test submitted successfully!',
        'redirect_url': url_for('show_results', submission_id=submission.id)
    })


@app.route('/test_feedback/<int:test_id>/<int:score>')
@login_required
def test_feedback(test_id, score):
    test = Test.query.get_or_404(test_id)

    # Load resources (external tutorials or links)
    try:
        with open('resources.json') as f:
            resources = json.load(f)
    except FileNotFoundError:
        resources = {}

    topic_resources = resources.get(test.topic, {})
    difficulty_resources = topic_resources.get(test.difficulty, [])

    # Handle edge case: 0/0
    if score == 0 or len(test.questions) == 0:
        message = f"⚠️ No questions attempted or no questions available for '{test.title}'. Review the topics below:"
        passed = False
    else:
        # Example: passing threshold = 60% correct
        passed = (score / len(test.questions)) >= 0.6
        if passed:
            message = "Excellent work! 🚀 No weak topics detected."
        else:
            message = "Review your weak topics below."

    return render_template(
        'test_feedback.html',
        test=test,
        score=score,
        passed=passed,
        resources=difficulty_resources,
        message=message
    )


@app.route('/adaptive_feedback/<int:submission_id>')
@login_required
def adaptive_feedback(submission_id):
    submission = Submission.query.get_or_404(submission_id)
    if submission.participant_id != current_user.id:
        flash("You cannot view this submission.", "error")
        return redirect(url_for('participant_dashboard'))

    test = Test.query.get_or_404(submission.test_id)

    # Load feedback
    feedback_data = json.loads(submission.ai_feedback)
    topic_performance = feedback_data.get('topic_performance', {})

    total_questions = sum(stats['total'] for stats in topic_performance.values())
    total_correct = sum(stats['correct'] for stats in topic_performance.values())
    passed = (total_correct / total_questions) >= 0.6 if total_questions > 0 else False

    # YouTube tutorials per topic
    youtube_videos = {
        "Python": [
            {"title": "Python Crash Course", "video_id": "rfscVS0vtbw"},
            {"title": "Python Tutorial for Beginners", "video_id": "_uQrJ0TkZlc"}
        ],
        "Web Dev": [
            {"title": "Web Development Full Course", "video_id": "3JluqTojuME"},
            {"title": "HTML CSS JS Crash Course", "video_id": "UB1O30fR-EE"}
        ],
        "Networks": [
            {"title": "Networking Basics", "video_id": "qiQR5rTSshw"},
            {"title": "Computer Networks Full Course", "video_id": "qiQR5rTSshw"}
        ]
    }

    if passed:
        suggestions = [{"title": "🎉 Excellent! You passed. Keep practicing to maintain mastery.", "video_id": None}]
    else:
        topic_name = test.topic
        suggestions = youtube_videos.get(topic_name, [])

    return render_template(
        'adaptive_feedback.html',
        test=test,
        passed=passed,
        suggestions=suggestions,
        score=total_correct,
        total_questions=total_questions
    )


@app.route('/adaptive_recommendations')
@login_required
def adaptive_recommendations():
    latest_submission = Submission.query.filter_by(participant_id=current_user.id)\
                                      .order_by(Submission.id.desc()).first()
    if not latest_submission:
        flash("Please complete a test first to get personalized recommendations.", "info")
        return redirect(url_for('participant_dashboard'))

    try:
        feedback_data = json.loads(latest_submission.ai_feedback)
    except json.JSONDecodeError:
        feedback_data = {}

    weak_topics = feedback_data.get('weak_topics', {})

    # Load video tutorials from JSON
    # Load video tutorials from JSON file in 'data' folder
    data_path = os.path.join(os.path.dirname(__file__), 'data', 'tutorials.json')
    try:
        with open(data_path, 'r') as f:
            youtube_videos_recommendations = json.load(f)
    except FileNotFoundError:
        youtube_videos_recommendations = {}

    recommendations = {}

    if not weak_topics:
        recommendations['Success'] = {
            'mastery': 100,
            'questions': [],
            'videos': [{"title": "🎉 Excellent work! No weak topics detected.", "video_id": None}]
        }
    else:
        for topic, mastery_score in weak_topics.items():
            # Fetch remedial questions
            remedial_questions_objs = Question.query.filter_by(topic=topic).limit(3).all()
            remedial_questions = [{'text': q.question_text} for q in remedial_questions_objs]

            # Get videos from JSON
            videos = youtube_videos_recommendations.get(topic, [])
            
            # Only fallback to search tutorial if videos list is empty
            if not videos:
                videos = [{"title": f"Search tutorials for '{topic}' on YouTube", "video_id": None}]
            
            recommendations[topic] = {
                'mastery': mastery_score,
                'questions': remedial_questions,
                'videos': videos[:3]  # limit to top 2 videos
            }

    return render_template(
        'adaptive_recommendations.html',
        recommendations=recommendations,
        last_test_title=latest_submission.test.title,
        has_weak_topics=bool(weak_topics)
    )



@app.route('/results/<int:submission_id>')
@login_required
def show_results(submission_id):
    submission = Submission.query.get_or_404(submission_id)
    if submission.participant_id != current_user.id:
        flash("You do not have permission to view this submission.", "error")
        return redirect(url_for('participant_dashboard'))

    test = Test.query.get_or_404(submission.test_id)

    # Parse answers and feedback
    try:
        answers_data = json.loads(submission.answers)
        feedback_data = json.loads(submission.ai_feedback)
    except json.JSONDecodeError:
        answers_data = {}
        feedback_data = {}

    question_feedback = feedback_data.get('question_feedback', {})
    topic_performance = feedback_data.get('topic_performance', {})

    # --- FIX 1: Use explicit variables for clarity ---
    total_attempted = len(answers_data) # This will be 7
    total_available_in_test = len(test.questions)
    score = submission.score or 0 # This will be 0

    # --- FIX 2: Correctly calculate incorrect answers in Python ---
    incorrect_answers = total_attempted - score

    # Determine overall pass/fail message based on attempted score
    percentage_score = (score / total_attempted) * 100 if total_attempted > 0 else 0
    
    if percentage_score < 60 and total_attempted > 0:
        message = "Needs improvement. Review weak topics. ⚠️"
        needs_recommendations = True
    else:
        message = "Good job! Keep practicing. 👍"
        needs_recommendations = False
    
    # Determine pass/fail for simple display (e.g., passing is >= 60%)
    passed = percentage_score >= 60

    return render_template(
        'results.html',
        submission=submission,
        test=test,
        # Pass the new, clear variables to the template
        total_attempted=total_attempted, 
        total_available=total_available_in_test,
        score=score,
        incorrect_answers=incorrect_answers,
        percentage_score=round(percentage_score, 1),
        message=message,
        needs_recommendations=needs_recommendations,
        question_feedback=question_feedback,
        topic_performance=topic_performance,
        passed=passed
    )



# (Rest of the routes remain the same)
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
        flash('Test created successfully! Now add questions (ideally using the JSON upload).', 'success')
        return redirect(url_for('creator_dashboard'))
    return render_template('create_test.html', form=form)

@app.route('/delete_test/<int:test_id>', methods=['POST'])
@login_required
def delete_test(test_id):
    test = Test.query.get_or_404(test_id)
    if test.creator_id != current_user.id:
        flash("Unauthorized access.", "error")
        return redirect(url_for('creator_dashboard'))
    # Questions and Submissions are automatically deleted due to cascade
    db.session.delete(test)
    db.session.commit()
    flash("Test and all associated data have been deleted.", "success")
    return redirect(url_for('creator_dashboard'))


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
# -----------------------------
# Run app
# -----------------------------
if __name__ == '__main__':
    app.run(debug=True)

