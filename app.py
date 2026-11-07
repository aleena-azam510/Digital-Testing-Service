
import os
import json
import random
from pathlib import Path
from collections import defaultdict
from urllib.parse import unquote

import click
from dotenv import load_dotenv

from flask import (
    Flask, render_template, redirect, url_for, flash,
    request, jsonify
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    logout_user, current_user
)
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_migrate import Migrate
from flask_wtf import FlaskForm
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Optional, Length
from sqlalchemy.orm import joinedload
from sqlalchemy.exc import SQLAlchemyError


# =========================================================
# CONFIGURATION
# =========================================================

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
UPLOAD_FOLDER = INSTANCE_DIR / "uploads"

INSTANCE_DIR.mkdir(exist_ok=True)
UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)

APP_ENV = os.getenv("APP_ENV", "development").lower()
IS_PRODUCTION = APP_ENV == "production"

secret_key = os.getenv("SECRET_KEY")

if IS_PRODUCTION and not secret_key:
    raise RuntimeError("SECRET_KEY must be configured in production.")

app.config["SECRET_KEY"] = (
    secret_key or "local-development-only-change-this-key"
)

app.config["UPLOAD_FOLDER"] = str(UPLOAD_FOLDER)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

database_url = os.getenv("DATABASE_URL")

if database_url:
    if database_url.startswith("postgres://"):
        database_url = database_url.replace(
            "postgres://", "postgresql+psycopg://", 1
        )
    elif database_url.startswith("postgresql://"):
        database_url = database_url.replace(
            "postgresql://", "postgresql+psycopg://", 1
        )

    app.config["SQLALCHEMY_DATABASE_URI"] = database_url

else:
    if IS_PRODUCTION:
        raise RuntimeError("DATABASE_URL must be configured in production.")

    local_database = INSTANCE_DIR / "digital_testing_service.db"

    app.config["SQLALCHEMY_DATABASE_URI"] = (
        f"sqlite:///{local_database.as_posix()}"
    )

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ECHO"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True}

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = IS_PRODUCTION


# =========================================================
# DATABASE AND LOGIN
# =========================================================

db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Please log in to access this page."
login_manager.login_message_category = "info"


# =========================================================
# MODELS
# =========================================================

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default="participant")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Test(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    time_limit_minutes = db.Column(db.Integer, default=0)

    topic = db.Column(
        db.String(100), nullable=False, default="Uncategorized"
    )
    difficulty = db.Column(
        db.String(20), nullable=False, default="easy"
    )
    category = db.Column(
        db.String(50), nullable=False, default="Uncategorized"
    )

    creator_id = db.Column(db.Integer, db.ForeignKey("user.id"))

    submissions = db.relationship(
        "Submission", back_populates="test", lazy="dynamic"
    )

    questions = db.relationship(
        "Question",
        backref="test",
        lazy=True,
        cascade="all, delete-orphan",
    )


class Submission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    test_id = db.Column(db.Integer, db.ForeignKey("test.id"))
    participant_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    answers = db.Column(db.Text)
    score = db.Column(db.Integer)
    ai_feedback = db.Column(db.Text)

    test = db.relationship("Test", back_populates="submissions")


class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    test_id = db.Column(
        db.Integer, db.ForeignKey("test.id"), nullable=False
    )
    question_text = db.Column(db.Text, nullable=False)
    is_open_ended = db.Column(db.Boolean, default=False)
    options = db.Column(db.Text)
    correct_option = db.Column(db.String(100))
    correct_answer_text = db.Column(db.Text)
    topic = db.Column(db.String(100), default="General")


# =========================================================
# ADMIN PANEL
# =========================================================

admin = Admin(
    app,
    name="DTS Admin Panel",
    template_mode="bootstrap3",
)


class CustomModelView(ModelView):

    def is_accessible(self):
        return (
            current_user.is_authenticated
            and current_user.role == "admin"
        )

    def inaccessible_callback(self, name, **kwargs):
        flash("Administrator access is required.", "error")
        return redirect(url_for("login"))


admin.add_view(CustomModelView(User, db.session))
admin.add_view(CustomModelView(Test, db.session))
admin.add_view(CustomModelView(Question, db.session))
admin.add_view(CustomModelView(Submission, db.session))


@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except (ValueError, TypeError):
        return None


# =========================================================
# TEMPLATE FILTERS
# =========================================================

@app.template_filter("from_json")
def from_json_filter(value):
    try:
        return json.loads(value) if value else {}
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}


# =========================================================
# CLI COMMANDS
# =========================================================

@app.cli.command("create-admin")
def create_admin():
    """Create an administrator account from the terminal."""

    username = click.prompt("Administrator username").strip()

    if not username:
        click.echo("Username cannot be empty.")
        return

    if User.query.filter_by(username=username).first():
        click.echo("This username already exists.")
        return

    password = click.prompt(
        "Administrator password",
        hide_input=True,
        confirmation_prompt=True,
    )

    if len(password) < 10:
        click.echo("Password must contain at least 10 characters.")
        return

    user = User(username=username, role="admin")
    user.set_password(password)

    try:
        db.session.add(user)
        db.session.commit()
        click.echo("Administrator account created successfully.")
    except SQLAlchemyError:
        db.session.rollback()
        app.logger.exception("Admin creation failed.")
        click.echo("Could not create administrator account.")


# =========================================================
# FORMS
# =========================================================

class CreateTestForm(FlaskForm):
    title = StringField(
        "Test Title",
        validators=[DataRequired(), Length(max=255)],
    )
    description = TextAreaField(
        "Description",
        validators=[Optional()],
    )
    submit = SubmitField("Create Test")


# =========================================================
# HELPER FUNCTIONS
# =========================================================

def participant_required():
    return (
        current_user.is_authenticated
        and current_user.role == "participant"
    )


def creator_required():
    return (
        current_user.is_authenticated
        and current_user.role == "creator"
    )


def load_feedback_data(submission):
    try:
        return json.loads(submission.ai_feedback or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}


def load_answers_data(submission):
    try:
        return json.loads(submission.answers or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}


def prepare_questions(questions_data, default_topic="General"):
    """
    Validate question data from the creator page or JSON upload.

    Supports both formats:
    - question_text / is_open_ended / correct_option
    - text / type / correct_answer
    """

    if not isinstance(questions_data, list) or not questions_data:
        raise ValueError("At least one question is required.")

    prepared = []

    for item in questions_data:
        if not isinstance(item, dict):
            raise ValueError("Each question must be an object.")

        question_text = str(
            item.get("question_text") or item.get("text") or ""
        ).strip()

        if not question_text:
            raise ValueError("Question text cannot be empty.")

        question_type = str(item.get("type", "")).lower()

        is_open = item.get("is_open_ended")

        if is_open is None:
            is_open = question_type in ("open", "open_ended")
        else:
            is_open = bool(is_open)

        if is_open:
            correct_answer = (
                item.get("correct_answer_text")
                or item.get("correct_answer")
                or ""
            )

            if not str(correct_answer).strip():
                raise ValueError(
                    "Open-ended questions require a correct answer."
                )

            options = None
            correct_option = None
            correct_answer_text = str(correct_answer).strip()

        else:
            options = item.get("options")

            if not isinstance(options, dict) or len(options) < 2:
                raise ValueError(
                    "MCQ questions require at least two options."
                )

            options = {
                str(key).strip(): str(value).strip()
                for key, value in options.items()
            }

            if any(not value for value in options.values()):
                raise ValueError("MCQ options cannot be empty.")

            correct_option = (
                item.get("correct_option")
                or item.get("correct_answer")
            )

            if not correct_option:
                raise ValueError(
                    "MCQ questions require a correct answer."
                )

            correct_option = str(correct_option).strip()

            if correct_option not in options:
                raise ValueError(
                    "The correct MCQ answer must match an option key."
                )

            correct_answer_text = None

        question_topic = str(
            item.get("topic") or default_topic
        ).strip() or default_topic

        prepared.append({
            "question_text": question_text,
            "is_open_ended": is_open,
            "options": options,
            "correct_option": correct_option,
            "correct_answer_text": correct_answer_text,
            "topic": question_topic,
        })

    return prepared


def save_questions(test, prepared_questions):
    for item in prepared_questions:
        question = Question(
            test_id=test.id,
            question_text=item["question_text"],
            is_open_ended=item["is_open_ended"],
            options=(
                json.dumps(item["options"])
                if item["options"] is not None
                else None
            ),
            correct_option=item["correct_option"],
            correct_answer_text=item["correct_answer_text"],
            topic=item["topic"],
        )
        db.session.add(question)


# =========================================================
# HOME
# =========================================================

@app.route("/")
def index():
    return render_template("index.html")


# =========================================================
# REGISTRATION
# =========================================================

@app.route("/register", methods=["GET", "POST"])
def register():

    if current_user.is_authenticated:
        return redirect(url_for("dashboard_redirect"))

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        if not username or not password:
            flash("Username and password are required.", "error")
            return redirect(url_for("register"))

        if len(username) > 100:
            flash("Username cannot exceed 100 characters.", "error")
            return redirect(url_for("register"))

        if len(password) < 10:
            flash("Password must contain at least 10 characters.", "error")
            return redirect(url_for("register"))

        if User.query.filter_by(username=username).first():
            flash("Username already exists.", "error")
            return redirect(url_for("register"))

        try:
            user = User(username=username, role="participant")
            user.set_password(password)

            db.session.add(user)
            db.session.commit()

            flash("Registration successful! Please log in.", "success")
            return redirect(url_for("login"))

        except SQLAlchemyError:
            db.session.rollback()
            app.logger.exception("Registration failed.")
            flash("Registration could not be completed.", "error")
            return redirect(url_for("register"))

    return render_template("register.html")


# =========================================================
# LOGIN AND LOGOUT
# =========================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if current_user.is_authenticated:
        return redirect(url_for("dashboard_redirect"))

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for("dashboard_redirect"))

        flash("Invalid username or password.", "error")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out successfully.", "success")
    return redirect(url_for("index"))


# =========================================================
# DASHBOARD REDIRECT
# =========================================================

@app.route("/dashboard")
@login_required
def dashboard_redirect():

    if current_user.role == "admin":
        return redirect(url_for("admin_dashboard"))

    if current_user.role == "creator":
        return redirect(url_for("creator_dashboard"))

    return redirect(url_for("participant_dashboard"))


# =========================================================
# ADMIN DASHBOARD
# =========================================================

@app.route("/dashboard/admin")
@login_required
def admin_dashboard():

    if current_user.role != "admin":
        flash("Unauthorized access.", "error")
        return redirect(url_for("dashboard_redirect"))

    return render_template(
        "admin_dashboard.html",
        total_users=User.query.count(),
        total_tests=Test.query.count(),
        total_submissions=Submission.query.count(),
        admin_count=User.query.filter_by(role="admin").count(),
        creator_count=User.query.filter_by(role="creator").count(),
        participant_count=User.query.filter_by(role="participant").count(),
    )


# =========================================================
# CREATOR DASHBOARD
# =========================================================

@app.route("/dashboard/creator")
@login_required
def creator_dashboard():

    if not creator_required():
        flash("Unauthorized access.", "error")
        return redirect(url_for("dashboard_redirect"))

    my_tests = (
        Test.query
        .filter_by(creator_id=current_user.id)
        .order_by(Test.id.desc())
        .all()
    )

    return render_template(
        "creator_dashboard.html",
        my_tests=my_tests,
    )


# =========================================================
# PARTICIPANT DASHBOARD
# =========================================================

@app.route("/dashboard/participant")
@login_required
def participant_dashboard():

    if not participant_required():
        flash("Unauthorized access.", "error")
        return redirect(url_for("dashboard_redirect"))

    try:
        topic_rows = (
            db.session.query(Test.topic)
            .filter(Test.topic.isnot(None))
            .filter(Test.topic != "")
            .distinct()
            .order_by(Test.topic)
            .all()
        )

        available_topics = [row[0] for row in topic_rows]

        recent_submissions = (
            Submission.query
            .filter_by(participant_id=current_user.id)
            .options(joinedload(Submission.test))
            .order_by(Submission.id.desc())
            .limit(5)
            .all()
        )

        return render_template(
            "participant_dashboard.html",
            available_topics=available_topics,
            recent_submissions=recent_submissions,
        )

    except SQLAlchemyError:
        db.session.rollback()
        app.logger.exception("Participant dashboard error.")
        flash("Could not load your dashboard.", "error")
        return redirect(url_for("index"))


# =========================================================
# CREATE TEST
# =========================================================

@app.route("/create_test", methods=["GET", "POST"])
@login_required
def create_test():

    if not creator_required():
        if request.is_json:
            return jsonify({"message": "Unauthorized access."}), 403

        flash("Unauthorized access.", "error")
        return redirect(url_for("dashboard_redirect"))

    # Updated creator page sends JSON through fetch().
    if request.method == "POST" and request.is_json:
        data = request.get_json(silent=True)

        if not isinstance(data, dict):
            return jsonify({"message": "Invalid JSON data."}), 400

        try:
            title = str(
                data.get("test_title") or data.get("title") or ""
            ).strip()

            description = str(data.get("description") or "").strip()
            topic = str(data.get("topic") or "Uncategorized").strip()
            difficulty = str(data.get("difficulty") or "easy").strip().lower()

            if not title or len(title) > 255:
                raise ValueError("A valid test title is required.")

            if not topic or len(topic) > 100:
                raise ValueError("A valid topic is required.")

            if difficulty not in ("easy", "medium", "hard"):
                raise ValueError("Difficulty must be easy, medium, or hard.")

            try:
                time_limit = int(data.get("time_limit_minutes", 0))
            except (ValueError, TypeError):
                raise ValueError("Time limit must be a valid number.")

            if time_limit < 0 or time_limit > 600:
                raise ValueError("Time limit must be between 0 and 600 minutes.")

            prepared_questions = prepare_questions(
                data.get("questions"),
                default_topic=topic,
            )

            new_test = Test(
                title=title,
                description=description,
                creator_id=current_user.id,
                topic=topic,
                difficulty=difficulty,
                time_limit_minutes=time_limit,
                category=str(data.get("category") or "Uncategorized"),
            )

            db.session.add(new_test)
            db.session.flush()

            save_questions(new_test, prepared_questions)

            db.session.commit()

            return jsonify({
                "success": True,
                "message": "Test created successfully.",
                "test_id": new_test.id,
                "redirect_url": url_for("creator_dashboard"),
            }), 201

        except (ValueError, TypeError) as error:
            db.session.rollback()
            return jsonify({"message": str(error)}), 400

        except SQLAlchemyError:
            db.session.rollback()
            app.logger.exception("Test creation failed.")
            return jsonify({
                "message": "Could not save the test. Please try again."
            }), 500

    # Traditional form fallback.
    if request.method == "POST":
        form = CreateTestForm()

        if form.validate_on_submit():
            try:
                new_test = Test(
                    title=form.title.data.strip(),
                    description=form.description.data,
                    creator_id=current_user.id,
                )
                db.session.add(new_test)
                db.session.commit()

                flash("Test created successfully.", "success")
                return redirect(url_for("creator_dashboard"))

            except SQLAlchemyError:
                db.session.rollback()
                app.logger.exception("Traditional test creation failed.")
                flash("Could not create the test.", "error")

    return render_template("create_test.html")


# =========================================================
# EDIT TEST DETAILS
# =========================================================

@app.route("/edit_test/<int:test_id>", methods=["GET", "POST"])
@login_required
def edit_test(test_id):

    if not creator_required():
        flash("Unauthorized access.", "error")
        return redirect(url_for("dashboard_redirect"))

    test = Test.query.get_or_404(test_id)

    if test.creator_id != current_user.id:
        flash("You do not own this test.", "error")
        return redirect(url_for("creator_dashboard"))

    if request.method == "POST":
        title = (
            request.form.get("title")
            or request.form.get("test_title")
            or ""
        ).strip()

        description = request.form.get("description", "")
        topic = (request.form.get("topic") or "Uncategorized").strip()
        difficulty = (request.form.get("difficulty") or "easy").strip().lower()
        category = (
            request.form.get("category") or "Uncategorized"
        ).strip()

        try:
            time_limit = int(request.form.get("time_limit_minutes") or 0)

            if time_limit < 0 or time_limit > 600:
                raise ValueError

        except (ValueError, TypeError):
            flash("Time limit must be between 0 and 600 minutes.", "error")
            return redirect(url_for("edit_test", test_id=test.id))

        if not title or len(title) > 255:
            flash("A valid test title is required.", "error")
            return redirect(url_for("edit_test", test_id=test.id))

        if difficulty not in ("easy", "medium", "hard"):
            flash("Select a valid difficulty.", "error")
            return redirect(url_for("edit_test", test_id=test.id))

        test.title = title
        test.description = description
        test.topic = topic or "Uncategorized"
        test.difficulty = difficulty
        test.category = category or "Uncategorized"
        test.time_limit_minutes = time_limit

        try:
            db.session.commit()
            flash("Test updated successfully.", "success")
            return redirect(url_for("creator_dashboard"))

        except SQLAlchemyError:
            db.session.rollback()
            app.logger.exception("Test update failed.")
            flash("Could not update the test.", "error")

    return render_template("edit_test.html", test=test)


# =========================================================
# EDIT TEST QUESTIONS USING JSON
# =========================================================

@app.route("/edit_test_json/<int:test_id>", methods=["GET", "POST"])
@login_required
def edit_test_json(test_id):

    if not creator_required():
        flash("Unauthorized access.", "error")
        return redirect(url_for("dashboard_redirect"))

    test = Test.query.get_or_404(test_id)

    if test.creator_id != current_user.id:
        flash("You do not own this test.", "error")
        return redirect(url_for("creator_dashboard"))

    test_data = {
        "title": test.title,
        "description": test.description,
        "time_limit_minutes": test.time_limit_minutes,
        "difficulty": test.difficulty,
        "topic": test.topic,
        "questions": [],
    }

    for question in test.questions:
        try:
            options = json.loads(question.options) if question.options else None
        except (TypeError, ValueError, json.JSONDecodeError):
            options = None

        test_data["questions"].append({
            "text": question.question_text,
            "type": "open" if question.is_open_ended else "mcq",
            "options": options,
            "correct_answer": (
                question.correct_answer_text
                if question.is_open_ended
                else question.correct_option
            ),
        })

    if request.method == "POST":
        try:
            raw_json = request.form.get("test_json", "")
            data = json.loads(raw_json)

            if not isinstance(data, dict):
                raise ValueError("JSON must contain an object.")

            title = str(data.get("title", test.title)).strip()

            if not title or len(title) > 255:
                raise ValueError("A valid test title is required.")

            topic = str(data.get("topic", test.topic)).strip()
            difficulty = str(
                data.get("difficulty", test.difficulty)
            ).strip().lower()

            if difficulty not in ("easy", "medium", "hard"):
                raise ValueError("Invalid difficulty.")

            time_limit = int(
                data.get("time_limit_minutes", test.time_limit_minutes or 0)
            )

            if time_limit < 0 or time_limit > 600:
                raise ValueError("Time limit must be between 0 and 600.")

            prepared = prepare_questions(
                data.get("questions"),
                default_topic=topic or "General",
            )

            test.title = title
            test.description = data.get("description", test.description)
            test.topic = topic or "Uncategorized"
            test.difficulty = difficulty
            test.time_limit_minutes = time_limit

            for old_question in list(test.questions):
                db.session.delete(old_question)

            db.session.flush()
            save_questions(test, prepared)
            db.session.commit()

            flash("Test questions updated successfully.", "success")
            return redirect(url_for("edit_test_json", test_id=test.id))

        except (json.JSONDecodeError, ValueError, TypeError) as error:
            db.session.rollback()
            flash(f"Could not update test: {error}", "danger")

        except SQLAlchemyError:
            db.session.rollback()
            app.logger.exception("JSON test update failed.")
            flash("Database error while updating the test.", "danger")

    return render_template(
        "edit_test_json.html",
        test=test,
        test_json=json.dumps(test_data, indent=2),
    )


# =========================================================
# UPLOAD JSON TEST
# =========================================================

@app.route("/upload_json_test", methods=["GET", "POST"])
@login_required
def upload_json_test():

    if not creator_required():
        flash("Unauthorized access.", "error")
        return redirect(url_for("dashboard_redirect"))

    if request.method == "POST":
        if "file" not in request.files:
            flash("No file selected.", "danger")
            return redirect(request.url)

        file = request.files["file"]

        if not file.filename:
            flash("Please select a JSON file.", "danger")
            return redirect(request.url)

        if not file.filename.lower().endswith(".json"):
            flash("Only JSON files are accepted.", "danger")
            return redirect(request.url)

        try:
            json_data = json.loads(file.read())

            if not isinstance(json_data, dict):
                raise ValueError("The JSON file must contain an object.")

            title = str(json_data.get("title") or "").strip()
            topic = str(json_data.get("topic") or "").strip()
            difficulty = str(
                json_data.get("difficulty") or "easy"
            ).strip().lower()

            if not title or len(title) > 255:
                raise ValueError("A valid test title is required.")

            if not topic or len(topic) > 100:
                raise ValueError("A valid topic is required.")

            if difficulty not in ("easy", "medium", "hard"):
                raise ValueError("Difficulty must be easy, medium, or hard.")

            time_limit = int(json_data.get("time_limit_minutes", 0))

            if time_limit < 0 or time_limit > 600:
                raise ValueError("Time limit must be between 0 and 600.")

            prepared = prepare_questions(
                json_data.get("questions"),
                default_topic=topic,
            )

            new_test = Test(
                creator_id=current_user.id,
                title=title,
                description=json_data.get(
                    "description", "No description provided."
                ),
                time_limit_minutes=time_limit,
                topic=topic,
                difficulty=difficulty,
                category=json_data.get("category", "Uncategorized"),
            )

            db.session.add(new_test)
            db.session.flush()

            save_questions(new_test, prepared)
            db.session.commit()

            flash(
                f'Test "{new_test.title}" uploaded with '
                f'{len(prepared)} questions.',
                "success",
            )
            return redirect(url_for("creator_dashboard"))

        except (json.JSONDecodeError, ValueError, TypeError) as error:
            db.session.rollback()
            flash(f"Upload failed: {error}", "danger")
            return redirect(request.url)

        except SQLAlchemyError:
            db.session.rollback()
            app.logger.exception("JSON upload failed.")
            flash("Database error while uploading the test.", "danger")
            return redirect(request.url)

    return render_template("upload_json_test.html")


# =========================================================
# TOPIC DETAIL
# =========================================================

@app.route("/dashboard/topic/<topic>")
@login_required
def topic_detail(topic):

    if not participant_required():
        flash("Unauthorized access.", "error")
        return redirect(url_for("dashboard_redirect"))

    decoded_topic = unquote(topic)

    tests = (
        Test.query
        .filter_by(topic=decoded_topic)
        .order_by(Test.id.desc())
        .all()
    )

    if not tests:
        flash("No tests available for this topic yet.", "warning")

    return render_template(
        "topic_detail.html",
        topic=decoded_topic,
        tests=tests,
    )


# =========================================================
# START TEST
# =========================================================

@app.route(
    "/start_test/<string:topic>/<string:difficulty_level>",
    methods=["GET"],
)
@login_required
def start_test(topic, difficulty_level):

    if not participant_required():
        flash("Unauthorized access.", "error")
        return redirect(url_for("dashboard_redirect"))

    test = (
        Test.query
        .filter_by(topic=topic, difficulty=difficulty_level.lower())
        .order_by(Test.id.asc())
        .first()
    )

    if test:
        return redirect(url_for("take_test", test_id=test.id))

    flash(
        f"No test found for {topic} at {difficulty_level} difficulty.",
        "danger",
    )
    return redirect(url_for("participant_dashboard"))


# =========================================================
# DELETE TEST
# =========================================================

@app.route("/delete_test/<int:test_id>", methods=["POST"])
@login_required
def delete_test(test_id):

    if not creator_required():
        flash("Unauthorized access.", "error")
        return redirect(url_for("dashboard_redirect"))

    test = Test.query.get_or_404(test_id)

    if test.creator_id != current_user.id:
        flash("You do not own this test.", "error")
        return redirect(url_for("creator_dashboard"))

    try:
        db.session.delete(test)
        db.session.commit()
        flash("Test and associated questions have been deleted.", "success")

    except SQLAlchemyError:
        db.session.rollback()
        app.logger.exception("Test deletion failed.")
        flash("Could not delete the test.", "error")

    return redirect(url_for("creator_dashboard"))


# =========================================================
# TAKE TEST
# =========================================================

@app.route("/take_test/<int:test_id>", methods=["GET"])
@login_required
def take_test(test_id):

    if not participant_required():
        flash("Unauthorized access.", "error")
        return redirect(url_for("dashboard_redirect"))

    test = Test.query.get_or_404(test_id)

    questions_pool = Question.query.filter_by(test_id=test.id).all()

    if not questions_pool:
        flash("No questions found for this test.", "error")
        return redirect(
            url_for("topic_detail", topic=test.topic)
        )

    target_questions = 20

    if len(questions_pool) >= target_questions:
        questions = random.sample(questions_pool, target_questions)
        flash(
            f"Loaded {target_questions} questions. Good luck!",
            "info",
        )
    else:
        questions = list(questions_pool)
        flash(
            f"Only {len(questions)} questions are available.",
            "warning",
        )

    random.shuffle(questions)

    return render_template(
        "take_test.html",
        test=test,
        questions=questions,
        time_limit=test.time_limit_minutes,
        difficulty=test.difficulty.title(),
    )


# =========================================================
# SUBMIT TEST
# =========================================================

@app.route("/submit_test/<int:test_id>", methods=["POST"])
@login_required
def submit_test(test_id):

    if not participant_required():
        return jsonify({"message": "Unauthorized."}), 403

    if not request.is_json:
        return jsonify({"message": "Request must contain JSON data."}), 400

    payload = request.get_json(silent=True)

    if not isinstance(payload, dict):
        return jsonify({"message": "Invalid submission data."}), 400

    answers = payload.get("answers", {})

    if not isinstance(answers, dict):
        return jsonify({"message": "Answers must be an object."}), 400

    test = Test.query.get_or_404(test_id)

    questions = {question.id: question for question in test.questions}

    total_score = 0
    feedback = {}
    valid_answers = {}

    topic_perf = defaultdict(
        lambda: {"correct": 0, "incorrect": 0, "total": 0}
    )

    for question_id_string, submitted_answer in answers.items():
        try:
            question_id = int(question_id_string)
        except (ValueError, TypeError):
            continue

        question = questions.get(question_id)

        if not question:
            continue

        if submitted_answer is None:
            submitted_answer = ""

        if not isinstance(submitted_answer, str):
            submitted_answer = str(submitted_answer)

        submitted_answer = submitted_answer.strip()

        if not submitted_answer:
            continue

        valid_answers[str(question_id)] = submitted_answer

        question_topic = (
            question.topic.strip()
            if question.topic and question.topic.strip()
            else "General"
        )

        if question.is_open_ended:
            correct_text = (
                question.correct_answer_text or ""
            ).strip().lower()

            is_correct = (
                bool(correct_text)
                and submitted_answer.lower() == correct_text
            )

            feedback[question.id] = (
                "Correct!"
                if is_correct
                else "Submitted for review."
            )

        else:
            correct_option = (
                question.correct_option or ""
            ).strip().lower()

            is_correct = (
                bool(correct_option)
                and submitted_answer.lower() == correct_option
            )

            feedback[question.id] = (
                "Correct!"
                if is_correct
                else f"Incorrect. Correct answer: {question.correct_option or 'N/A'}."
            )

        topic_perf[question_topic]["total"] += 1

        if is_correct:
            total_score += 1
            topic_perf[question_topic]["correct"] += 1
        else:
            topic_perf[question_topic]["incorrect"] += 1

    if not valid_answers:
        return jsonify({
            "message": "Please answer at least one question before submitting."
        }), 400

    weak_topics = {}

    for topic, stats in topic_perf.items():
        if stats["total"]:
            mastery = stats["correct"] / stats["total"] * 100
            if mastery < 60:
                weak_topics[topic] = round(mastery, 1)

    feedback_data = {
        "topic_performance": dict(topic_perf),
        "question_feedback": feedback,
        "weak_topics": weak_topics,
    }

    submission = Submission(
        test_id=test.id,
        participant_id=current_user.id,
        answers=json.dumps(valid_answers),
        score=total_score,
        ai_feedback=json.dumps(feedback_data),
    )

    try:
        db.session.add(submission)
        db.session.commit()

    except SQLAlchemyError:
        db.session.rollback()
        app.logger.exception("Submission could not be saved.")
        return jsonify({
            "message": "Your submission could not be saved. Please try again."
        }), 500

    return jsonify({
        "message": "Test submitted successfully!",
        "redirect_url": url_for(
            "show_results",
            submission_id=submission.id,
        ),
    })


# =========================================================
# TEST FEEDBACK
# =========================================================

@app.route("/test_feedback/<int:test_id>/<int:score>")
@login_required
def test_feedback(test_id, score):

    if not participant_required():
        flash("Unauthorized access.", "error")
        return redirect(url_for("dashboard_redirect"))

    test = Test.query.get_or_404(test_id)

    resources = {}

    try:
        with open(BASE_DIR / "resources.json", encoding="utf-8") as file:
            resources = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        pass

    topic_resources = resources.get(test.topic, {})
    difficulty_resources = topic_resources.get(test.difficulty, [])

    total_questions = len(test.questions)

    if total_questions == 0:
        message = f"No questions are available for '{test.title}'."
        passed = False
    else:
        percentage = score / total_questions * 100
        passed = percentage >= 60
        message = (
            "Excellent work! Keep practicing."
            if passed
            else "Review your weak topics and try again."
        )

    return render_template(
        "test_feedback.html",
        test=test,
        score=score,
        passed=passed,
        resources=difficulty_resources,
        message=message,
    )


# =========================================================
# ADAPTIVE FEEDBACK
# =========================================================

@app.route("/adaptive_feedback/<int:submission_id>")
@login_required
def adaptive_feedback(submission_id):

    if not participant_required():
        flash("Unauthorized access.", "error")
        return redirect(url_for("dashboard_redirect"))

    submission = Submission.query.get_or_404(submission_id)

    if submission.participant_id != current_user.id:
        flash("You cannot view this submission.", "error")
        return redirect(url_for("participant_dashboard"))

    test = Test.query.get_or_404(submission.test_id)
    feedback_data = load_feedback_data(submission)

    topic_performance = feedback_data.get("topic_performance", {})

    total_questions = sum(
        stats.get("total", 0)
        for stats in topic_performance.values()
    )

    total_correct = sum(
        stats.get("correct", 0)
        for stats in topic_performance.values()
    )

    percentage = (
        total_correct / total_questions * 100
        if total_questions else 0
    )

    passed = percentage >= 60

    youtube_videos = {
        "Python": [
            {"title": "Python Crash Course", "video_id": "rfscVS0vtbw"},
            {"title": "Python Tutorial for Beginners", "video_id": "_uQrJ0TkZlc"},
        ],
        "Web Dev": [
            {"title": "Web Development Full Course", "video_id": "3JluqTojuME"},
            {"title": "HTML CSS JS Crash Course", "video_id": "UB1O30fR-EE"},
        ],
        "Networks": [
            {"title": "Networking Basics", "video_id": "qiQR5rTSshw"},
        ],
    }

    if passed:
        suggestions = [{
            "title": "Excellent work! You passed. Keep practicing.",
            "text": "Excellent work! You passed. Keep practicing.",
            "video_id": None,
        }]
    else:
        suggestions = []

        for topic in feedback_data.get("weak_topics", {}):
            videos = youtube_videos.get(topic, [])

            if videos:
                suggestions.extend(videos)
            else:
                suggestions.append({
                    "title": f"Search tutorials for {topic}",
                    "text": f"Search tutorials for {topic}",
                    "video_id": None,
                })

        if not suggestions:
            suggestions = [{
                "title": "Review the questions you answered incorrectly.",
                "text": "Review the questions you answered incorrectly.",
                "video_id": None,
            }]

    return render_template(
        "adaptive_feedback.html",
        test=test,
        passed=passed,
        suggestions=suggestions,
        score=total_correct,
        total_questions=total_questions,
    )


# =========================================================
# ADAPTIVE RECOMMENDATIONS
# =========================================================

@app.route("/adaptive_recommendations")
@login_required
def adaptive_recommendations():

    if not participant_required():
        flash("Unauthorized access.", "error")
        return redirect(url_for("dashboard_redirect"))

    latest_submission = (
        Submission.query
        .filter_by(participant_id=current_user.id)
        .order_by(Submission.id.desc())
        .first()
    )

    if not latest_submission:
        flash(
            "Please complete a test first to get recommendations.",
            "info",
        )
        return redirect(url_for("participant_dashboard"))

    feedback_data = load_feedback_data(latest_submission)
    weak_topics = feedback_data.get("weak_topics", {})

    tutorials_path = BASE_DIR / "data" / "tutorials.json"

    try:
        with open(tutorials_path, encoding="utf-8") as file:
            youtube_videos = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        youtube_videos = {}

    videos_dict = {
        key.strip().lower(): value
        for key, value in youtube_videos.items()
    }

    recommendations = {}

    if not weak_topics:
        recommendations["Success"] = {
            "mastery": 100,
            "questions": [],
            "videos": [{
                "title": "Excellent work! No weak topics detected.",
                "video_id": None,
            }],
        }
    else:
        for topic, mastery_score in weak_topics.items():
            remedial_questions = (
                Question.query
                .filter_by(
                    test_id=latest_submission.test_id,
                    topic=topic,
                )
                .limit(3)
                .all()
            )

            questions_data = [
                {"text": question.question_text}
                for question in remedial_questions
            ]

            videos = videos_dict.get(topic.strip().lower(), [])

            if not videos:
                videos = [{
                    "title": f"Search tutorials for '{topic}' on YouTube",
                    "video_id": None,
                }]

            recommendations[topic] = {
                "mastery": mastery_score,
                "questions": questions_data,
                "videos": videos[:3],
            }

    test_title = (
        latest_submission.test.title
        if latest_submission.test
        else "Previous test"
    )

    return render_template(
        "adaptive_recommendations.html",
        recommendations=recommendations,
        last_test_title=test_title,
        has_weak_topics=bool(weak_topics),
    )


# =========================================================
# RESULTS
# =========================================================

@app.route("/results/<int:submission_id>")
@login_required
def show_results(submission_id):

    if not participant_required():
        flash("Unauthorized access.", "error")
        return redirect(url_for("dashboard_redirect"))

    submission = Submission.query.get_or_404(submission_id)

    if submission.participant_id != current_user.id:
        flash(
            "You do not have permission to view this submission.",
            "error",
        )
        return redirect(url_for("participant_dashboard"))

    test = Test.query.get_or_404(submission.test_id)

    answers_data = load_answers_data(submission)
    feedback_data = load_feedback_data(submission)

    question_feedback = feedback_data.get("question_feedback", {})
    topic_performance = feedback_data.get("topic_performance", {})

    total_attempted = len(answers_data)
    total_available = len(test.questions)
    score = submission.score or 0

    incorrect_answers = max(total_attempted - score, 0)

    percentage_score = (
        score / total_attempted * 100
        if total_attempted else 0
    )

    passed = percentage_score >= 60

    message = (
        "Good job! Keep practicing."
        if passed
        else "Needs improvement. Review your weak topics."
    )

    return render_template(
        "results.html",
        submission=submission,
        test=test,
        total_attempted=total_attempted,
        total_available=total_available,
        score=score,
        incorrect_answers=incorrect_answers,
        percentage_score=round(percentage_score, 1),
        message=message,
        needs_recommendations=not passed,
        question_feedback=question_feedback,
        topic_performance=topic_performance,
        passed=passed,
    )


# =========================================================
# STATIC PAGES
# =========================================================

@app.route("/features")
def features():
    return render_template("features.html")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact", methods=["GET", "POST"])
def contact():

    if request.method == "POST":
        flash(
            "The contact form is not connected to a messaging service yet.",
            "info",
        )
        return redirect(url_for("contact"))

    return render_template("contact.html")


# =========================================================
# APPLICATION STARTUP
# =========================================================

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=int(os.getenv("PORT", 5000)),
        debug=not IS_PRODUCTION,
    )
