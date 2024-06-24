from datetime import datetime
from typing import Optional
import os
import os.path

import openai

from lib import extract_text_from_pdf, generate_case_study, generate_quiz
import tiktoken

from flask import Flask, render_template, url_for, redirect, flash

from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

from flask_login import UserMixin, LoginManager, current_user, login_user, logout_user

from flask_sqlalchemy import SQLAlchemy
import sqlalchemy as sa
import sqlalchemy.orm as so

from flask_migrate import Migrate

from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired

app = Flask(__name__)

db = SQLAlchemy()

# NOTE: This is a token used to protect the form against CSRF attacks
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'do-not-use-this-in-production' 

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///projects.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
migrate = Migrate(app, db)

openai.api_key = os.environ.get("OPENAI_API_KEY")

login_manager = LoginManager(app)

# Models

class User(UserMixin, db.Model):
    id: so.Mapped[int] = so.mapped_column(primary_key=True)
    username: so.Mapped[str] = so.mapped_column(sa.String(64), index=True,
                                                unique=True)
    email: so.Mapped[str] = so.mapped_column(sa.String(120), index=True,
                                             unique=True)
    password_hash: so.Mapped[Optional[str]] = so.mapped_column(sa.String(256))

    def __repr__(self):
        return f'<User {self.username}, {self.email}>'
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method='pbkdf2')

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class CaseStudy(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    pdf_file_text = db.Column(db.Text)
    pdf_file_path = db.Column(db.Text)
    description = db.Column(db.Text)
    author_id = db.Column(db.Integer, db.ForeignKey(User.id))
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    tag = db.Column(db.String(256))
    content = db.Column(db.String(1024))
    comments = db.relationship('Comment', backref='commented_post')

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey(User.id))
    author_name = db.relationship('User', backref='comment_poster')
    content = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    post_id = db.Column(db.Integer, db.ForeignKey(CaseStudy.id))
    # replies = db.relationship('Reply', backref='replied_comment')

# Forms

class LoginForm(FlaskForm):
    username = StringField('Nom d\'utilisateur', validators=[DataRequired()])
    password = PasswordField('Mot de passe', validators=[DataRequired()])
    submit = SubmitField('Se connecter')

class RegisterForm(FlaskForm):
    username = StringField('Nom d\'utilisateur', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Mot de passe', validators=[DataRequired()])
    password_confirmation = PasswordField('Confirmer le mot de passe', validators=[DataRequired()])
    submit = SubmitField('S\'inscrire')

class CaseStudyCreationForm(FlaskForm):
    title = StringField('Titre', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    tag = StringField('Sujet', validators=[DataRequired()])
    pdf_file = FileField('Fichier PDF', validators=[FileRequired()])
    submit = SubmitField('Enregistrer')

class CommentCreationForm(FlaskForm):
    content = TextAreaField('Ajouter un commentaire', validators=[DataRequired()])
    submit = SubmitField('Enregistrer')

with app.app_context():
    db.create_all()
    db.session.commit()

projects = []

# Fonction pour compter les tokens
def count_tokens(messages, model="gpt-3.5-turbo"):
    encoding = tiktoken.encoding_for_model(model)
    num_tokens = 0
    for message in messages:
        num_tokens += len(encoding.encode(message["content"]))
    return num_tokens

# Fonction pour tronquer le texte
def truncate_text(text, max_tokens, model="gpt-3.5-turbo"):
    encoding = tiktoken.encoding_for_model(model)
    tokens = encoding.encode(text)
    if len(tokens) > max_tokens:
        tokens = tokens[:max_tokens]
    return encoding.decode(tokens)
    

@app.route('/favicon.ico')
def favicon():
    return app.send_static_file('favicon.ico')

@app.route('/')
def root():
    return render_template('index.html')

@app.route('/index')
def index():
    return redirect(url_for('root'))

@login_manager.user_loader
def load_user(id):
    return db.session.get(User, int(id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        flash('Utilisateur déjà connecté', 'error')
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        print("user?", db.session.scalar(sa.select(User)))
        user = db.session.scalar(
            sa.select(User).where(User.username == form.username.data))
        
        if user is None or not user.check_password(form.password.data):
            flash('Nom d\'utilisateur ou mot de passe incorrect', 'error')
            return redirect(url_for('login'))
        
        login_user(user, remember=False)
        return redirect(url_for('index'))
    return render_template('login.html', title='Connexion', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegisterForm()
    if form.validate_on_submit():
        if form.password.data != form.password_confirmation.data:
            flash('Les mots de passe ne correspondent pas', 'error')
            return redirect(url_for('register'))

        user = db.session.scalar(
            sa.select(User).where(User.username == form.username.data))
        if user is not None:
            flash('Nom d\'utilisateur existe déjà', 'error')
            return redirect(url_for('register'))
        
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        print("added user!", db.session.scalar(sa.select(User)))
        return redirect(url_for('index'))
    return render_template('register.html', title='Inscription', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/case-studies')
def case_studies():
    case_studies = CaseStudy.query.order_by(CaseStudy.date_posted)
    case_study_form = CaseStudyCreationForm()
    return render_template('case-studies.html', case_studies=case_studies, case_study_form=case_study_form, current_user=current_user)

@app.route('/create-case-study', methods=['POST'])
def create_case_study():
    if not current_user.is_authenticated:
        flash('Veuillez vous connecter', 'error')
        return redirect(url_for('login'))
    
    form = CaseStudyCreationForm()
    f = form.pdf_file.data
    filename = secure_filename(f.filename)
    path = os.path.join(app.instance_path, "uploads", filename)
    f.save(path)
    text = extract_text_from_pdf(path)
    content = generate_case_study(text)
    study = CaseStudy(
        title=form.title.data,
        pdf_file_text=text, 
        pdf_file_path=path, 
        tag=form.tag.data, 
        description=form.description.data,
        author_id=current_user.id,
        content=content
    )
    db.session.add(study)
    db.session.commit()

    return redirect(url_for('case_studies'))
    
@app.route('/case-study/<int:id>', methods=['GET', 'POST'])
def case_study(id):
    case_study = CaseStudy.query.get_or_404(id)
    all_comments = Comment.query.order_by(Comment.timestamp)
    comments = [comment for comment in all_comments if comment.post_id == id]
    comment_form = CommentCreationForm()
    return render_template('case-study.html', case_study=case_study, comments=comments, comment_form=comment_form, current_user=current_user)

@app.route('/case-study/<int:id>/delete')
def delete_case_study(id):
    case_study = CaseStudy.query.get_or_404(id)
    db.session.delete(case_study)
    db.session.commit()
    return redirect(url_for('case_studies'))

@app.route('/case-study/<int:id>/create-comment', methods=['POST'])
def create_comment(id):
    if not current_user.is_authenticated:
        flash('Veuillez vous connecter', 'error')
    user = load_user(current_user.id)

    form = CommentCreationForm()
    comment = Comment(content=form.content.data, author_id=user.id, post_id=id)
    db.session.add(comment)
    db.session.commit()

    return redirect(url_for(f'case_study', id=id))

@app.route('/case-study/<int:case_study_id>/delete-comment/<int:comment_id>')
def delete_comment(case_study_id, comment_id):
    comment = Comment.query.get_or_404(comment_id)
    db.session.delete(comment)
    db.session.commit()
    return redirect(url_for('case_study', id=case_study_id))

@app.route('/case-study/<int:id>/take-quiz')
def take_quiz(id):
    if not current_user.is_authenticated:
        flash('Veuillez vous connecter', 'error')

    case_study = CaseStudy.query.get_or_404(id)

    return render_template('quiz.html', id=id, case_study=case_study)

@app.route('/case-study/<int:id>/take-quiz/questions')
def quiz_questions(id):
    if not current_user.is_authenticated:
        flash('Veuillez vous connecter', 'error')

    study = db.session.scalar(sa.select(CaseStudy).where(CaseStudy.id == id))
    return generate_quiz(study.content)

if __name__ == "__main__":
    app.run(port=9000, debug=True)
