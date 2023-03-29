from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
import sqlalchemy.exc
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_gravatar import Gravatar
import os
from decouple import config
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = config('SECRET_KEY')
ckeditor = CKEditor(app)
Bootstrap(app)

# CREATE LOGIN MANAGER
login_manager = LoginManager()
login_manager.init_app(app)


# callback used to load user object from user ID stored in session
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# decorator to validate that current authenticated user is admin
def admin_only(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if current_user.is_anonymous or current_user.id != 1:
            return abort(403)

        return func(*args, **kwargs)
    return wrapper


# initialize Gravatar in Flask app with default parameters
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


# CONNECT TO DB
db_uri = os.getenv("DATABASE_URL")

# to fix SQLAlchemy no longer supporting PostgreSQL db addresses starting with 'postgres://'
if db_uri and db_uri.startswith("postgres://"):
    db_uri = db_uri.replace("postgres://", "postgresql://", 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.abspath(os.getcwd())+"/blog.db"

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# CONFIGURE TABLES

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author = relationship("User", back_populates="posts")
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship("Comment", back_populates="parent_post")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    author = relationship("User", back_populates="comments")
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    parent_post = relationship("BlogPost", back_populates="comments")
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))


# # for db creation after dropping previous db due to schema change, or for first push to Heroku production environment
# with app.app_context():
#     db.create_all()
#     db.session.commit()


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = CreateUserForm()
    if form.validate_on_submit():
        # create Python dictionary from form data
        user_dict = dict(request.form)
        # remove keys for columns that do not exist in database:
        filtered_user_dict = {key: user_dict[key] for key in user_dict if key in dir(User)}
        # hash user password and salt with string of given length
        filtered_user_dict['password'] = generate_password_hash(password=filtered_user_dict['password'],
                                                                method='pbkdf2:sha256',
                                                                salt_length=8)
        # noinspection PyArgumentList
        created_user = User(**filtered_user_dict)
        db.session.add(created_user)
        try:
            db.session.commit()
        except sqlalchemy.exc.IntegrityError:
            flash(f"Account for that email already exists. Log in here.", "error")
            return redirect(url_for('login'))

        # log in and authenticate after adding user to db
        login_user(created_user)

        return redirect(url_for('get_all_posts'))

    return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        entered_email = request.form['email']
        entered_password = request.form['password']

        user = User.query.filter_by(email=entered_email).first()

        if user is None:
            flash("That email does not exist. Please try again", "error")
            return redirect(url_for('login'))

        # compare hashed password in database to hashed user-entered password and authenticate if identical
        if check_password_hash(user.password, entered_password):
            login_user(user)
            return redirect(url_for('get_all_posts'))
        flash("Password incorrect. Enter valid password.", "error")
        return redirect(url_for('login'))

    return render_template("login.html", form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()

    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    form = CommentForm()
    if form.validate_on_submit():
        if current_user.is_anonymous:
            flash("Log in or register if you haven't already to post your comment.", "error")
            return redirect(url_for('login'))

        new_comment = Comment(
            text=form.text.data,
            author=current_user,
            parent_post=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for("show_post", post_id=post_id))

    return render_template("post.html", post=requested_post, form=form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


server_port = int(config("PORT", 8000))
if config("DATABASE_URL", False):
    debug_status = False
else:
    debug_status = True
if __name__ == "__main__":
    app.run(port=server_port, debug=debug_status)
