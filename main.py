from flask import Flask, render_template, redirect, url_for, flash , request , abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash 
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm , RegisterForm , Loginform , CommentForm
from flask_gravatar import Gravatar

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


##CONFIGURE TABLES
class User(db.Model , UserMixin):
    __tablename__ = "User"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")


class BlogPost(db.Model):
    __tablename__ = "BlogPost"
    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    #Create Foreign Key, "users.id" the users refers to the tablename of User.
    author_id = db.Column(db.Integer, db.ForeignKey("User.id"))
    #Create reference to the User object, the "posts" refers to the posts protperty in the User class.
    author = relationship("User", back_populates="posts")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)

    author_id = db.Column(db.Integer, db.ForeignKey("User.id"))
    comment_author = relationship("User", back_populates="comments")
db.create_all()



@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts , is_logged_in = current_user.is_authenticated ,)


@app.route('/register' , methods=['GET','POST'])
def register():
    register_form = RegisterForm()
    
    if request.method == 'POST':
        user = User(username = register_form.username.data ,
        email = register_form.email.data ,
        password = generate_password_hash(password = register_form.password.data ,
                                              method='pbkdf2:sha256',
                                              salt_length=8))

        #If user's email already exists

        if User.query.filter_by(username = user.username).first():
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))
            


        db.session.add(user)
        db.session.commit()

        login_user(user)

        return redirect(url_for('get_all_posts'))
    
    return render_template("register.html" , form = register_form , is_logged_in = current_user.is_authenticated)


@app.route('/login' , methods = ['GET','POST'])
def login():
    login_form = Loginform()
    if request.method == "POST":
        username = login_form.username.data
        password = login_form.password.data
        
        #Find user by email entered.
        user = User.query.filter_by(username = username).first()

        # If the email doesn't exist
        if user == None:
            flash("This username does not exist, please try again.")
            return render_template("login.html", form = login_form , is_logged_in = current_user.is_authenticated)
        
        #Check stored password hash against entered password hashed.
        if check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('get_all_posts'))
        else:
            flash('Password is incorrect, please try again.')


    return render_template("login.html" , form = login_form , is_logged_in = current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))
    

@app.route("/post/<int:post_id>")
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    comment_form = CommentForm()
    return render_template("post.html", post=requested_post ,form = comment_form ,is_logged_in = current_user.is_authenticated)


@app.route("/about")
def about():
    return render_template("about.html" , is_logged_in = current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html" , is_logged_in = current_user.is_authenticated)


@app.route("/new-post" , methods = ['GET','POST'])
def add_new_post():
    if current_user.id == 1:
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
        return render_template("make-post.html", form=form , is_logged_in = current_user.is_authenticated)
    else:
        abort(403)

@app.route("/edit-post/<int:post_id>")
def edit_post(post_id):
    if current_user.id == 1:
        post = BlogPost.query.get(post_id)
        edit_form = CreatePostForm(
            title=post.title,
            subtitle=post.subtitle,
            img_url=post.img_url,
            author=post.author,
            body=post.body
        )
        if edit_form.validate_on_submit():
            post.title = edit_form.title.data
            post.subtitle = edit_form.subtitle.data
            post.img_url = edit_form.img_url.data
            post.author = edit_form.author.data
            post.body = edit_form.body.data
            db.session.commit()
            return redirect(url_for("show_post", post_id=post.id))

        return render_template("make-post.html", form=edit_form , is_logged_in = current_user.is_authenticated)
    else:
        return abort(403)

@app.route("/delete/<int:post_id>")
def delete_post(post_id):
    if current_user.id == 1:
        post_to_delete = BlogPost.query.get(post_id)
        db.session.delete(post_to_delete)
        db.session.commit()
        return redirect(url_for('get_all_posts'))
    else:
        abort(403)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000 , debug=True)
