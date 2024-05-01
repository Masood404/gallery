import click

from os import remove, getenv, path, listdir
from base64 import b64encode
from flask import Flask, flash, render_template, redirect, session, request, jsonify, abort, send_from_directory
from flask_session import Session
from flask_mail import Mail, Message
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from werkzeug.datastructures import FileStorage
from datetime import datetime, timedelta
from sqlalchemy.exc import IntegrityError
from sqlalchemy import update, delete, and_ 
from form import RegistrationForm, LoginForm, ResetpasswordForm, ConfirmResetPasswordForm, ChangepasswordForm, ChangeusernameForm, ModifyEmailForm, ImageForm, UpdateImgTitleForm
from database import db, migrate, User, Email, Metadata, Image
from helpers import secret_key, roles, privilaged_roles, login_required, check_role, create_token, validate_token, upload_images, get_content_type_from_extension, UPLOAD_DIR

# Define flask app
app = Flask(__name__)

# Configure flask to have the secret loaded from the env file
app.config["SECRET_KEY"] = secret_key

# Configure SQLAlachemy
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///gallery.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db.init_app(app)
migrate.init_app(app)

# Configure session to use filesystem
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Confugure the usage of mail
app.config["MAIL_SERVER"] = getenv("MAIL_SERVER")
app.config["MAIL_USERNAME"] = getenv("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = getenv("MAIL_PASSWORD")
app.config["MAIL_PORT"] = getenv("MAIL_PORT")
app.config["MAIL_USE_SSL"] = getenv("MAIL_USE_SSL")
app.config["MAIL_DEFAULT_SENDER"] = app.config["MAIL_USERNAME"]
mail = Mail(app)

# Configure roles for rendering
app.config["PRIVILAGED_ROLES"] = privilaged_roles

# Custom command to initialize database tables for 'this' app
@click.command('init-db')
def init_db_command():
    """Initialize the database"""
    with app.app_context():
        # Create tables
        db.create_all()
        click.echo("Database initialized.")
 
app.cli.add_command(init_db_command)

@app.route("/")
@app.route("/home")
@login_required
def index():
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    # So much less line of code with these, i love these. SQL alchemy is also good.
    form = LoginForm(request.form)

    if request.method == "POST" and form.validate():
        # Get the user from the database
        user = db.session.query(User).where(User.username == form.username.data).one_or_none()
        # If they don't exist or their password is incorrect
        if user is None or not check_password_hash(user.hash, form.password.data): 
            form.username.errors.append("Invalid credentials!")
            return render_template("login.html", form=form)
        
        # Log them out first if logged in
        session.clear()

        # Log them in
        session["user_id"] = user.id
        session["user_role"] = user.role_id

        # Success
        flash("Logged in!", "success")
        return redirect("/")

    return render_template("login.html", form=form)

@app.route("/logout")
def logout():
    # Aka logout, technically
    session.clear()

    flash("Logged out!", "warning")
    return redirect("/")

@app.route("/register", methods=["GET", "POST"])
@app.route("/register/<r_role>", methods=["GET", "POST"])
def register(r_role=None):
    # Checks if a requested role was provided in the url.
    r_role = "member" if r_role is None else r_role.lower()

    # Check if the requested role exists.
    role_id = roles[r_role] if r_role in roles else None

    if role_id is None:
        flash("This user type does not exist!", "danger")
        return redirect("/register")
    
    is_first_admin = False
    
    # Check if role is admin. This 'if' block will be ignored if an admin is logged in a session.
    if role_id in privilaged_roles and not check_role("admin"):
        # Check metadata for if the first admin is registered
        metadata = db.session.query(Metadata).where(Metadata.key == "first_admin_registered").one_or_none()
        if metadata is not None:
            flash("Forbidden route used!", "danger")
            return redirect("/")
        # Then lets check if an admin 'really' does not exist
        admin = db.session.query(User).where(User.role_id == roles["admin"]).first()
        if admin is not None:
            flash("Forbidden route used!", "danger")
            return redirect("/")
        
        is_first_admin = True
        
        # Else lets continue with the registeration out of this 'if' block

    # Wtforms are cool :D
    form = RegistrationForm(request.form)

    if request.method == "POST" and form.validate():
        # Generate a hash for the password
        user_hash = generate_password_hash(form.password.data)
        # Define user record
        user = User(
            username=form.username.data,
            hash=user_hash,
            role_id=role_id
        )
        # Add user record to the database
        db.session.add(user)

        # Check if email is provided
        if form.email.data:
            # Define email record
            email = Email(
                email_address=form.email.data,
                user=user
            )
            # Add email record to the database
            db.session.add(email)
        
        # Check if this was the registeration for the first admin
        if is_first_admin:
            # Add metadata that the firstadmin is registered
            metadata = Metadata(
                key="first_admin_registered"
            )
            db.session.add(metadata)
        
        # Default images for the user
        default_images = []
        default_dir = "static/images/default"
        for filename in listdir(default_dir):
            file_path = path.join(default_dir, filename)
            # Check if the file is not another directory
            if path.isfile(file_path):
                name, extension = path.splitext(filename)
                if extension in [".jpg", ".png", ".gif", ".webp"]:
                    # Open stream(s)
                    file = open(file_path, "r+b")  
                    content_type = get_content_type_from_extension(filename)

                    # File Storage object is needed to upload images
                    file_storage_obj = FileStorage(
                        stream=file,
                        filename=filename,
                        content_type=content_type
                    )

                    default_images.append({
                        "title": name,
                        "image_data": file_storage_obj
                    })

        try:
            db.session.commit()
        except IntegrityError as e:
            db.session.rollback()
            if "UNIQUE constraint failed: users.username" in str(e):
                form.username.errors.append("Username is already taken! Please choose another one.")
            elif "UNIQUE constraint failed: emails.email" in str(e):
                form.email.errors.append("Email is already in use.")
            # Lets re-render the the template with custom errors being appended in the form
            return render_template("register.html", form=form, title=r_role.capitalize())
        
        # Log user in
        session["user_id"] = user.id
        session["user_role"] = user.role_id

        try:
            # Upload images. The streams needs to be opened for this
            upload_images(default_images, False)
        except (IntegrityError, FileNotFoundError):
            db.session.rollback()
            session.clear()

            flash("Unexpected error while adding default images for the user!", "danger")
            return redirect("/")

        # Close all the streams
        for image in default_images:
            image["image_data"].stream.close()

        # Success
        flash("Registered!", "success")
        return redirect("/")

    return render_template("register.html", form=form, title=r_role.capitalize())

@app.route("/reset_password", methods=["GET", "POST"])
@app.route("/forgot_password", methods=["GET", "POST"])
def reset_password():

    token = request.args.get("token")
    if token:
        # Validate token 
        valid, result = validate_token(token)
        if not valid:
            flash(result, "danger")
            return redirect("/")
        
        form = ConfirmResetPasswordForm(request.form)
        
        if request.method == "POST" and form.validate():
            # Generate a new hash for the user
            hash = generate_password_hash(form.password.data)
            # Lets first also query for the user so we could log them in with their role.
            user = db.session.query(User).where(User.id == result["user_id"]).one_or_none()
            if user is None:
                flash("Unexpected, user does not exist!", "danger")
                return redirect("/", 403)
            # Lets now update the user's hash using orm sqlalchemy 
            user.hash = hash
            db.session.commit()

            # Lets be generous, log the user in.
            session["user_id"] = user.id
            session["user_role"] = user.role_id

            # Success
            flash("Password successfully changed!", "success")
            return redirect("/")

        return render_template("confirm_reset_pass.html", form=form)

    form = ResetpasswordForm(request.form)

    if request.method == "POST" and form.validate():
        # Check if the email exists and get the associated user
        user = (db.session.query(User)
                .join(Email, User.id == Email.user_id)
                .where(Email.email_address == form.email.data)
                .one_or_none()
                )
        if user is not None:
            # Expiry minutes
            exp_min = 3 
            # Token payload for the reset link
            payload =  {
                "user_id": user.id,
                "exp": (datetime.now() + timedelta(minutes=exp_min)).timestamp() # Expiry of the token is is some minutes after its issue
            }

            # Reset link
            link = f"{request.url}?token={create_token(payload)}"

            # Construct a mail message
            msg = Message(subject="Gallery: Reset Password", 
                           recipients=[form.email.data],
                           sender="yaquobimasood@gmail.com")
            
            # Have the reset link the the body as a hyperlink
            msg.body=f'Click <a href="{link}>here</a> to reset your password for Next Stop."'
            msg.html = render_template("email/reset_pass.html", reset_link=link, username=user.username)
            # Send the reset link mail
            mail.send(msg)
        
        # 'Generic' Success
        flash(f"A link has been send to {form.email.data} if it is registered.", "info")
        return redirect(request.url)
        
    return render_template("reset_password.html", form=form)
            
@app.route("/account", methods=["GET", "POST"])
def account():
    user_id = session.get("user_id")

    # Give prefixes as we are using multiple forms
    username_form = ChangeusernameForm(prefix="username")
    password_form = ChangepasswordForm(prefix="password")
    email_form = ModifyEmailForm(user_id, prefix="email")

    if request.method == "POST":
        # Handle change username form
        if username_form.submit.data and username_form.validate():
            # Update username using sqlalchemy core
            stmt = (update(User)
                    .where(User.id == user_id)
                    .values(username=username_form.username.data))
            db.session.execute(stmt)
            try:
                db.session.commit()
                flash("Username successfully changed!", "success")
                return redirect("/account")
            except IntegrityError:
                db.session.rollback()
                username_form.username.errors.append("Username already taken! Please choose another one.")

        # Handle change for password
        elif password_form.submit.data and password_form.validate():
            # For this one, lets update user's password/hash using sqlalchemy orm because we also need to compare the old_password
            user = (db.session.query(User)
                    .where(User.id == user_id)
                    .one_or_none())
            # Extra check, if user does not exist
            if user is None:
                flash("Unexpected, user does not exist!", "danger")
                return redirect("/", 403)
            # Old Password check
            if check_password_hash(user.hash, password_form.old_password.data):
                # Generate new hash
                hash = generate_password_hash(password_form.new_password.data)
                user.hash = hash
                db.session.commit()
                flash("Password successfully changed!", "success")
                return redirect("/account")
            # Else
            password_form.old_password.errors.append("Incorrect old password!")
        
        # Handle the email submission
        elif email_form.submit.data and email_form.validate():
            # Insert email using sqlachemy's orm
            email = Email(
                email_address=email_form.email.data,
                user_id=user_id
            )
            db.session.add(email)
            try:
                db.session.commit()
                flash("Successfully added email address to account!", "success")
                return redirect("/account")

            except IntegrityError:
                db.session.rollback()
                email_form.email.errors.append("Unable to add new email!") # Generic message for security
            
        # Handle email deletion
        elif email_form.delete.data and email_form.validate():
            # Delete email using sqlalchemy's core
            stmt = (delete(Email)
                    .where(and_(Email.id == email_form.select.data, Email.user_id == user_id)))
            db.session.execute(stmt)
            db.session.commit()

            flash("Email successfully deleted from your account!", "success")
            return redirect("/account")                              
            
    return render_template("account.html", username_form=username_form, password_form=password_form, email_form=email_form)

@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    """ Handle route to upload images to the database and to the folder directory of static/images/upload"""
    form = ImageForm()

    if request.method == "POST" and form.validate():
        # Get the Image's file object
        images_data = form.images.data
        
        images = []

        for image_data in images_data:
            images.append({
                "title": form.title.data,
                "image_data": image_data
            })

        try:
            upload_images(images)
            flash("Successfully uploaded image(s)", "success")
        except (IntegrityError, FileExistsError):
            form.images.errors.append("Unable to add image, please change the filename and try again.")
    
    return render_template("upload.html", form=form)

@app.route(f"/{UPLOAD_DIR}/<filename>")
@login_required
def get_uploaded_image(filename):
    """ Handle the upload route for images so they only return requested image if that image belongs to that user """
    image = (db.session.query(Image)
             .where(and_(Image.user_id == session.get("user_id"), Image.filename == filename)) # Authorize user and filter by the filename
             .first())
    if image is None:
        abort(404) 
    return send_from_directory(UPLOAD_DIR, filename)

@app.route("/get_images")
@login_required
def get_images():
    try:
        """ Handle route to get the images models of a user for their gallery """
        # Amount of images to return from the database
        amount = int(request.args.get("amount"))
        """ 
        The offset of returned images. Example if there are 20 images in db, the amount is 10 and the offset is 5. 
        Then we will return the all images between 5 and 15. This pagination design helps us better for loading meaning as
        the user scrolls we will load new images.
        """
        offset = int(request.args.get("offset"))
    except TypeError:
        return jsonify({
            "error": "Query parmeters 'amount' and 'offset' are in in incorrect format or they are not provided!"
        }), 400
    
    # Optional search query
    q = request.args.get('q')
    # Optional search query statement with sqlalchemy. When no query is provided, by default should return true for every result.  
    search = Image.title.ilike(f'%{q}%') if q else True

    # Query the images
    images = (db.session.query(Image)
              .where(and_(Image.user_id == session.get("user_id"), search))
              .order_by(Image.upload_date)
              .limit(amount)
              .offset(offset)
              .all())
    
    # Put them in a list
    image_list = []
    for image in images:
        image_list.append({
            "id": image.id,
            "title": image.title,
            "path": f"/{UPLOAD_DIR}/{image.filename}",
            "upload_date": image.upload_date.strftime("%Y-%m-%d %h:%m:%s")
        })
    
    # Convert and return them in json
    return jsonify(image_list)

@app.route("/update_image_title", methods=["POST"])
@login_required
def update_image_title():
    """ Route to update an image's title especially used for async api functions """
    form = UpdateImgTitleForm()

    if form.validate():
        # Update the image title using sqlalchemy core
        stmt = (update(Image)
                .where(and_(Image.user_id == session.get("user_id"), Image.id == form.id.data))
                .values(title=form.title.data))
        db.session.execute(stmt)
        db.session.commit()
        return jsonify({
            "success": "Successfully updated image title."
        })
        
    
    # Return comma seperated form errors in json
    return jsonify({
        "error": ", ".join(form.errors)
    }), 400

@app.route("/delete_images", methods=["POST"])
@login_required
def delete_images():
    # Get the list of ids of images
    delete_list = request.get_json().get("delete_list")
    # Get the image object model from the database
    images = (db.session.query(Image)
            .where(and_(Image.id.in_(delete_list), Image.user_id == session.get("user_id")))
            .all())
    # Delete from database
    for image in images:
        db.session.delete(image)
    # Delete actual image file
    for image in images:
        file_path = f"{UPLOAD_DIR}/{image.filename}"
        if path.exists(file_path):
            remove(file_path)
            
    db.session.commit()

    return jsonify({
        "success": "Image(s) successfully deleted!"
    })

@app.route("/credits")
def credits():
    return render_template("credits.html")