import jwt

from os import getenv, path
from werkzeug.utils import secure_filename
from flask import redirect, session, flash
from functools import wraps
from datetime import datetime
from database import db, User, Image
from bidict import bidict
from mimetypes import guess_type

# Load the secret key from .env
secret_key = getenv("SECRET_KEY")

# Roles bi-dictionary map
roles = bidict({
    "admin": 1,
    "editor": 2,
    "member": 3
})
privilaged_roles = [1, 2]

# Vehicle types map
vehicle_types = {
    "bus": 1,
    "metro": 2
}

# Constant for Image Upload directory
UPLOAD_DIR= "static/images/upload"

def login_required(f):
    """
    Decorate routes to require login.

    https://flask.palletsprojects.com/en/latest/patterns/viewdecorators/
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get("user_id")
        # Check if the user_id exists in their session
        if user_id is None:
            return redirect("/login")
        
        # Check if user_role does not exist
        if session.get("user_role") is None:
            # Get the user's role from the database through their id
            role_id = db.session.query(User.role_id).where(User.id == session["user_id"]).one_or_none()
            # Role is None implies that the user does not exist in the database
            if role_id is None:
                # Log user out
                session.clear()
                flash("Authentication failed!", "danger")
                return redirect("/login")
            # Add it to their session 
            session["user_role"] = role_id
        
        return f(*args, **kwargs)

    return decorated_function

# Used with the help of the cs50 duck
def role_required(*provided_roles: str):
    """Decorate routes to require user_role"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not check_role(*provided_roles):
                flash("Forbidden route used!", "danger")
                return redirect("/", 403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def check_role(*provided_roles: str):
    """Check if the user's role and the provided role are equal"""
    # User role contains the id of a role object
    user_role_id = session.get("user_role")
    if user_role_id is not None and roles.inverse[user_role_id] in provided_roles:
        return True
    return False

def create_token(payload):
    return jwt.encode(payload, secret_key, "HS256")

def validate_token(token):
    """Validates jwt tokens and return the payload on correct validation"""
    try:
        # Decode the token
        payload = jwt.decode(token, secret_key, algorithms=["HS256"])
        # Check expiration
        if payload["exp"] and payload["exp"] < datetime.now().timestamp():
            raise jwt.ExpiredSignatureError
        return True, payload
    except jwt.ExpiredSignatureError:
        return False, "Token has expired!"
    except jwt.InvalidTokenError:
        return False, "Invalid token!"

def get_content_type_from_extension(filename):
    # Get the MIME type (content type) based on the file extension
    mime_type, _ = guess_type(filename)
    if mime_type:
        # Add the "image/" prefix to the MIME type
        content_type = "image/" + mime_type.split("/")[1]
        return content_type
    else:
        # Default to a generic image type if the extension is not recognized
        return "image/jpeg"  # You can change this default value as needed

def upload_images(images, index=True):
    # For database object model
    images_orm = []
    image_i = 0
    for image in images:   
        if not (image["image_data"].filename and image["title"] and image["image_data"]):
            return ValueError
        # Check for duplicate filename using os
        i = 0
        orignal_filename = image["image_data"].filename
        while path.exists(path.join(UPLOAD_DIR, image["image_data"].filename)):
            # Seperate name and extension
            name, extension = path.splitext(orignal_filename)
            # Update the filename to a non-duplicate one
            image["image_data"].filename = f"{secure_filename(name)}({i}){extension}"
            i += 1

        images_orm.append(Image(
            # If multiple images are provided, the title will be index with numbers inside brackets.
            title=f'{image["title"]}({image_i})' if image_i else image["title"],
            filename=image["image_data"].filename,
            user_id=session.get("user_id") 
        ))
        image_i = image_i + 1 if index else 0

        # Save the image to the upload directory(Exception may be raised)
        image["image_data"].save(f'{UPLOAD_DIR}/{image["image_data"].filename}')

    # Add the images database model
    db.session.add_all(images_orm)
    db.session.commit()
        