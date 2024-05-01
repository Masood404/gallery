from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed, FileRequired, MultipleFileField
from flask_wtf.form import _Auto
from wtforms import StringField, PasswordField, EmailField, SubmitField, SelectField, HiddenField
from wtforms.validators import Length, Regexp, DataRequired, EqualTo, Email, Optional, ValidationError
from database import Email as Email_Model, db

username_length = Length(min=4, max=25, message="Minimum of 4 characters and Maximum of 25 characters for username!")
username_regex = Regexp(r"^[0-9A-Za-z@_\-]{4,25}$", message="""Username requires any letters, numbers or characters like
                            '@', '-', '_'. It must contain more thatn 6 characters but no more than 32""")

password_length = Length(min=8, max=32, message="Minimum of 8 characters and Maxiumum of 32 characters for password!")
password_regex = Regexp(r"^(?=.*?[0-9])(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[^0-9A-Za-z]).{8,32}", message="""Password requires at least one uppercase 
               letter, at least one lowercase letter, and at least one special character.""")

class RegistrationForm(FlaskForm):
    """Registration From model with flask-wts"""
    username = StringField("Username", validators=[
        username_length,
        username_regex,
        DataRequired("Empty username provided!")
    ], render_kw={
        "autofocus": True
    })
    email = EmailField("Email Address", validators=[
        Optional(),
        Email("Invalid email address provided!")
    ])
    password = PasswordField("Password", validators=[
        password_length,
        password_regex,
        EqualTo("confirmation", "Password and its confirmation must match!"),
        DataRequired("Empty password provided!")
    ])
    confirmation = PasswordField("Confirm Password")
    submit = SubmitField("Register")
    
class LoginForm(FlaskForm):
    """
    Login Form model with flask-wtf
    No more validators because the validators may be updated and the user's who have registered before 'that' update, they may not be able to log in again.
    """
    username = StringField("Username", validators={
        DataRequired("Empty username provided!") 
    })
    password = PasswordField("Password", validators=[
        DataRequired("Empty password provided!")
    ])
    submit = SubmitField("Login")

class ChangeusernameForm(FlaskForm):
    """Change username form for the account page"""
    username = StringField("New Username", validators=[
        username_length,
        username_regex,
        DataRequired("Empty field provided for new username!")
    ])

    submit = SubmitField("Change Username")

class ChangepasswordForm(FlaskForm):
    """Change password form for the account page"""
    # Not gonna validate it against length and regex due to possible validators upate
    old_password = PasswordField("Old Password", validators=[
        DataRequired("Empty field provided for old password!")
    ])
    new_password = PasswordField("New Password", validators=[
        password_length, 
        password_regex,
        EqualTo("confirmation", "New password and its confirmation must match!"),
        DataRequired("Empty field provided for new password!")
    ])
    confirmation = PasswordField("Confrim New Password") # No need for validator as new_password field will validate for it

    submit = SubmitField("Change Password")

    def validate_old_password(form, field):
        if form.new_password.data == field.data:
            raise ValidationError("Old Password and New Password Must be different!")

class ResetpasswordForm(FlaskForm):
    """Reset/Forgot password form with flask-wtf"""

    email = EmailField("Email Address", validators=[
        Email("Invalid email address provided!"),
        DataRequired("Email address not provided")
    ], render_kw={
        "autofocus": True
    })
    submit = SubmitField("Send Link")

class ConfirmResetPasswordForm(FlaskForm):
    """Form to confirm the reset of a user's password"""

    password = PasswordField("New Password", validators=[
        password_length,
        password_regex,
        EqualTo("confirmation", "Password and its confirmation must match"),
        DataRequired("Empty password provided!")
    ], render_kw={
        "autofocus": True
    })
    confirmation = PasswordField("Confirm New Password")
    submit = SubmitField("Reset Password")

class ModifyEmailForm(FlaskForm):
    """Form to add or delete email addresses. Takes in an argument user_id to query the database for their emails."""
    select = SelectField("Modify Email Addresses", validators=[
        DataRequired("Empty selection provided")
    ])
    email = EmailField("Email Address", validators=[
        Optional(),
        Email("Invalid email address!")
    ])

    submit = SubmitField("Submit")
    delete = SubmitField("Delete", render_kw={"hidden": True}) # For the first render, hide the delete button. The render should be down by javascript.

    def __init__(self, user_id, *args,  **kwargs):
        super().__init__(*args, **kwargs)

        self.select.choices = [("add_email", "Add email address")]

        # Query the user's emails
        emails = (db.session.query(Email_Model)
                  .where(Email_Model.user_id == user_id)
                  .all())
        
        for email in emails:
            self.select.choices.append((email.id, email.email_address))

title_validators = [
    Length(min=3, max=100, message="Minimum of 3 characters and Maximum of 100 characters for image's title!"),
    Optional()
]

class ImageForm(FlaskForm):
    """Form to upload images"""
    title = StringField("Title", validators=title_validators)
    images = MultipleFileField("Image", validators=[
        FileAllowed(["jpg", "png", "gif", "webp"], "Unsupported file extenstion!"),
        FileRequired("No Image File was provided!")
    ])

    submit = SubmitField("Upload")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Check for empty title
        if self.title.data is None or not self.title.data.strip():
            self.title.data = "Untitled"

class UpdateImgTitleForm(FlaskForm):
    # Disable csrf protection because of restful api
    class Meta:
        csrf = False

    title = StringField("Title", validators=title_validators)
    id = HiddenField("Image id")

    def validate_id(self, field):
        try:
            # Also checks for if the field can be converted to type int
            if int(field.data) < 1:
                raise TypeError
        except:
            field.errors.append("Id must be a positive integer!")
