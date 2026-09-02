from functools import wraps

from flask_login import current_user

from flask import flash, redirect, url_for


def admin_required(func):

    @wraps(func)

    def wrapper(*args, **kwargs):

        if current_user.role != "Admin":

            flash("Access Denied")

            return redirect(url_for("dashboard"))

        return func(*args, **kwargs)

    return wrapper