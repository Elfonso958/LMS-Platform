from flask import Blueprint, render_template, redirect, url_for, flash, request, session, current_app as app
from flask_login import login_user
from werkzeug.security import check_password_hash
from app.models import User
from app.main import fetch_and_assign_user_roles

import requests

auth_bp = Blueprint("auth", __name__)

ENVISION_AUTH_URL = "https://envision.airchathams.co.nz:8790/v1/Authenticate"

@auth_bp.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username_or_email = request.form.get("username", "").strip()
        entered_password = request.form.get("password", "").strip()  # Store entered password

        if not username_or_email or not entered_password:
            flash("Username and password are required.", "danger")
            return redirect(url_for("login"))

        user = User.query.filter((User.crew_code == username_or_email) | (User.email == username_or_email)).first()

        if not user:
            app.logger.warning(f"Login attempt failed: User not found ({username_or_email})")
            flash("User not found.", "danger")
            return redirect(url_for("login"))

        # Log user details for debugging
        app.logger.info(f"Login attempt: User ID={user.id}, Username={user.username}, Auth Type={user.auth_type}")

        # Determine authentication type
        if user.auth_type == "local":
            app.logger.info(f"User {user.username} is a local user. Verifying password...")

            stored_hashed_password = user.password  # Store hashed password for debugging
            is_password_correct = check_password_hash(stored_hashed_password, entered_password)

            # Log password comparison
            app.logger.info(f"Entered Password: {entered_password}")
            app.logger.info(f"Stored Hashed Password: {stored_hashed_password}")
            app.logger.info(f"Password Match: {is_password_correct}")

            if is_password_correct:
                app.logger.info(f"Password match successful for User ID={user.id}")
                login_user(user, remember=True)
                session.permanent = True
                flash("Login successful!", "success")
                return redirect(url_for("user_dashboard"))
            else:
                app.logger.warning(f"Password mismatch for User ID={user.id}")
                flash("Invalid username or password.", "danger")
                return redirect(url_for("login"))

        elif user.auth_type == "envision":
            app.logger.info(f"User {user.username} is an Envision user. Sending authentication request...")

            response = requests.post(
                ENVISION_AUTH_URL,
                json={"username": username_or_email, "password": entered_password, "nonce": "some_nonce"},
                verify=False  # ⚠️ Temporary! Use 'verify="path/to/cert.pem"' in production.
            )

            app.logger.info(f"Envision API Response: {response.status_code}, Content: {response.text}")

            if response.status_code == 200:
                data = response.json()
                token = data.get("token")

                if not token:
                    app.logger.warning(f"Envision login failed: No token received for User ID={user.id}")
                    flash("Authentication token missing from API response.", "danger")
                    return redirect(url_for("login"))

                session['auth_token'] = token
                login_user(user, remember=True)
                session.permanent = True
                flash("Login successful via Envision!", "success")
                fetch_and_assign_user_roles(user)
                return redirect(url_for("user_dashboard"))
            else:
                app.logger.warning(f"Envision login failed: Invalid credentials for User ID={user.id}")
                flash("Invalid username or password for Envision.", "danger")
                return redirect(url_for("login"))

        else:
            app.logger.error(f"Invalid authentication method for User ID={user.id}")
            flash("Invalid authentication method.", "danger")
            return redirect(url_for("login"))

    return render_template("login.html")