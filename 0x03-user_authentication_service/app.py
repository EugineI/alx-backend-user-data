#!/usr/bin/env python3
""" app with a single get root"""
from flask import Flask, request, jsonify, abort, make_response
from models.user import User
from auth import Auth
from api.v1.auth.auth import Auth

app = Flask(__name__)
AUTH = Auth()


@app.route("/", methods=["GET"])
def welcome():
    """Return a welcome message in JSON."""
    return jsonify({"message": "Bienvenue"})


@app.route("/users", methods=["POST"])
def users():
    """Register a new user if email is not already registered"""
    email = request.form.get("email")
    password = request.form.get("password")

    try:
        user = AUTH.register_user(email, password)
        return jsonify({"email": user.email, "message": "user created"})
    except ValueError:
        return jsonify({"message": "email already registered"}), 400


@app.route('/sessions', methods=['POST'])
def login():
    """Handle user login and create session"""
    email = request.form.get('email')
    password = request.form.get('password')

    if not email or not password:
        abort(401)

    user = auth.get_user_from_email(email)
    if not user or not user.is_valid_password(password):
        abort(401)
    session_id = auth.create_session(user.id)
    response = make_response(jsonify({"email": user.email,
                                      "message": "logged in"}))
    response.set_cookie("session_id", session_id)

    return response


@app.route('/profile', methods=['GET'])
def profile():
    """Retrieve user profile based on session cookie"""
    auth = Auth()
    session_id = request.cookies.get('session_id')
    if not session_id:
        abort(403)
    user = auth.get_user_from_session_id(session_id)
    if not user:
        abort(403)
    return jsonify({"email": user.email}), 200


@app.route('/reset_password', methods=['POST'])
def get_reset_password_token():
    """Handles password reset token generation"""
    email = request.form.get('email')
    if not email:
        abort(403)

    try:
        reset_token = auth.get_reset_password_token(email)
    except Exception:
        abort(403)

    return jsonify({"email": email, "reset_token": reset_token}), 200


@app.route('/reset_password', methods=['PUT'])
def update_password():
    """Update the user's password using a valid reset token"""
    email = request.form.get('email')
    reset_token = request.form.get('reset_token')
    new_password = request.form.get('new_password')

    try:
        auth.update_password(reset_token, new_password)
        return jsonify({"email": email, "message": "Password updated"}), 200
    except Exception:
        abort(403)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
