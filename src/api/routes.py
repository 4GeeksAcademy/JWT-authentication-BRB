"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, User
from api.utils import generate_sitemap, APIException
from flask_cors import CORS
from flask_jwt_extended import create_access_token
from werkzeug.security import generate_password_hash, check_password_hash
api = Blueprint('api', __name__)

# Allow CORS requests to this API
CORS(api)


@api.route('/login', methods=['POST'])
def login():
        email_value = request.json.get("email")
        password = request.json.get("password")
        find_user = User.query.filter_by(email = email_value).first()

        if not find_user:
         return jsonify("no user found, try again!!"), 400
        
        if not check_password_hash(find_user.password, password):
         return jsonify("Incorrect password!"), 500

        token = create_access_token(identity = email_value)

        return jsonify(token_value = token), 200

# can turn into an object to make sure message can be shown in case incorrect password.


# look up api endpoint index and why that is used



@api.route('/signup', methods=['POST'])
def sign_up():
        email_value = request.json.get("email")
        password_value = request.json.get("password")
        find_user = User.query.filter_by(email = email_value).first()
        new_user = User(
                
            email = email_value,
            password = generate_password_hash(password_value)
        )

        db.session.add(new_user)
        db.session.commit()


        return jsonify("user created"), 200