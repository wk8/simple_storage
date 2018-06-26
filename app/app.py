from flask import Flask, jsonify
import sqlalchemy

from database import db_session, init_db
from helpers import error_reply, validate_json
from models import User, UserToken
import json_schemas

app = Flask(__name__)
init_db()


@app.teardown_appcontext
def shutdown_session(exception=None):
    db_session.remove()


# FIXME: remove?
@app.route('/')
def hello_world():
    return 'Hello, World!'


@app.route('/register', methods=['POST'])
@validate_json(json_schemas.REGISTER_SCHEMA)
def register(json):
    try:
        user = User(json['username'], json['password'], db_session=db_session)

        return '', 204
    except sqlalchemy.exc.IntegrityError:
        return error_reply('User already exists', 409)


@app.route('/login', methods=['POST'])
@validate_json(json_schemas.LOGIN_SCHEMA)
def login(json):
    user = db_session.query(User).filter(User.name == json['username']).first()

    if not user:
        return error_reply('User not found', 404)

    if not user.is_valid_password(json['password']):
        return error_reply('Wrong password', 403)

    token = UserToken(user, db_session=db_session)

    return jsonify({'token': str(token)})
