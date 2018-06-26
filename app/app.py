from flask import Flask
import sqlalchemy

from database import db_session, init_db
from helpers import error_reply, validate_json
from models import User
import json_schemas

app = Flask(__name__)
init_db()


# FIXME: remove?
@app.route('/')
def hello_world():
    return 'Hello, World!'


@app.route('/register', methods=['POST'])
@validate_json(json_schemas.REGISTER_SCHEMA)
def register(json):
    try:
        user = User(json['username'], json['password'])

        db_session.add(user)
        db_session.commit()

        return '', 204
    except sqlalchemy.exc.IntegrityError:
        return error_reply('User already exists', 409)
