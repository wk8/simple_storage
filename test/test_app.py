from flask import Flask, Response as FlaskResponse
from flask.testing import FlaskClient

import json
import pytest
import random
import re
import string
import uuid

from app import app
from database import db_session
from models import User, UserToken

JSON_CONTENT_TYPE = 'application/json'


class Client(FlaskClient):
    def open(self, *args, **kwargs):
        if 'json' in kwargs:
            kwargs['data'] = json.dumps(kwargs.pop('json'))
            if 'content_type' not in kwargs:
                kwargs['content_type'] = JSON_CONTENT_TYPE

        return super(Client, self).open(*args, **kwargs)


class Response(FlaskResponse):
    @property
    def json(self):
        content_type = self.headers.get('content-type')
        if content_type != JSON_CONTENT_TYPE:
            raise AssertionError('Unexpected content-type: %s' % (content_type, ))

        return json.loads(self.data)


app.test_client_class = Client
app.response_class = Response
app.config['TESTING'] = True


# FIXME: empty DB for each test!!
@pytest.fixture
def client():
    yield app.test_client()


# FIXME: remove?
def test_empty_db(client):
    reply = client.get('/')
    assert reply.data == b'Hello, World!'


def test_register_new_user_happy_path(client):
    name = generate_username()
    password = generate_password()
    reply = client.post('/register', json={'username': name, 'password': password})

    assert reply.status_code == 204
    assert len(reply.data) == 0

    # the user should exist in the DB
    user = db_session.query(User).filter(User.name == name).first()
    assert user is not None
    # and it should have the right password
    assert user.is_valid_password(password)
    assert not user.is_valid_password('not_the_right_password')


def test_register_new_user_already_exists(client):
    name = generate_username()
    password = generate_password()

    # let's create a new user
    reply = client.post('/register', json={'username': name, 'password': password})
    assert reply.status_code == 204

    # and then try to create it again
    reply = client.post('/register', json={'username': name, 'password': password})
    assert_error_json(reply, 'User already exists', 409)


def test_register_new_user_missing_content_type_header(client):
    name = generate_username()
    password = generate_password()

    body = {'username': name, 'password': password}
    reply = client.post('/register', json=body, content_type=None)

    assert_error_json(reply, 'Please send a valid JSON with the appropriate Content-Type header')


def test_register_new_user_not_a_json(client):
    reply = client.post('/register', data='i aint a JSON', content_type=JSON_CONTENT_TYPE)
    assert_error_json(reply, 'Please send a valid JSON with the appropriate Content-Type header')


def test_register_new_user_username_too_short(client):
    name = generate_username(User.NAME_MIN_LENGTH - 1)
    password = generate_password()

    reply = client.post('/register', json={'username': name, 'password': password})

    assert_error_json(reply, "Invalid input: '%s' is too short" % (name, ))


def test_register_new_user_username_too_long(client):
    name = generate_username(User.NAME_MAX_LENGTH + 1)
    password = generate_password()

    reply = client.post('/register', json={'username': name, 'password': password})

    assert_error_json(reply, "Invalid input: '%s' is too long" % (name, ))


def test_register_new_user_password_too_short(client):
    name = generate_username()
    password = generate_password(User.PASSWORD_MIN_LENGTH - 1)

    reply = client.post('/register', json={'username': name, 'password': password})

    assert_error_json(reply, "Invalid input: '%s' is too short" % (password, ))


def test_register_new_user_extra_field(client):
    name = generate_username()
    password = generate_password()

    reply = client.post('/register', json={'username': name, 'password': password, 'hey': 'ho'})

    msg = "Invalid input: Additional properties are not allowed ('hey' was unexpected)"
    assert_error_json(reply, msg)


def test_login_happy_path(client):
    name = generate_username()
    password = generate_password()

    user = User(name, password, db_session=db_session)
    user_id = user.id

    reply = client.post('/login', json={'username': name, 'password': password})

    assert reply.status_code == 200
    assert list(reply.json.keys()) == ['token']

    token = reply.json['token']
    assert re.match('^[a-f0-9]{64}$', token)

    assert UserToken.get_user_id_with_token(token) == user_id
    assert UserToken.get_user_id_with_token(token, db_session=db_session) == user_id

    # same prefix, but different suffix
    invalid_token = token[:32] + str(uuid.uuid4()).replace('-', '')
    assert UserToken.get_user_id_with_token(invalid_token) is None
    assert UserToken.get_user_id_with_token(invalid_token, db_session=db_session) is None

    # same suffix, but different prefix
    invalid_token = str(uuid.uuid4()).replace('-', '') + token[-32:]
    assert UserToken.get_user_id_with_token(invalid_token) is None
    assert UserToken.get_user_id_with_token(invalid_token, db_session=db_session) is None


def test_login_user_not_found(client):
    reply = client.post('/login', json={'username': 'i dont exist', 'password': 'x'})

    assert_error_json(reply, 'User not found', 404)


def test_login_wrong_password(client):
    name = generate_username()
    password = generate_password()

    user = User(name, password, db_session=db_session)

    reply = client.post('/login', json={'username': name, 'password': 'wrong password!'})

    assert_error_json(reply, 'Wrong password', 403)


def test_login_missing_content_type_header(client):
    name = generate_username()
    password = generate_password()

    body = {'username': name, 'password': password}
    reply = client.post('/login', json=body, content_type=None)

    assert_error_json(reply, 'Please send a valid JSON with the appropriate Content-Type header')


def test_login_not_a_json(client):
    reply = client.post('/login', data='i aint a JSON', content_type=JSON_CONTENT_TYPE)
    assert_error_json(reply, 'Please send a valid JSON with the appropriate Content-Type header')


################
# Test Helpers #
################


def assert_error_json(reply, message, status_code=400):
    assert reply.status_code == status_code
    assert reply.json == {'error': message}


def generate_username(length=None):
    if not length:
        length = random.randint(User.NAME_MIN_LENGTH, User.NAME_MAX_LENGTH)
    return random_string(length)


def generate_password(length=None):
    if not length:
        length = random.randint(User.PASSWORD_MIN_LENGTH, 100)
    return random_string(length)


def random_string(length):
    return ''.join([random.choice(string.ascii_letters + string.digits) for _ in range(length)])
