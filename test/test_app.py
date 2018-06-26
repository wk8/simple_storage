from flask import Flask, Response as FlaskResponse
from flask.testing import FlaskClient

import hashlib
import json
import os
import pytest
import random
import re
import string
import tempfile
import uuid

from app.database import init_db
from app import create_app
from app.models import User, UserToken

JSON_CONTENT_TYPE = 'application/json'


class Client(FlaskClient):
    def open(self, *args, **kwargs):
        if 'json' in kwargs:
            kwargs['data'] = json.dumps(kwargs.pop('json'))
            if 'content_type' not in kwargs:
                kwargs['content_type'] = JSON_CONTENT_TYPE
        elif 'fixture' in kwargs:
            fixture = kwargs.pop('fixture')

            path = fixture_path(fixture)
            _, content_type = os.path.splitext(path)
            kwargs['content_type'] = content_type[1:]

            with open(path, 'rb') as input_file:
                kwargs['data'] = input_file.read()

        if 'token' in kwargs:
            headers = kwargs.get('headers', {})
            headers['X-Session'] = kwargs.pop('token')
            kwargs['headers'] = headers

        return super(Client, self).open(*args, **kwargs)


class Response(FlaskResponse):
    @property
    def json(self):
        content_type = self.headers.get('content-type')
        if content_type != JSON_CONTENT_TYPE:
            raise AssertionError('Unexpected content-type: %s' % (content_type, ))

        return json.loads(self.data)


@pytest.fixture
def db_session():
    with tempfile.NamedTemporaryFile() as temp_db:
        yield init_db(temp_db.name)


@pytest.fixture
def client(db_session):
    app = create_app(db_session=db_session)

    app.test_client_class = Client
    app.response_class = Response
    app.config['TESTING'] = True

    yield app.test_client()


#######################
# Test POST /register #
#######################


def test_register_new_user_happy_path(client, db_session):
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


####################
# Test POST /login #
####################


def test_login_happy_path(client, db_session):
    name = generate_username()
    password = generate_password()

    user = User(name, password, db_session=db_session)
    user_id = user.id

    reply = client.post('/login', json={'username': name, 'password': password})

    assert reply.status_code == 200
    assert list(reply.json.keys()) == ['token']

    token = reply.json['token']
    assert re.match('^[a-f0-9]{64}$', token)

    assert UserToken.get_user_id_with_token(token, db_session) == user_id

    # same prefix, but different suffix
    invalid_token = token[:32] + str(uuid.uuid4()).replace('-', '')
    assert UserToken.get_user_id_with_token(invalid_token, db_session) is None

    # same suffix, but different prefix
    invalid_token = str(uuid.uuid4()).replace('-', '') + token[-32:]
    assert UserToken.get_user_id_with_token(invalid_token, db_session) is None


def test_login_user_not_found(client):
    reply = client.post('/login', json={'username': 'i dont exist', 'password': 'x'})

    assert_error_json(reply, 'User not found', 404)


def test_login_wrong_password(client, db_session):
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


#######################
# Test files endpoint #
#######################


# our fixtures' SHA1 hashes
SHA1S = {
    'happy_bunnies.jpg': '0e96d3e45f7d91da9a153386de498c67ccad18b2',
    'sad_bunny.jpg':     'bd4ec98b1d918bd1859eec4e2fbd47de3009624c'
}


def test_files_happy_path(client, db_session):
    token = get_valid_token(db_session)

    # the list of our files should be empty
    reply = get_list_files_and_check_reply(client, token)
    assert reply.json == []

    # now let's push some bunnies
    fixture_name_1 = 'happy_bunnies.jpg'
    route_1 = '/files/%s' % (fixture_name_1, )

    push_file_and_check_reply(client, token, route_1)

    # now let's try to retrieve it
    retrieve_jpg_and_check_reply(client, token, route_1)

    # and now our list of files should contain this entry
    reply = get_list_files_and_check_reply(client, token)
    assert reply.json == [fixture_name_1]

    # now let's push another file
    fixture_name_2 = 'sad_bunny.jpg'
    route_2 = '/files/%s' % (fixture_name_2, )

    push_file_and_check_reply(client, token, route_2)
    retrieve_jpg_and_check_reply(client, token, route_2)

    # our list of files should contain that too
    reply = get_list_files_and_check_reply(client, token)
    assert reply.json == [fixture_name_1, fixture_name_2]

    # now let's delete the 1st image
    delete_file_and_check_reply(client, token, route_1)

    # trying to retrieve it should yield a 404
    reply = client.get(route_1, token=token)
    assert reply.status_code == 404

    # and our lists should only contain the 2nd one now
    reply = get_list_files_and_check_reply(client, token)
    assert reply.json == [fixture_name_2]

    # can't hurt to check the 2nd file's data is unaffected
    retrieve_jpg_and_check_reply(client, token, route_2)

    # now let's delete it too
    delete_file_and_check_reply(client, token, route_2)
    reply = client.get(route_2, token=token)
    assert reply.status_code == 404

    # the list of our files should be empty again
    reply = get_list_files_and_check_reply(client, token)
    assert reply.json == []

    # trying to delete again should yield a 404 too
    reply = client.delete(route_2, token=token)
    assert reply.status_code == 404


def test_files_overwrite(client, db_session):
    token = get_valid_token(db_session)
    route = '/files/bunnies'

    fixture_name_1 = 'happy_bunnies.jpg'
    push_file_and_check_reply(client, token, route, fixture_name=fixture_name_1)
    retrieve_jpg_and_check_reply(client, token, route, fixture_name=fixture_name_1)

    # now let's overwrite it
    fixture_name_2 = 'sad_bunny.jpg'
    push_file_and_check_reply(client, token, route, fixture_name=fixture_name_2)
    retrieve_jpg_and_check_reply(client, token, route, fixture_name=fixture_name_2)


def test_files_same_filename_different_users(client, db_session):
    route = '/files/bunnies'

    token_1 = get_valid_token(db_session, 'user1')
    fixture_name_1 = 'happy_bunnies.jpg'
    push_file_and_check_reply(client, token_1, route, fixture_name=fixture_name_1)
    retrieve_jpg_and_check_reply(client, token_1, route, fixture_name=fixture_name_1)

    token_2 = get_valid_token(db_session, 'user2')
    fixture_name_2 = 'sad_bunny.jpg'
    push_file_and_check_reply(client, token_2, route, fixture_name=fixture_name_2)
    retrieve_jpg_and_check_reply(client, token_2, route, fixture_name=fixture_name_2)

    # didn't overwrite user 1's file
    retrieve_jpg_and_check_reply(client, token_1, route, fixture_name=fixture_name_1)


def test_invalid_token(client):
    bogus_tokens = ['2ec4ef6596ee4df4bf2eb203db4bab656407b7f875b74a4eb1a68f349b571b9c',
                    'Z' * 64,
                    'hello']

    for token in bogus_tokens:
        reply = client.get('/files', token=token)
        assert_error_json(reply, 'Invalid token', 401)


################
# Test Helpers #
################


def get_valid_token(db_session, username=None):
    if username is None:
        username = generate_username()

    user = User(username, generate_password(), db_session=db_session)
    return str(UserToken(user, db_session=db_session))


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


def fixture_path(filename):
    return os.path.join(os.path.dirname(__file__), 'fixtures', filename)


def push_file_and_check_reply(client, token, route, fixture_name=None):
    if fixture_name is None:
        fixture_name = os.path.basename(route)

    reply = client.put(route, token=token, fixture=fixture_name)

    assert reply.status_code == 201
    assert reply.headers['Location'] == 'http://localhost%s' % (route, )

    return reply


def retrieve_jpg_and_check_reply(client, token, route, fixture_name=None):
    if fixture_name is None:
        fixture_name = os.path.basename(route)

    reply = client.get(route, token=token)

    assert reply.status_code == 200
    assert reply.headers['Content-Type'] == 'jpg'

    # let's check the data is the same
    assert hashlib.sha1(reply.data).hexdigest() == SHA1S[fixture_name]

    return reply


def get_list_files_and_check_reply(client, token):
    reply = client.get('/files', token=token)
    assert reply.status_code == 200
    return reply


def delete_file_and_check_reply(client, token, route):
    reply = client.delete(route, token=token)
    assert reply.status_code == 204
    return reply
