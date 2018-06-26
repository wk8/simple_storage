from functools import wraps
from jsonschema import validate, ValidationError

from flask import jsonify, request

from app.models import File, UserToken


def validate_json(schema):
    def internal_decorator(handler):
        @wraps(handler)
        def wrapper():
            json = request.get_json(silent=True, cache=False)

            if json is None:
                message = 'Please send a valid JSON with the appropriate Content-Type header'
                return error_reply(message)

            try:
                validate(json, schema)
            except ValidationError as e:
                return error_reply('Invalid input: %s' % (e.message, ))

            return handler(json)

        return wrapper

    return internal_decorator


def validate_user_token(db_session):
    def internal_decorator(handler):
        @wraps(handler)
        def wrapper(*args, **kwargs):
            token = request.headers.get('X-Session')
            user_id = UserToken.get_user_id_with_token(token, db_session)

            if user_id:
                return handler(user_id, *args, **kwargs)

            return error_reply('Invalid token', 401)

        return wrapper

    return internal_decorator


def fetch_exisiting_file(db_session, must_exist=True):
    def internal_decorator(handler):
        @wraps(handler)
        def wrapper(user_id, filename):
            file_object = (db_session.query(File).filter(File.user_id == user_id)
                                                 .filter(File.name == filename).first())

            if file_object or not must_exist:
                return handler(file_object, user_id, filename)

            return error_reply('File not found', 404)

        return wrapper

    return internal_decorator


def error_reply(message, status_code=400):
    return jsonify({'error': message}), status_code
