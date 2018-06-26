from functools import wraps

from flask import jsonify, request

from jsonschema import validate, ValidationError


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
                return jsonify({'error': 'Invalid input: %s' % (e.message, )}), 400

            return handler(json)

        return wrapper

    return internal_decorator


def error_reply(message, status_code=400):
    return jsonify({'error': message}), status_code
