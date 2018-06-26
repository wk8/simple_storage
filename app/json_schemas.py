'''
Contains the JSON schemas for our app

Simpler to just have them as py code altogether, and also
allows re-using certain constants from the models
'''

from models import User

_SCHEMA_VERSION = 'http://json-schema.org/draft-04/schema#'


def _add_schema_version(schema):
    schema['$schema'] = _SCHEMA_VERSION
    return schema


REGISTER_SCHEMA = _add_schema_version(
    {
        'type': 'object',
        'properties': {
            'username': {
                'type': 'string',
                'minLength': User.NAME_MIN_LENGTH,
                'maxLength': User.NAME_MAX_LENGTH,
                'pattern': User.NAME_REGEX.pattern
            },
            'password': {
                'type': 'string',
                'minLength': User.PASSWORD_MIN_LENGTH
            }
        },
        'required': [
            'username',
            'password'
        ],
        'additionalProperties': False
    })
