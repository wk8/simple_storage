from flask import Flask, jsonify, request
import sqlalchemy

from app.database import init_db
from app.helpers import error_reply, fetch_exisiting_file, validate_json, validate_user_token
from app.models import File, User, UserToken
import app.json_schemas


def create_app(db_file_name='db.sqlite', db_session=None):
    app = Flask(__name__)

    if not db_session:
        db_session = init_db(db_file_name)

    @app.teardown_appcontext
    def shutdown_session(exception=None):
        db_session.remove()

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

    @app.route('/files/<filename>', methods=['PUT'])
    @validate_user_token(db_session)
    @fetch_exisiting_file(db_session, must_exist=False)
    def put_file(file_object, user_id, filename):
        content_type = request.headers.get('Content-Type')

        if file_object:
            file_object.content_type = content_type
            file_object.data = request.data
        else:
            file_object = File(user_id, filename, content_type, request.data)

        db_session.add(file_object)
        db_session.commit()

        return '', 201, {'Location': request.path}

    @app.route('/files/<filename>')
    @validate_user_token(db_session)
    @fetch_exisiting_file(db_session)
    def get_file(file_object, *_args):
        return file_object.data, {'Content-Type': file_object.content_type}

    @app.route('/files')
    @validate_user_token(db_session)
    def get_file_list(user_id):
        files = db_session.query(File).filter(File.user_id == user_id)
        return jsonify([f.name for f in files])

    @app.route('/files/<filename>', methods=['DELETE'])
    @validate_user_token(db_session)
    @fetch_exisiting_file(db_session)
    def delete_file(file_object, *_args):
        db_session.delete(file_object)
        db_session.commit()

        return '', 204

    return app
