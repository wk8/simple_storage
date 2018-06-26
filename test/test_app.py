import pytest

from app import app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    client = app.test_client()

    yield client


def test_empty_db(client):
    rv = client.get('/')
    assert rv.data == b'Hello, World!'
