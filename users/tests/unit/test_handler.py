# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import json
import pytest
from unittest.mock import MagicMock, patch


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_event(method, resource, path_params=None, body=None, cognito_sub=None):
    """Build a minimal API Gateway proxy event."""
    event = {
        'httpMethod': method,
        'resource': resource,
        'pathParameters': path_params or {},
        'body': json.dumps(body) if body else None,
        'requestContext': {}
    }
    if cognito_sub:
        event['requestContext'] = {
            'authorizer': {'claims': {'sub': cognito_sub}}
        }
    return event


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def mock_ddb_env(monkeypatch):
    monkeypatch.setenv('USERS_TABLE', 'test-users-table')


@pytest.fixture()
def mock_ddb_table():
    with patch('src.api.users.ddbTable') as mock_table:
        yield mock_table


# ── get_caller_sub ────────────────────────────────────────────────────────────

class TestGetCallerSub:
    def test_returns_sub_when_present(self):
        from src.api.users import get_caller_sub
        assert get_caller_sub(make_event('GET', '/users', cognito_sub='user-123')) == 'user-123'

    def test_returns_none_when_no_authorizer(self):
        from src.api.users import get_caller_sub
        assert get_caller_sub(make_event('GET', '/users')) is None

    def test_returns_none_on_malformed_context(self):
        from src.api.users import get_caller_sub
        assert get_caller_sub({'requestContext': {'authorizer': None}}) is None


# ── GET /users ────────────────────────────────────────────────────────────────

class TestGetUsers:
    def test_returns_all_users(self, mock_ddb_table):
        from src.api.users import lambda_handler
        mock_ddb_table.scan.return_value = {
            'Items': [{'userid': 'a', 'name': 'Alice'}, {'userid': 'b', 'name': 'Bob'}]
        }
        resp = lambda_handler(make_event('GET', '/users'), {})
        assert resp['statusCode'] == 200
        assert len(json.loads(resp['body'])) == 2

    def test_returns_empty_list(self, mock_ddb_table):
        from src.api.users import lambda_handler
        mock_ddb_table.scan.return_value = {'Items': []}
        resp = lambda_handler(make_event('GET', '/users'), {})
        assert resp['statusCode'] == 200
        assert json.loads(resp['body']) == []


# ── GET /users/{userid} ───────────────────────────────────────────────────────

class TestGetUserById:
    def test_returns_user_when_found(self, mock_ddb_table):
        from src.api.users import lambda_handler
        mock_ddb_table.get_item.return_value = {'Item': {'userid': 'abc', 'name': 'Alice'}}
        resp = lambda_handler(make_event('GET', '/users/{userid}', path_params={'userid': 'abc'}), {})
        assert resp['statusCode'] == 200
        assert json.loads(resp['body'])['name'] == 'Alice'

    def test_returns_empty_when_not_found(self, mock_ddb_table):
        from src.api.users import lambda_handler
        mock_ddb_table.get_item.return_value = {}
        resp = lambda_handler(make_event('GET', '/users/{userid}', path_params={'userid': 'x'}), {})
        assert resp['statusCode'] == 200
        assert json.loads(resp['body']) == {}


# ── POST /users ───────────────────────────────────────────────────────────────

class TestPostUser:
    def test_uses_cognito_sub_as_userid(self, mock_ddb_table):
        from src.api.users import lambda_handler
        mock_ddb_table.put_item.return_value = {}
        resp = lambda_handler(make_event('POST', '/users', body={'name': 'Alice'}, cognito_sub='sub-111'), {})
        assert resp['statusCode'] == 200
        body = json.loads(resp['body'])
        assert body['userid'] == 'sub-111'
        assert body['created_by'] == 'sub-111'
        assert 'timestamp' in body

    def test_generates_uuid_without_cognito(self, mock_ddb_table):
        from src.api.users import lambda_handler
        mock_ddb_table.put_item.return_value = {}
        resp = lambda_handler(make_event('POST', '/users', body={'name': 'Bob'}), {})
        assert resp['statusCode'] == 200
        assert 'userid' in json.loads(resp['body'])

    def test_keeps_provided_userid_without_cognito(self, mock_ddb_table):
        from src.api.users import lambda_handler
        mock_ddb_table.put_item.return_value = {}
        resp = lambda_handler(make_event('POST', '/users', body={'name': 'Carol', 'userid': 'custom-id'}), {})
        assert json.loads(resp['body'])['userid'] == 'custom-id'


# ── PUT /users/{userid} ───────────────────────────────────────────────────────

class TestPutUser:
    def test_owner_can_update(self, mock_ddb_table):
        from src.api.users import lambda_handler
        mock_ddb_table.put_item.return_value = {}
        resp = lambda_handler(make_event(
            'PUT', '/users/{userid}',
            path_params={'userid': 'sub-111'},
            body={'name': 'Alice Updated'},
            cognito_sub='sub-111'
        ), {})
        assert resp['statusCode'] == 200
        assert json.loads(resp['body'])['name'] == 'Alice Updated'

    def test_non_owner_gets_403(self, mock_ddb_table):
        from src.api.users import lambda_handler
        resp = lambda_handler(make_event(
            'PUT', '/users/{userid}',
            path_params={'userid': 'other-user'},
            body={'name': 'Hacked'},
            cognito_sub='sub-111'
        ), {})
        assert resp['statusCode'] == 403
        assert 'Forbidden' in json.loads(resp['body'])['Message']

    def test_no_cognito_allows_update(self, mock_ddb_table):
        from src.api.users import lambda_handler
        mock_ddb_table.put_item.return_value = {}
        resp = lambda_handler(make_event(
            'PUT', '/users/{userid}',
            path_params={'userid': 'any-user'},
            body={'name': 'Updated'}
        ), {})
        assert resp['statusCode'] == 200


# ── DELETE /users/{userid} ────────────────────────────────────────────────────

class TestDeleteUser:
    def test_owner_can_delete(self, mock_ddb_table):
        from src.api.users import lambda_handler
        mock_ddb_table.delete_item.return_value = {}
        resp = lambda_handler(make_event(
            'DELETE', '/users/{userid}',
            path_params={'userid': 'sub-111'},
            cognito_sub='sub-111'
        ), {})
        assert resp['statusCode'] == 200
        assert json.loads(resp['body']) == {}

    def test_non_owner_gets_403(self, mock_ddb_table):
        from src.api.users import lambda_handler
        resp = lambda_handler(make_event(
            'DELETE', '/users/{userid}',
            path_params={'userid': 'other-user'},
            cognito_sub='sub-111'
        ), {})
        assert resp['statusCode'] == 403

    def test_no_cognito_allows_delete(self, mock_ddb_table):
        from src.api.users import lambda_handler
        mock_ddb_table.delete_item.return_value = {}
        resp = lambda_handler(make_event(
            'DELETE', '/users/{userid}',
            path_params={'userid': 'any-user'}
        ), {})
        assert resp['statusCode'] == 200


# ── Edge cases ────────────────────────────────────────────────────────────────

class TestEdgeCases:
    def test_unsupported_route_returns_400(self, mock_ddb_table):
        from src.api.users import lambda_handler
        resp = lambda_handler(make_event('PATCH', '/users'), {})
        assert resp['statusCode'] == 400
        assert json.loads(resp['body'])['Message'] == 'Unsupported route'

    def test_ddb_exception_returns_400(self, mock_ddb_table):
        from src.api.users import lambda_handler
        mock_ddb_table.scan.side_effect = Exception('DynamoDB error')
        resp = lambda_handler(make_event('GET', '/users'), {})
        assert resp['statusCode'] == 400
        assert 'DynamoDB error' in json.loads(resp['body'])['Error:']

    def test_response_has_cors_header(self, mock_ddb_table):
        from src.api.users import lambda_handler
        mock_ddb_table.scan.return_value = {'Items': []}
        resp = lambda_handler(make_event('GET', '/users'), {})
        assert resp['headers']['Access-Control-Allow-Origin'] == '*'