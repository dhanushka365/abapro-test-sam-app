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
    monkeypatch.setenv('USER_POOL_CLIENT_ID', 'test-client-id')
    monkeypatch.setenv('USER_POOL_ID', 'us-east-1_testPool')


@pytest.fixture()
def mock_ddb_table():
    with patch('src.api.users.ddbTable') as mock_table:
        yield mock_table


@pytest.fixture()
def mock_cognito():
    with patch('src.api.users.cognito') as mock_cog:
        yield mock_cog


@pytest.fixture()
def mock_cw():
    with patch('src.api.users.cw_client') as mock_cloudwatch:
        yield mock_cloudwatch


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

    # ── Scenario 1: Missing required fields ───────────────────────────────────
    def test_missing_email_returns_400(self, mock_ddb_table, mock_cognito):
        from src.api.users import lambda_handler
        resp = lambda_handler(make_event('POST', '/users', body={'name': 'Alice', 'password': 'Pass123!'}), {})
        assert resp['statusCode'] == 400
        assert 'email and password are required' in json.loads(resp['body'])['Message']
        mock_cognito.sign_up.assert_not_called()
        mock_ddb_table.put_item.assert_not_called()

    def test_missing_password_returns_400(self, mock_ddb_table, mock_cognito):
        from src.api.users import lambda_handler
        resp = lambda_handler(make_event('POST', '/users', body={'name': 'Alice', 'email': 'alice@example.com'}), {})
        assert resp['statusCode'] == 400
        assert 'email and password are required' in json.loads(resp['body'])['Message']
        mock_cognito.sign_up.assert_not_called()
        mock_ddb_table.put_item.assert_not_called()

    def test_missing_both_fields_returns_400(self, mock_ddb_table, mock_cognito):
        from src.api.users import lambda_handler
        resp = lambda_handler(make_event('POST', '/users', body={'name': 'Alice'}), {})
        assert resp['statusCode'] == 400
        mock_cognito.sign_up.assert_not_called()

    # ── Scenario 2: Cognito fails — DynamoDB never called ─────────────────────
    def test_cognito_duplicate_email_returns_409(self, mock_ddb_table, mock_cognito):
        from src.api.users import lambda_handler
        from botocore.exceptions import ClientError
        mock_cognito.sign_up.side_effect = ClientError(
            {'Error': {'Code': 'UsernameExistsException', 'Message': 'User already exists'}},
            'SignUp'
        )
        resp = lambda_handler(make_event('POST', '/users', body={'name': 'Alice', 'email': 'alice@example.com', 'password': 'Pass123!'}), {})
        assert resp['statusCode'] == 409
        assert 'already exists' in json.loads(resp['body'])['Message']
        assert json.loads(resp['body'])['ErrorCode'] == 'UsernameExistsException'
        mock_ddb_table.put_item.assert_not_called()  # DynamoDB never touched

    def test_cognito_weak_password_returns_400(self, mock_ddb_table, mock_cognito):
        from src.api.users import lambda_handler
        from botocore.exceptions import ClientError
        mock_cognito.sign_up.side_effect = ClientError(
            {'Error': {'Code': 'InvalidPasswordException', 'Message': 'Password too weak'}},
            'SignUp'
        )
        resp = lambda_handler(make_event('POST', '/users', body={'name': 'Alice', 'email': 'alice@example.com', 'password': 'weak'}), {})
        assert resp['statusCode'] == 400
        assert 'Password does not meet requirements' in json.loads(resp['body'])['Message']
        mock_ddb_table.put_item.assert_not_called()

    def test_cognito_invalid_email_returns_400(self, mock_ddb_table, mock_cognito):
        from src.api.users import lambda_handler
        from botocore.exceptions import ClientError
        mock_cognito.sign_up.side_effect = ClientError(
            {'Error': {'Code': 'InvalidParameterException', 'Message': 'Invalid email'}},
            'SignUp'
        )
        resp = lambda_handler(make_event('POST', '/users', body={'name': 'Alice', 'email': 'not-an-email', 'password': 'Pass123!'}), {})
        assert resp['statusCode'] == 400
        assert 'Invalid email' in json.loads(resp['body'])['Message']
        mock_ddb_table.put_item.assert_not_called()

    def test_cognito_unknown_error_returns_400(self, mock_ddb_table, mock_cognito):
        from src.api.users import lambda_handler
        from botocore.exceptions import ClientError
        mock_cognito.sign_up.side_effect = ClientError(
            {'Error': {'Code': 'TooManyRequestsException', 'Message': 'Rate limit exceeded'}},
            'SignUp'
        )
        resp = lambda_handler(make_event('POST', '/users', body={'name': 'Alice', 'email': 'alice@example.com', 'password': 'Pass123!'}), {})
        assert resp['statusCode'] == 400
        assert 'Registration failed' in json.loads(resp['body'])['Message']
        mock_ddb_table.put_item.assert_not_called()

    # ── Scenario 3: Both steps succeed ────────────────────────────────────────
    def test_successful_registration_returns_201(self, mock_ddb_table, mock_cognito):
        from src.api.users import lambda_handler
        mock_cognito.sign_up.return_value = {'UserSub': 'cognito-sub-abc'}
        mock_ddb_table.put_item.return_value = {}
        resp = lambda_handler(make_event('POST', '/users', body={
            'name': 'Alice', 'email': 'alice@example.com', 'password': 'Pass123!'
        }), {})
        assert resp['statusCode'] == 201
        body = json.loads(resp['body'])
        assert body['userid'] == 'cognito-sub-abc'
        assert body['created_by'] == 'cognito-sub-abc'
        assert 'timestamp' in body
        assert 'password' not in body                          # password never stored
        assert 'registered successfully' in body['message']

    def test_successful_registration_with_extra_fields(self, mock_ddb_table, mock_cognito):
        from src.api.users import lambda_handler
        mock_cognito.sign_up.return_value = {'UserSub': 'cognito-sub-xyz'}
        mock_ddb_table.put_item.return_value = {}
        resp = lambda_handler(make_event('POST', '/users', body={
            'name': 'Bob', 'email': 'bob@example.com', 'password': 'Pass123!', 'age': 30, 'city': 'New York'
        }), {})
        assert resp['statusCode'] == 201
        body = json.loads(resp['body'])
        assert body['age'] == 30
        assert body['city'] == 'New York'
        assert 'password' not in body

    def test_cognito_called_with_correct_params(self, mock_ddb_table, mock_cognito):
        from src.api.users import lambda_handler
        mock_cognito.sign_up.return_value = {'UserSub': 'sub-999'}
        mock_ddb_table.put_item.return_value = {}
        lambda_handler(make_event('POST', '/users', body={
            'name': 'Alice', 'email': 'alice@example.com', 'password': 'Pass123!'
        }), {})
        mock_cognito.sign_up.assert_called_once_with(
            ClientId='test-client-id',
            Username='alice@example.com',
            Password='Pass123!',
            UserAttributes=[{'Name': 'email', 'Value': 'alice@example.com'}]
        )

    # ── Scenario 4: Cognito succeeds, DynamoDB fails — rollback triggered ─────
    def test_ddb_failure_triggers_cognito_rollback(self, mock_ddb_table, mock_cognito):
        from src.api.users import lambda_handler
        mock_cognito.sign_up.return_value = {'UserSub': 'cognito-sub-abc'}
        mock_ddb_table.put_item.side_effect = Exception('DynamoDB unavailable')
        mock_cognito.admin_delete_user.return_value = {}
        resp = lambda_handler(make_event('POST', '/users', body={
            'name': 'Alice', 'email': 'alice@example.com', 'password': 'Pass123!'
        }), {})
        assert resp['statusCode'] == 500
        assert 'database error' in json.loads(resp['body'])['Message']
        # Rollback: Cognito user must be deleted
        mock_cognito.admin_delete_user.assert_called_once_with(            UserPoolId='us-east-1_testPool',
            Username='alice@example.com'
        )

    def test_ddb_failure_rollback_itself_fails_returns_500(self, mock_ddb_table, mock_cognito):
        from src.api.users import lambda_handler
        from botocore.exceptions import ClientError
        mock_cognito.sign_up.return_value = {'UserSub': 'cognito-sub-abc'}
        mock_ddb_table.put_item.side_effect = Exception('DynamoDB unavailable')
        # Rollback also fails
        mock_cognito.admin_delete_user.side_effect = ClientError(
            {'Error': {'Code': 'UserNotFoundException', 'Message': 'User not found'}},
            'AdminDeleteUser'
        )
        resp = lambda_handler(make_event('POST', '/users', body={
            'name': 'Alice', 'email': 'alice@example.com', 'password': 'Pass123!'
        }), {})
        # Still returns 500 to the client even though rollback failed
        assert resp['statusCode'] == 500
        assert 'database error' in json.loads(resp['body'])['Message']


# ── POST /users/verify ────────────────────────────────────────────────────────

class TestVerifyUser:

    def test_missing_email_returns_400(self, mock_cognito, mock_cw):
        from src.api.users import lambda_handler
        resp = lambda_handler(make_event('POST', '/users/verify', body={'code': '123456'}), {})
        assert resp['statusCode'] == 400
        assert 'email and code are required' in json.loads(resp['body'])['Message']
        mock_cognito.confirm_sign_up.assert_not_called()

    def test_missing_code_returns_400(self, mock_cognito, mock_cw):
        from src.api.users import lambda_handler
        resp = lambda_handler(make_event('POST', '/users/verify', body={'email': 'alice@example.com'}), {})
        assert resp['statusCode'] == 400
        assert 'email and code are required' in json.loads(resp['body'])['Message']
        mock_cognito.confirm_sign_up.assert_not_called()

    def test_successful_verification_returns_200(self, mock_ddb_table, mock_cognito, mock_cw):
        from src.api.users import lambda_handler
        mock_cognito.confirm_sign_up.return_value = {}
        mock_ddb_table.scan.return_value = {'Items': [{'userid': 'sub-abc', 'email': 'alice@example.com'}]}
        mock_ddb_table.update_item.return_value = {}
        resp = lambda_handler(make_event('POST', '/users/verify', body={
            'email': 'alice@example.com', 'code': '123456'
        }), {})
        assert resp['statusCode'] == 200
        assert 'verified successfully' in json.loads(resp['body'])['Message']
        mock_cognito.confirm_sign_up.assert_called_once_with(
            ClientId='test-client-id',
            Username='alice@example.com',
            ConfirmationCode='123456'
        )

    def test_successful_verification_updates_ddb(self, mock_ddb_table, mock_cognito, mock_cw):
        from src.api.users import lambda_handler
        mock_cognito.confirm_sign_up.return_value = {}
        mock_ddb_table.scan.return_value = {'Items': [{'userid': 'sub-abc', 'email': 'alice@example.com'}]}
        mock_ddb_table.update_item.return_value = {}
        lambda_handler(make_event('POST', '/users/verify', body={
            'email': 'alice@example.com', 'code': '123456'
        }), {})
        mock_ddb_table.update_item.assert_called_once()
        call_kwargs = mock_ddb_table.update_item.call_args[1]
        assert call_kwargs['Key'] == {'userid': 'sub-abc'}
        assert ':v' in call_kwargs['ExpressionAttributeValues']
        assert call_kwargs['ExpressionAttributeValues'][':v'] is True

    def test_verification_skips_ddb_update_when_user_not_found(self, mock_ddb_table, mock_cognito, mock_cw):
        from src.api.users import lambda_handler
        mock_cognito.confirm_sign_up.return_value = {}
        mock_ddb_table.scan.return_value = {'Items': []}
        resp = lambda_handler(make_event('POST', '/users/verify', body={
            'email': 'unknown@example.com', 'code': '123456'
        }), {})
        assert resp['statusCode'] == 200
        mock_ddb_table.update_item.assert_not_called()

    def test_code_mismatch_returns_400(self, mock_ddb_table, mock_cognito, mock_cw):
        from src.api.users import lambda_handler
        from botocore.exceptions import ClientError
        mock_cognito.confirm_sign_up.side_effect = ClientError(
            {'Error': {'Code': 'CodeMismatchException', 'Message': 'Invalid code'}},
            'ConfirmSignUp'
        )
        resp = lambda_handler(make_event('POST', '/users/verify', body={
            'email': 'alice@example.com', 'code': '000000'
        }), {})
        assert resp['statusCode'] == 400
        assert 'Invalid verification code' in json.loads(resp['body'])['Message']
        assert json.loads(resp['body'])['ErrorCode'] == 'CodeMismatchException'

    def test_expired_code_returns_400(self, mock_ddb_table, mock_cognito, mock_cw):
        from src.api.users import lambda_handler
        from botocore.exceptions import ClientError
        mock_cognito.confirm_sign_up.side_effect = ClientError(
            {'Error': {'Code': 'ExpiredCodeException', 'Message': 'Code expired'}},
            'ConfirmSignUp'
        )
        resp = lambda_handler(make_event('POST', '/users/verify', body={
            'email': 'alice@example.com', 'code': '123456'
        }), {})
        assert resp['statusCode'] == 400
        assert 'expired' in json.loads(resp['body'])['Message'].lower()

    def test_already_confirmed_returns_400(self, mock_ddb_table, mock_cognito, mock_cw):
        from src.api.users import lambda_handler
        from botocore.exceptions import ClientError
        mock_cognito.confirm_sign_up.side_effect = ClientError(
            {'Error': {'Code': 'NotAuthorizedException', 'Message': 'Already confirmed'}},
            'ConfirmSignUp'
        )
        resp = lambda_handler(make_event('POST', '/users/verify', body={
            'email': 'alice@example.com', 'code': '123456'
        }), {})
        assert resp['statusCode'] == 400
        assert 'already confirmed' in json.loads(resp['body'])['Message'].lower()

    def test_user_not_found_returns_400(self, mock_ddb_table, mock_cognito, mock_cw):
        from src.api.users import lambda_handler
        from botocore.exceptions import ClientError
        mock_cognito.confirm_sign_up.side_effect = ClientError(
            {'Error': {'Code': 'UserNotFoundException', 'Message': 'User not found'}},
            'ConfirmSignUp'
        )
        resp = lambda_handler(make_event('POST', '/users/verify', body={
            'email': 'ghost@example.com', 'code': '123456'
        }), {})
        assert resp['statusCode'] == 400
        assert 'No account found' in json.loads(resp['body'])['Message']

    def test_verify_publishes_email_verified_metric(self, mock_ddb_table, mock_cognito, mock_cw):
        from src.api.users import lambda_handler
        mock_cognito.confirm_sign_up.return_value = {}
        mock_ddb_table.scan.return_value = {'Items': []}
        lambda_handler(make_event('POST', '/users/verify', body={
            'email': 'alice@example.com', 'code': '123456'
        }), {})
        metric_names = [
            call[1]['MetricData'][0]['MetricName']
            for call in mock_cw.put_metric_data.call_args_list
        ]
        assert 'EmailVerified' in metric_names

    def test_verify_error_publishes_email_verify_error_metric(self, mock_ddb_table, mock_cognito, mock_cw):
        from src.api.users import lambda_handler
        from botocore.exceptions import ClientError
        mock_cognito.confirm_sign_up.side_effect = ClientError(
            {'Error': {'Code': 'CodeMismatchException', 'Message': 'Bad code'}},
            'ConfirmSignUp'
        )
        lambda_handler(make_event('POST', '/users/verify', body={
            'email': 'alice@example.com', 'code': '000000'
        }), {})
        metric_names = [
            call[1]['MetricData'][0]['MetricName']
            for call in mock_cw.put_metric_data.call_args_list
        ]
        assert 'EmailVerifyError' in metric_names

    def test_validation_failure_publishes_validation_error_metric(self, mock_cognito, mock_cw):
        from src.api.users import lambda_handler
        lambda_handler(make_event('POST', '/users/verify', body={'email': 'alice@example.com'}), {})
        metric_names = [
            call[1]['MetricData'][0]['MetricName']
            for call in mock_cw.put_metric_data.call_args_list
        ]
        assert 'ValidationError' in metric_names


# ── POST /users/login ─────────────────────────────────────────────────────────

class TestLoginUser:

    def test_missing_email_returns_400(self, mock_cognito, mock_cw):
        from src.api.users import lambda_handler
        resp = lambda_handler(make_event('POST', '/users/login', body={'password': 'Pass123!'}), {})
        assert resp['statusCode'] == 400
        assert 'email and password are required' in json.loads(resp['body'])['Message']
        mock_cognito.initiate_auth.assert_not_called()

    def test_missing_password_returns_400(self, mock_cognito, mock_cw):
        from src.api.users import lambda_handler
        resp = lambda_handler(make_event('POST', '/users/login', body={'email': 'alice@example.com'}), {})
        assert resp['statusCode'] == 400
        assert 'email and password are required' in json.loads(resp['body'])['Message']
        mock_cognito.initiate_auth.assert_not_called()

    def test_successful_login_returns_200_with_tokens(self, mock_cognito, mock_cw):
        from src.api.users import lambda_handler
        mock_cognito.initiate_auth.return_value = {
            'AuthenticationResult': {
                'IdToken':      'id-token-abc',
                'AccessToken':  'access-token-abc',
                'RefreshToken': 'refresh-token-abc',
                'ExpiresIn':    3600,
                'TokenType':    'Bearer'
            }
        }
        resp = lambda_handler(make_event('POST', '/users/login', body={
            'email': 'alice@example.com', 'password': 'Pass123!'
        }), {})
        assert resp['statusCode'] == 200
        body = json.loads(resp['body'])
        assert body['IdToken']      == 'id-token-abc'
        assert body['AccessToken']  == 'access-token-abc'
        assert body['RefreshToken'] == 'refresh-token-abc'
        assert body['ExpiresIn']    == 3600
        assert body['TokenType']    == 'Bearer'

    def test_login_calls_cognito_with_correct_params(self, mock_cognito, mock_cw):
        from src.api.users import lambda_handler
        mock_cognito.initiate_auth.return_value = {
            'AuthenticationResult': {
                'IdToken': 'tok', 'AccessToken': 'tok',
                'RefreshToken': 'tok', 'ExpiresIn': 3600, 'TokenType': 'Bearer'
            }
        }
        lambda_handler(make_event('POST', '/users/login', body={
            'email': 'alice@example.com', 'password': 'Pass123!'
        }), {})
        mock_cognito.initiate_auth.assert_called_once_with(
            ClientId='test-client-id',
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': 'alice@example.com',
                'PASSWORD': 'Pass123!'
            }
        )

    def test_wrong_password_returns_401(self, mock_cognito, mock_cw):
        from src.api.users import lambda_handler
        from botocore.exceptions import ClientError
        mock_cognito.initiate_auth.side_effect = ClientError(
            {'Error': {'Code': 'NotAuthorizedException', 'Message': 'Incorrect username or password'}},
            'InitiateAuth'
        )
        resp = lambda_handler(make_event('POST', '/users/login', body={
            'email': 'alice@example.com', 'password': 'WrongPass!'
        }), {})
        assert resp['statusCode'] == 401
        assert 'Incorrect email or password' in json.loads(resp['body'])['Message']
        assert json.loads(resp['body'])['ErrorCode'] == 'NotAuthorizedException'

    def test_unconfirmed_user_returns_401(self, mock_cognito, mock_cw):
        from src.api.users import lambda_handler
        from botocore.exceptions import ClientError
        mock_cognito.initiate_auth.side_effect = ClientError(
            {'Error': {'Code': 'UserNotConfirmedException', 'Message': 'Not confirmed'}},
            'InitiateAuth'
        )
        resp = lambda_handler(make_event('POST', '/users/login', body={
            'email': 'alice@example.com', 'password': 'Pass123!'
        }), {})
        assert resp['statusCode'] == 401
        assert 'verify your email' in json.loads(resp['body'])['Message'].lower()

    def test_unknown_user_returns_401(self, mock_cognito, mock_cw):
        from src.api.users import lambda_handler
        from botocore.exceptions import ClientError
        mock_cognito.initiate_auth.side_effect = ClientError(
            {'Error': {'Code': 'UserNotFoundException', 'Message': 'User does not exist'}},
            'InitiateAuth'
        )
        resp = lambda_handler(make_event('POST', '/users/login', body={
            'email': 'ghost@example.com', 'password': 'Pass123!'
        }), {})
        assert resp['statusCode'] == 401
        assert 'No account found' in json.loads(resp['body'])['Message']

    def test_password_reset_required_returns_401(self, mock_cognito, mock_cw):
        from src.api.users import lambda_handler
        from botocore.exceptions import ClientError
        mock_cognito.initiate_auth.side_effect = ClientError(
            {'Error': {'Code': 'PasswordResetRequiredException', 'Message': 'Reset required'}},
            'InitiateAuth'
        )
        resp = lambda_handler(make_event('POST', '/users/login', body={
            'email': 'alice@example.com', 'password': 'Pass123!'
        }), {})
        assert resp['statusCode'] == 401
        assert 'Password reset' in json.loads(resp['body'])['Message']

    def test_unknown_cognito_error_returns_401(self, mock_cognito, mock_cw):
        from src.api.users import lambda_handler
        from botocore.exceptions import ClientError
        mock_cognito.initiate_auth.side_effect = ClientError(
            {'Error': {'Code': 'TooManyRequestsException', 'Message': 'Rate limited'}},
            'InitiateAuth'
        )
        resp = lambda_handler(make_event('POST', '/users/login', body={
            'email': 'alice@example.com', 'password': 'Pass123!'
        }), {})
        assert resp['statusCode'] == 401
        assert 'Login failed' in json.loads(resp['body'])['Message']

    def test_successful_login_publishes_user_login_metric(self, mock_cognito, mock_cw):
        from src.api.users import lambda_handler
        mock_cognito.initiate_auth.return_value = {
            'AuthenticationResult': {
                'IdToken': 'tok', 'AccessToken': 'tok',
                'RefreshToken': 'tok', 'ExpiresIn': 3600, 'TokenType': 'Bearer'
            }
        }
        lambda_handler(make_event('POST', '/users/login', body={
            'email': 'alice@example.com', 'password': 'Pass123!'
        }), {})
        metric_names = [
            call[1]['MetricData'][0]['MetricName']
            for call in mock_cw.put_metric_data.call_args_list
        ]
        assert 'UserLogin' in metric_names

    def test_login_failure_publishes_login_error_metric(self, mock_cognito, mock_cw):
        from src.api.users import lambda_handler
        from botocore.exceptions import ClientError
        mock_cognito.initiate_auth.side_effect = ClientError(
            {'Error': {'Code': 'NotAuthorizedException', 'Message': 'Bad creds'}},
            'InitiateAuth'
        )
        lambda_handler(make_event('POST', '/users/login', body={
            'email': 'alice@example.com', 'password': 'Wrong!'
        }), {})
        metric_names = [
            call[1]['MetricData'][0]['MetricName']
            for call in mock_cw.put_metric_data.call_args_list
        ]
        assert 'LoginError' in metric_names

    def test_validation_failure_publishes_validation_error_metric(self, mock_cognito, mock_cw):
        from src.api.users import lambda_handler
        lambda_handler(make_event('POST', '/users/login', body={'email': 'alice@example.com'}), {})
        metric_names = [
            call[1]['MetricData'][0]['MetricName']
            for call in mock_cw.put_metric_data.call_args_list
        ]
        assert 'ValidationError' in metric_names


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


# ── CloudWatch metrics ────────────────────────────────────────────────────────

class TestCloudWatchMetrics:

    def test_get_users_publishes_metric(self, mock_ddb_table, mock_cw):
        from src.api.users import lambda_handler
        mock_ddb_table.scan.return_value = {'Items': []}
        lambda_handler(make_event('GET', '/users'), {})
        mock_cw.put_metric_data.assert_called_once()
        call_kwargs = mock_cw.put_metric_data.call_args[1]
        assert call_kwargs['MetricData'][0]['MetricName'] == 'GetUsers'

    def test_get_user_by_id_publishes_metric(self, mock_ddb_table, mock_cw):
        from src.api.users import lambda_handler
        mock_ddb_table.get_item.return_value = {'Item': {'userid': 'abc'}}
        lambda_handler(make_event('GET', '/users/{userid}', path_params={'userid': 'abc'}), {})
        mock_cw.put_metric_data.assert_called_once()
        assert mock_cw.put_metric_data.call_args[1]['MetricData'][0]['MetricName'] == 'GetUserById'

    def test_successful_registration_publishes_user_registered_metric(self, mock_ddb_table, mock_cognito, mock_cw):
        from src.api.users import lambda_handler
        mock_cognito.sign_up.return_value = {'UserSub': 'sub-abc'}
        mock_ddb_table.put_item.return_value = {}
        lambda_handler(make_event('POST', '/users', body={
            'name': 'Alice', 'email': 'alice@example.com', 'password': 'Pass123!'
        }), {})
        metric_names = [
            call[1]['MetricData'][0]['MetricName']
            for call in mock_cw.put_metric_data.call_args_list
        ]
        assert 'UserRegistered' in metric_names

    def test_missing_fields_publishes_validation_error_metric(self, mock_ddb_table, mock_cognito, mock_cw):
        from src.api.users import lambda_handler
        lambda_handler(make_event('POST', '/users', body={'name': 'Alice'}), {})
        metric_names = [
            call[1]['MetricData'][0]['MetricName']
            for call in mock_cw.put_metric_data.call_args_list
        ]
        assert 'ValidationError' in metric_names

    def test_cognito_signup_failure_publishes_cognito_error_metric(self, mock_ddb_table, mock_cognito, mock_cw):
        from src.api.users import lambda_handler
        from botocore.exceptions import ClientError
        mock_cognito.sign_up.side_effect = ClientError(
            {'Error': {'Code': 'UsernameExistsException', 'Message': 'exists'}}, 'SignUp'
        )
        lambda_handler(make_event('POST', '/users', body={
            'name': 'Alice', 'email': 'alice@example.com', 'password': 'Pass123!'
        }), {})
        metric_names = [
            call[1]['MetricData'][0]['MetricName']
            for call in mock_cw.put_metric_data.call_args_list
        ]
        assert 'CognitoSignUpError' in metric_names

    def test_ddb_write_failure_publishes_ddb_error_metric(self, mock_ddb_table, mock_cognito, mock_cw):
        from src.api.users import lambda_handler
        mock_cognito.sign_up.return_value = {'UserSub': 'sub-abc'}
        mock_ddb_table.put_item.side_effect = Exception('DynamoDB down')
        mock_cognito.admin_delete_user.return_value = {}
        lambda_handler(make_event('POST', '/users', body={
            'name': 'Alice', 'email': 'alice@example.com', 'password': 'Pass123!'
        }), {})
        metric_names = [
            call[1]['MetricData'][0]['MetricName']
            for call in mock_cw.put_metric_data.call_args_list
        ]
        assert 'DynamoDBWriteError' in metric_names

    def test_delete_forbidden_publishes_auth_failure_metric(self, mock_ddb_table, mock_cw):
        from src.api.users import lambda_handler
        lambda_handler(make_event(
            'DELETE', '/users/{userid}',
            path_params={'userid': 'other-user'},
            cognito_sub='sub-111'
        ), {})
        metric_names = [
            call[1]['MetricData'][0]['MetricName']
            for call in mock_cw.put_metric_data.call_args_list
        ]
        assert 'AuthorizationFailure' in metric_names

    def test_update_forbidden_publishes_auth_failure_metric(self, mock_ddb_table, mock_cw):
        from src.api.users import lambda_handler
        lambda_handler(make_event(
            'PUT', '/users/{userid}',
            path_params={'userid': 'other-user'},
            body={'name': 'Hacked'},
            cognito_sub='sub-111'
        ), {})
        metric_names = [
            call[1]['MetricData'][0]['MetricName']
            for call in mock_cw.put_metric_data.call_args_list
        ]
        assert 'AuthorizationFailure' in metric_names

    def test_put_user_success_publishes_update_metric(self, mock_ddb_table, mock_cw):
        from src.api.users import lambda_handler
        mock_ddb_table.put_item.return_value = {}
        lambda_handler(make_event(
            'PUT', '/users/{userid}',
            path_params={'userid': 'sub-111'},
            body={'name': 'Updated'},
            cognito_sub='sub-111'
        ), {})
        metric_names = [
            call[1]['MetricData'][0]['MetricName']
            for call in mock_cw.put_metric_data.call_args_list
        ]
        assert 'UpdateUser' in metric_names

    def test_delete_user_success_publishes_delete_metric(self, mock_ddb_table, mock_cw):
        from src.api.users import lambda_handler
        mock_ddb_table.delete_item.return_value = {}
        lambda_handler(make_event(
            'DELETE', '/users/{userid}',
            path_params={'userid': 'sub-111'},
            cognito_sub='sub-111'
        ), {})
        metric_names = [
            call[1]['MetricData'][0]['MetricName']
            for call in mock_cw.put_metric_data.call_args_list
        ]
        assert 'DeleteUser' in metric_names

    def test_metric_failure_does_not_break_response(self, mock_ddb_table, mock_cw):
        """CloudWatch being down must never crash the API."""
        from src.api.users import lambda_handler
        mock_ddb_table.scan.return_value = {'Items': []}
        mock_cw.put_metric_data.side_effect = Exception('CW unavailable')
        resp = lambda_handler(make_event('GET', '/users'), {})
        assert resp['statusCode'] == 200  # API still responds normally