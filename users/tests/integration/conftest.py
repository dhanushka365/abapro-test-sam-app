# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import os
import boto3
import pytest

STACK_NAME = os.environ.get('AWS_SAM_STACK_NAME', 'ws-serverless-patterns-users')


def get_stack_output(key: str) -> str:
    """Fetch a CloudFormation stack output value by key."""
    cf = boto3.client('cloudformation')
    stacks = cf.describe_stacks(StackName=STACK_NAME)['Stacks']
    outputs = stacks[0].get('Outputs', [])
    for output in outputs:
        if output['OutputKey'] == key:
            return output['OutputValue']
    raise KeyError(f"Stack output '{key}' not found in stack '{STACK_NAME}'")


@pytest.fixture(scope='session')
def api_url():
    return get_stack_output('UsersApi')


@pytest.fixture(scope='session')
def user_pool_id():
    return get_stack_output('UserPoolId')


@pytest.fixture(scope='session')
def user_pool_client_id():
    return get_stack_output('UserPoolClientId')


@pytest.fixture(scope='session')
def cognito_token(user_pool_id, user_pool_client_id):
    """
    Sign in a test user and return a valid JWT id_token.
    Set TEST_USER_EMAIL and TEST_USER_PASSWORD env vars before running.
    """
    email = os.environ.get('TEST_USER_EMAIL', 'testuser@example.com')
    password = os.environ.get('TEST_USER_PASSWORD', 'Test1234!')

    cognito = boto3.client('cognito-idp', region_name='us-east-1')

    # Create user if it doesn't exist
    try:
        cognito.admin_create_user(
            UserPoolId=user_pool_id,
            Username=email,
            TemporaryPassword=password,
            UserAttributes=[{'Name': 'email', 'Value': email}],
            MessageAction='SUPPRESS'
        )
        # Set permanent password
        cognito.admin_set_user_password(
            UserPoolId=user_pool_id,
            Username=email,
            Password=password,
            Permanent=True
        )
    except cognito.exceptions.UsernameExistsException:
        pass

    # Authenticate
    auth_response = cognito.initiate_auth(
        AuthFlow='USER_PASSWORD_AUTH',
        AuthParameters={'USERNAME': email, 'PASSWORD': password},
        ClientId=user_pool_client_id
    )
    return auth_response['AuthenticationResult']['IdToken']


@pytest.fixture(scope='session')
def cognito_user_sub(user_pool_id, cognito_token):
    """Return the Cognito sub of the test user."""
    import base64, json as _json
    # Decode JWT payload (no verification needed here — integration test)
    payload = cognito_token.split('.')[1]
    payload += '=' * (-len(payload) % 4)  # fix padding
    claims = _json.loads(base64.urlsafe_b64decode(payload))
    return claims['sub']