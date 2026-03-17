# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import json
import uuid
import os
import boto3
from botocore.exceptions import ClientError
from datetime import datetime

# Prepare DynamoDB client
USERS_TABLE = os.getenv('USERS_TABLE', None)
USER_POOL_CLIENT_ID = os.getenv('USER_POOL_CLIENT_ID', None)
USER_POOL_ID = os.getenv('USER_POOL_ID', None)

dynamodb = boto3.resource('dynamodb')
ddbTable = dynamodb.Table(USERS_TABLE)

cognito = boto3.client('cognito-idp')

def get_caller_sub(event):
    """Extract the Cognito sub (user ID) from the JWT authorizer context."""
    try:
        return event['requestContext']['authorizer']['claims']['sub']
    except (KeyError, TypeError):
        return None


def lambda_handler(event, context):
    route_key = f"{event['httpMethod']} {event['resource']}"

    # Set default response, override with data from DynamoDB if any
    response_body = {'Message': 'Unsupported route'}
    status_code = 400
    headers = {
        'Content-Type': 'application/json',        'Access-Control-Allow-Origin': '*'
        }

    try:
        caller_sub = get_caller_sub(event)

        # Get a list of all Users
        if route_key == 'GET /users':
            ddb_response = ddbTable.scan(Select='ALL_ATTRIBUTES')
            response_body = ddb_response['Items']
            status_code = 200

        # CRUD operations for a single User

        # Read a user by ID
        if route_key == 'GET /users/{userid}':
            ddb_response = ddbTable.get_item(
                Key={'userid': event['pathParameters']['userid']}
            )
            if 'Item' in ddb_response:
                response_body = ddb_response['Item']
            else:
                response_body = {}
            status_code = 200

        # Delete a user by ID — only the owner can delete their own record
        if route_key == 'DELETE /users/{userid}':
            userid = event['pathParameters']['userid']
            # Ownership check: Cognito sub must match the userid
            if caller_sub and caller_sub != userid:
                status_code = 403
                response_body = {'Message': 'Forbidden: you can only delete your own record'}
            else:
                ddbTable.delete_item(Key={'userid': userid})
                response_body = {}
                status_code = 200        # Create a new user — registers in Cognito AND saves to DynamoDB
        if route_key == 'POST /users':
            request_json = json.loads(event['body'])

            email = request_json.get('email')
            password = request_json.get('password')

            if not email or not password:
                status_code = 400
                response_body = {'Message': 'email and password are required to create a user'}
            else:
                cognito_sub = None
                try:
                    # ── Step 1: Register user in Cognito ──────────────────────
                    cognito_response = cognito.sign_up(
                        ClientId=USER_POOL_CLIENT_ID,
                        Username=email,
                        Password=password,
                        UserAttributes=[
                            {'Name': 'email', 'Value': email},
                        ]
                    )
                    cognito_sub = cognito_response['UserSub']
                except ClientError as cognito_err:
                    # Cognito failed — DynamoDB was never touched, safe to return error
                    error_code = cognito_err.response['Error']['Code']
                    error_messages = {
                        'UsernameExistsException': 'An account with this email already exists.',
                        'InvalidPasswordException': 'Password does not meet requirements (min 8 chars, upper, lower, number).',
                        'InvalidParameterException': 'Invalid email or parameter provided.',
                    }
                    msg = error_messages.get(error_code, f'Registration failed: {cognito_err.response["Error"]["Message"]}')
                    status_code = 409 if error_code == 'UsernameExistsException' else 400
                    response_body = {'Message': msg, 'ErrorCode': error_code}
                    return {
                        'statusCode': status_code,
                        'body': json.dumps(response_body),
                        'headers': headers
                    }

                try:
                    # ── Step 2: Save profile to DynamoDB (password NOT stored) ─
                    request_json.pop('password', None)
                    request_json['userid'] = cognito_sub
                    request_json['created_by'] = cognito_sub
                    request_json['timestamp'] = datetime.now().isoformat()

                    ddbTable.put_item(Item=request_json)
                    response_body = {
                        **request_json,
                        'message': 'User registered successfully. Please check your email to confirm your account.'
                    }
                    status_code = 201
                except Exception as ddb_err:
                    # ── ROLLBACK: DynamoDB failed — delete the Cognito user ────
                    print(f'DynamoDB failed for {cognito_sub}, rolling back Cognito user. Error: {ddb_err}')
                    try:
                        cognito.admin_delete_user(
                            UserPoolId=USER_POOL_ID,
                            Username=email
                        )
                        print(f'Rollback successful: Cognito user {email} deleted.')
                    except ClientError as rollback_err:
                        # Rollback itself failed — log it for manual cleanup
                        print(f'ROLLBACK FAILED for Cognito user {email}: {rollback_err}')
                    status_code = 500
                    response_body = {'Message': 'User registration failed due to a database error. Please try again.'}

        # Update a specific user by ID — only the owner can update their own record
        if route_key == 'PUT /users/{userid}':
            userid = event['pathParameters']['userid']
            # Ownership check: Cognito sub must match the userid
            if caller_sub and caller_sub != userid:
                status_code = 403
                response_body = {'Message': 'Forbidden: you can only update your own record'}
            else:
                request_json = json.loads(event['body'])
                request_json['timestamp'] = datetime.now().isoformat()
                request_json['userid'] = userid
                ddbTable.put_item(Item=request_json)
                response_body = request_json
                status_code = 200
    except Exception as err:
        status_code = 400
        response_body = {'Error:': str(err)}
        print(str(err))
    return {
        'statusCode': status_code,
        'body': json.dumps(response_body),
        'headers': headers
    }