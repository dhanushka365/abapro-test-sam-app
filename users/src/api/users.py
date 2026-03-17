# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import json
import uuid
import os
import boto3
import logging
from botocore.exceptions import ClientError
from datetime import datetime

# ── Logging ───────────────────────────────────────────────────────────────────
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ── AWS clients ───────────────────────────────────────────────────────────────
USERS_TABLE        = os.getenv('USERS_TABLE', None)
USER_POOL_CLIENT_ID = os.getenv('USER_POOL_CLIENT_ID', None)
USER_POOL_ID       = os.getenv('USER_POOL_ID', None)
STACK_NAME         = os.getenv('STACK_NAME', 'users-api')

dynamodb  = boto3.resource('dynamodb')
ddbTable  = dynamodb.Table(USERS_TABLE)
cognito   = boto3.client('cognito-idp')
cw_client = boto3.client('cloudwatch')


def put_metric(metric_name, value=1, unit='Count', **dimensions):
    """Publish a custom metric to CloudWatch."""
    try:
        cw_client.put_metric_data(
            Namespace=f'{STACK_NAME}/UsersAPI',
            MetricData=[{
                'MetricName': metric_name,
                'Value': value,
                'Unit': unit,
                'Dimensions': [{'Name': k, 'Value': v} for k, v in dimensions.items()]
            }]
        )
    except Exception as e:
        logger.warning(f'Failed to publish metric {metric_name}: {e}')

def get_caller_sub(event):
    """Extract the Cognito sub (user ID) from the JWT authorizer context."""
    try:
        return event['requestContext']['authorizer']['claims']['sub']
    except (KeyError, TypeError):
        return None


def lambda_handler(event, context):
    route_key = f"{event['httpMethod']} {event['resource']}"

    logger.info(json.dumps({
        'event': 'REQUEST',
        'route': route_key,
        'requestId': context.aws_request_id if context else 'local'
    }))

    # Set default response, override with data from DynamoDB if any
    response_body = {'Message': 'Unsupported route'}
    status_code = 400
    headers = {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
    }

    try:
        caller_sub = get_caller_sub(event)

        # Get a list of all Users
        if route_key == 'GET /users':
            ddb_response = ddbTable.scan(Select='ALL_ATTRIBUTES')
            response_body = ddb_response['Items']
            status_code = 200
            logger.info(json.dumps({'event': 'GET_USERS', 'count': len(response_body)}))
            put_metric('GetUsers', Operation='GET /users')

        # Read a user by ID
        if route_key == 'GET /users/{userid}':
            userid = event['pathParameters']['userid']
            ddb_response = ddbTable.get_item(Key={'userid': userid})
            if 'Item' in ddb_response:
                response_body = ddb_response['Item']
                logger.info(json.dumps({'event': 'GET_USER', 'userid': userid, 'found': True}))
            else:
                response_body = {}
                logger.info(json.dumps({'event': 'GET_USER', 'userid': userid, 'found': False}))
            status_code = 200
            put_metric('GetUserById', Operation='GET /users/{userid}')

        # Delete a user by ID — only the owner can delete their own record
        if route_key == 'DELETE /users/{userid}':
            userid = event['pathParameters']['userid']
            if caller_sub and caller_sub != userid:
                status_code = 403
                response_body = {'Message': 'Forbidden: you can only delete your own record'}
                logger.warning(json.dumps({'event': 'DELETE_FORBIDDEN', 'caller': caller_sub, 'target': userid}))
                put_metric('AuthorizationFailure', Operation='DELETE /users/{userid}')
            else:
                ddbTable.delete_item(Key={'userid': userid})
                response_body = {}
                status_code = 200
                logger.info(json.dumps({'event': 'DELETE_USER', 'userid': userid}))
                put_metric('DeleteUser', Operation='DELETE /users/{userid}')

        # Create a new user — registers in Cognito AND saves to DynamoDB
        if route_key == 'POST /users':
            request_json = json.loads(event['body'])
            email    = request_json.get('email')
            password = request_json.get('password')

            if not email or not password:
                status_code = 400
                response_body = {'Message': 'email and password are required to create a user'}
                logger.warning(json.dumps({'event': 'POST_USER_VALIDATION_FAIL', 'reason': 'missing email or password'}))
                put_metric('ValidationError', Operation='POST /users')
            else:
                cognito_sub = None
                try:
                    # ── Step 1: Register user in Cognito ──────────────────────
                    cognito_response = cognito.sign_up(
                        ClientId=USER_POOL_CLIENT_ID,
                        Username=email,
                        Password=password,
                        UserAttributes=[{'Name': 'email', 'Value': email}]
                    )
                    cognito_sub = cognito_response['UserSub']
                    logger.info(json.dumps({'event': 'COGNITO_SIGNUP_SUCCESS', 'sub': cognito_sub}))
                except ClientError as cognito_err:
                    error_code = cognito_err.response['Error']['Code']
                    error_messages = {
                        'UsernameExistsException':  'An account with this email already exists.',
                        'InvalidPasswordException': 'Password does not meet requirements (min 8 chars, upper, lower, number).',
                        'InvalidParameterException':'Invalid email or parameter provided.',
                    }
                    msg = error_messages.get(error_code, f'Registration failed: {cognito_err.response["Error"]["Message"]}')
                    status_code  = 409 if error_code == 'UsernameExistsException' else 400
                    response_body = {'Message': msg, 'ErrorCode': error_code}
                    logger.error(json.dumps({'event': 'COGNITO_SIGNUP_FAIL', 'errorCode': error_code, 'email': email}))
                    put_metric('CognitoSignUpError', Operation='POST /users', ErrorCode=error_code)
                    return {
                        'statusCode': status_code,
                        'body': json.dumps(response_body),
                        'headers': headers
                    }

                try:
                    # ── Step 2: Save profile to DynamoDB (password NOT stored) ─
                    request_json.pop('password', None)
                    request_json['userid']     = cognito_sub
                    request_json['created_by'] = cognito_sub
                    request_json['timestamp']  = datetime.now().isoformat()

                    ddbTable.put_item(Item=request_json)
                    response_body = {
                        **request_json,
                        'message': 'User registered successfully. Please check your email to confirm your account.'
                    }
                    status_code = 201
                    logger.info(json.dumps({'event': 'POST_USER_SUCCESS', 'userid': cognito_sub}))
                    put_metric('UserRegistered', Operation='POST /users')
                except Exception as ddb_err:
                    # ── ROLLBACK: DynamoDB failed — delete the Cognito user ────
                    logger.error(json.dumps({'event': 'DDB_WRITE_FAIL', 'sub': cognito_sub, 'error': str(ddb_err)}))
                    put_metric('DynamoDBWriteError', Operation='POST /users')
                    try:
                        cognito.admin_delete_user(UserPoolId=USER_POOL_ID, Username=email)
                        logger.info(json.dumps({'event': 'COGNITO_ROLLBACK_SUCCESS', 'email': email}))
                    except ClientError as rollback_err:
                        logger.error(json.dumps({'event': 'COGNITO_ROLLBACK_FAIL', 'email': email, 'error': str(rollback_err)}))
                        put_metric('CognitoRollbackError', Operation='POST /users')
                    status_code   = 500
                    response_body = {'Message': 'User registration failed due to a database error. Please try again.'}

        # Update a specific user by ID — only the owner can update their own record
        if route_key == 'PUT /users/{userid}':
            userid = event['pathParameters']['userid']
            if caller_sub and caller_sub != userid:
                status_code   = 403
                response_body = {'Message': 'Forbidden: you can only update your own record'}
                logger.warning(json.dumps({'event': 'UPDATE_FORBIDDEN', 'caller': caller_sub, 'target': userid}))
                put_metric('AuthorizationFailure', Operation='PUT /users/{userid}')
            else:
                request_json = json.loads(event['body'])
                request_json['timestamp'] = datetime.now().isoformat()
                request_json['userid']    = userid
                ddbTable.put_item(Item=request_json)
                response_body = request_json
                status_code   = 200
                logger.info(json.dumps({'event': 'UPDATE_USER', 'userid': userid}))
                put_metric('UpdateUser', Operation='PUT /users/{userid}')

    except Exception as err:
        status_code   = 400
        response_body = {'Error:': str(err)}
        logger.error(json.dumps({'event': 'UNHANDLED_ERROR', 'route': route_key, 'error': str(err)}))
        put_metric('UnhandledError', Operation=route_key)

    logger.info(json.dumps({'event': 'RESPONSE', 'route': route_key, 'statusCode': status_code}))
    return {
        'statusCode': status_code,
        'body': json.dumps(response_body),
        'headers': headers
    }