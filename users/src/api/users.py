# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import json
import uuid
import os
import boto3
from datetime import datetime

# Prepare DynamoDB client
USERS_TABLE = os.getenv('USERS_TABLE', None)
dynamodb = boto3.resource('dynamodb')
ddbTable = dynamodb.Table(USERS_TABLE)

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
                status_code = 200

        # Create a new user — userid is set to the Cognito sub so it's tied to the identity
        if route_key == 'POST /users':
            request_json = json.loads(event['body'])
            request_json['timestamp'] = datetime.now().isoformat()
            # Use Cognito sub as userid if available, otherwise generate one
            if caller_sub:
                request_json['userid'] = caller_sub
            elif 'userid' not in request_json:
                request_json['userid'] = str(uuid.uuid1())
            request_json['created_by'] = caller_sub or request_json['userid']
            ddbTable.put_item(Item=request_json)
            response_body = request_json
            status_code = 200

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