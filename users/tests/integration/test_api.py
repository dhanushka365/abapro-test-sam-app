# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""
Integration tests — runs against the LIVE deployed stack.

Prerequisites:
  export AWS_SAM_STACK_NAME=ws-serverless-patterns-users
  export TEST_USER_EMAIL=testuser@example.com
  export TEST_USER_PASSWORD=Test1234!
  pytest tests/integration/
"""

import os
import uuid
import pytest
import requests


# ── GET /users ────────────────────────────────────────────────────────────────

class TestGetUsers:
    def test_get_users_requires_auth(self, api_url):
        """Without a token the endpoint must return 401."""
        resp = requests.get(f'{api_url}/users')
        assert resp.status_code == 401

    def test_get_users_with_valid_token(self, api_url, cognito_token):
        """Authenticated request returns 200 and a list."""
        resp = requests.get(
            f'{api_url}/users',
            headers={'Authorization': cognito_token}
        )
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)


# ── POST /users ───────────────────────────────────────────────────────────────

class TestPostUser:
    def test_create_user_sets_userid_to_cognito_sub(self, api_url, cognito_token, cognito_user_sub):
        resp = requests.post(
            f'{api_url}/users',
            headers={'Authorization': cognito_token, 'Content-Type': 'application/json'},
            json={'name': 'Integration Test User', 'email': 'test@example.com'}
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body['userid'] == cognito_user_sub
        assert body['created_by'] == cognito_user_sub
        assert 'timestamp' in body

    def test_create_user_requires_auth(self, api_url):
        resp = requests.post(f'{api_url}/users', json={'name': 'No Auth'})
        assert resp.status_code == 401


# ── GET /users/{userid} ───────────────────────────────────────────────────────

class TestGetUserById:
    def test_get_own_user(self, api_url, cognito_token, cognito_user_sub):
        resp = requests.get(
            f'{api_url}/users/{cognito_user_sub}',
            headers={'Authorization': cognito_token}
        )
        assert resp.status_code == 200
        body = resp.json()
        # Item may be empty dict if not created yet — just check 200
        assert isinstance(body, dict)

    def test_get_user_requires_auth(self, api_url):
        resp = requests.get(f'{api_url}/users/some-id')
        assert resp.status_code == 401


# ── PUT /users/{userid} ───────────────────────────────────────────────────────

class TestPutUser:
    def test_owner_can_update(self, api_url, cognito_token, cognito_user_sub):
        resp = requests.put(
            f'{api_url}/users/{cognito_user_sub}',
            headers={'Authorization': cognito_token, 'Content-Type': 'application/json'},
            json={'name': 'Updated Name'}
        )
        assert resp.status_code == 200
        assert resp.json()['name'] == 'Updated Name'

    def test_non_owner_gets_403(self, api_url, cognito_token):
        fake_id = str(uuid.uuid4())
        resp = requests.put(
            f'{api_url}/users/{fake_id}',
            headers={'Authorization': cognito_token, 'Content-Type': 'application/json'},
            json={'name': 'Should Fail'}
        )
        assert resp.status_code == 403

    def test_update_requires_auth(self, api_url):
        resp = requests.put(f'{api_url}/users/some-id', json={'name': 'No Auth'})
        assert resp.status_code == 401


# ── DELETE /users/{userid} ────────────────────────────────────────────────────

class TestDeleteUser:
    def test_non_owner_gets_403(self, api_url, cognito_token):
        fake_id = str(uuid.uuid4())
        resp = requests.delete(
            f'{api_url}/users/{fake_id}',
            headers={'Authorization': cognito_token}
        )
        assert resp.status_code == 403

    def test_owner_can_delete(self, api_url, cognito_token, cognito_user_sub):
        """Delete runs last so it cleans up the test user record."""
        resp = requests.delete(
            f'{api_url}/users/{cognito_user_sub}',
            headers={'Authorization': cognito_token}
        )
        assert resp.status_code == 200
        assert resp.json() == {}

    def test_delete_requires_auth(self, api_url):
        resp = requests.delete(f'{api_url}/users/some-id')
        assert resp.status_code == 401