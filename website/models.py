import time
from authlib.common.encoding import json_loads, json_dumps
from authlib.oauth2.rfc6749.util import scope_to_list, list_to_scope
from authlib.oauth2.rfc6749 import ClientMixin
from authlib.oauth2.rfc6749 import (
    TokenMixin,
    AuthorizationCodeMixin,
)
from flask_sqlalchemy import SQLAlchemy


db = SQLAlchemy()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True)

    def __str__(self):
        return self.username

    def get_user_id(self):
        return self.id

    def check_password(self, password):
        return password == 'valid'


class OAuth2Client(db.Model, ClientMixin):
    __tablename__ = 'oauth2_client'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
    user = db.relationship('User')

    client_id = db.Column(db.String(48), index=True)
    client_secret = db.Column(db.String(120))
    client_id_issued_at = db.Column(db.Integer, nullable=False, default=0)
    client_secret_expires_at = db.Column(db.Integer, nullable=False, default=0)
    _client_metadata = db.Column('client_metadata', db.Text)

    @property
    def client_info(self):
        """Implementation for Client Info in OAuth 2.0 Dynamic Client
        Registration Protocol via `Section 3.2.1`_.
        .. _`Section 3.2.1`: https://tools.ietf.org/html/rfc7591#section-3.2.1
        """
        return dict(
            client_id=self.client_id,
            client_secret=self.client_secret,
            client_id_issued_at=self.client_id_issued_at,
            client_secret_expires_at=self.client_secret_expires_at,
        )

    @property
    def client_metadata(self):
        if 'client_metadata' in self.__dict__:
            return self.__dict__['client_metadata']
        if self._client_metadata:
            data = json_loads(self._client_metadata)
            self.__dict__['client_metadata'] = data
            return data
        return {}

    def set_client_metadata(self, value):
        self._client_metadata = json_dumps(value)

    @property
    def redirect_uris(self):
        return self.client_metadata.get('redirect_uris', [])

    @property
    def token_endpoint_auth_method(self):
        return self.client_metadata.get(
            'token_endpoint_auth_method',
            'client_secret_basic'
        )

    @property
    def grant_types(self):
        return self.client_metadata.get('grant_types', [])

    @property
    def response_types(self):
        return self.client_metadata.get('response_types', [])

    @property
    def client_name(self):
        return self.client_metadata.get('client_name')

    @property
    def client_uri(self):
        return self.client_metadata.get('client_uri')

    @property
    def logo_uri(self):
        return self.client_metadata.get('logo_uri')

    @property
    def scope(self):
        return self.client_metadata.get('scope', '')

    @property
    def contacts(self):
        return self.client_metadata.get('contacts', [])

    @property
    def tos_uri(self):
        return self.client_metadata.get('tos_uri')

    @property
    def policy_uri(self):
        return self.client_metadata.get('policy_uri')

    @property
    def jwks_uri(self):
        return self.client_metadata.get('jwks_uri')

    @property
    def jwks(self):
        return self.client_metadata.get('jwks', [])

    @property
    def software_id(self):
        return self.client_metadata.get('software_id')

    @property
    def software_version(self):
        return self.client_metadata.get('software_version')

    def get_client_id(self):
        return self.client_id

    def get_default_redirect_uri(self):
        if self.redirect_uris:
            return self.redirect_uris[0]

    def get_allowed_scope(self, scope):
        if not scope:
            return ''
        allowed = set(self.scope.split())
        scopes = scope_to_list(scope)
        return list_to_scope([s for s in scopes if s in allowed])

    def check_redirect_uri(self, redirect_uri):
        return redirect_uri in self.redirect_uris

    def has_client_secret(self):
        return bool(self.client_secret)

    def check_client_secret(self, client_secret):
        return self.client_secret == client_secret

    def check_token_endpoint_auth_method(self, method):
        return self.token_endpoint_auth_method == method

    def check_response_type(self, response_type):
        return response_type in self.response_types

    def check_grant_type(self, grant_type):
        return grant_type in self.grant_types


class OAuth2AuthorizationCode(db.Model, AuthorizationCodeMixin):
    __tablename__ = 'oauth2_code'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
    user = db.relationship('User')

    code = db.Column(db.String(120), unique=True, nullable=False)
    client_id = db.Column(db.String(48))
    redirect_uri = db.Column(db.Text, default='')
    response_type = db.Column(db.Text, default='')
    scope = db.Column(db.Text, default='')
    nonce = db.Column(db.Text)
    auth_time = db.Column(
        db.Integer, nullable=False,
        default=lambda: int(time.time())
    )

    code_challenge = db.Column(db.Text)
    code_challenge_method = db.Column(db.String(48))

    def is_expired(self):
        return self.auth_time + 300 < time.time()

    def get_redirect_uri(self):
        return self.redirect_uri

    def get_scope(self):
        return self.scope

    def get_auth_time(self):
        return self.auth_time

    def get_nonce(self):
        return self.nonce


class OAuth2Token(db.Model, TokenMixin):
    __tablename__ = 'oauth2_token'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
    user = db.relationship('User')

    client_id = db.Column(db.String(48))
    token_type = db.Column(db.String(40))
    access_token = db.Column(db.String(255), unique=True, nullable=False)
    refresh_token = db.Column(db.String(255), index=True)
    scope = db.Column(db.Text, default='')
    revoked = db.Column(db.Boolean, default=False)
    issued_at = db.Column(
        db.Integer, nullable=False, default=lambda: int(time.time())
    )
    expires_in = db.Column(db.Integer, nullable=False, default=0)

    def is_refresh_token_active(self):
        if self.revoked:
            return False
        expires_at = self.issued_at + self.expires_in * 2
        return expires_at >= time.time()

    def get_client_id(self):
        return self.client_id

    def get_scope(self):
        return self.scope

    def get_expires_in(self):
        return self.expires_in

    def get_expires_at(self):
        return self.issued_at + self.expires_in
