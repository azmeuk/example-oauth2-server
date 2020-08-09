from authlib.integrations.flask_oauth2 import (
    AuthorizationServer,
    ResourceProtector,
)
from authlib.oauth2.rfc6749 import grants
from authlib.oauth2.rfc7636 import CodeChallenge
from .models import db, User
from .models import OAuth2Client, OAuth2AuthorizationCode, OAuth2Token


class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = [
        "client_secret_basic",
        "client_secret_post",
        "none",
    ]

    def save_authorization_code(self, code, request):
        code_challenge = request.data.get("code_challenge")
        code_challenge_method = request.data.get("code_challenge_method")
        auth_code = OAuth2AuthorizationCode(
            code=code,
            client_id=request.client.client_id,
            redirect_uri=request.redirect_uri,
            scope=request.scope,
            user_id=request.user.id,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
        )
        db.session.add(auth_code)
        db.session.commit()
        return auth_code

    def query_authorization_code(self, code, client):
        auth_code = OAuth2AuthorizationCode.query.filter_by(
            code=code, client_id=client.client_id
        ).first()
        if auth_code and not auth_code.is_expired():
            return auth_code

    def delete_authorization_code(self, authorization_code):
        db.session.delete(authorization_code)
        db.session.commit()

    def authenticate_user(self, authorization_code):
        return User.query.get(authorization_code.user_id)


class PasswordGrant(grants.ResourceOwnerPasswordCredentialsGrant):
    def authenticate_user(self, username, password):
        user = User.query.filter_by(username=username).first()
        if user is not None and user.check_password(password):
            return user


class RefreshTokenGrant(grants.RefreshTokenGrant):
    def authenticate_refresh_token(self, refresh_token):
        token = OAuth2Token.query.filter_by(refresh_token=refresh_token).first()
        if token and token.is_refresh_token_active():
            return token

    def authenticate_user(self, credential):
        return User.query.get(credential.user_id)

    def revoke_old_credential(self, credential):
        credential.revoked = True
        db.session.add(credential)
        db.session.commit()


def create_query_client_func(session, client_model):
    """Create an ``query_client`` function that can be used in authorization
    server.
    :param session: SQLAlchemy session
    :param client_model: Client model class
    """

    def query_client(client_id):
        q = session.query(client_model)
        return q.filter_by(client_id=client_id).first()

    return query_client


query_client = create_query_client_func(db.session, OAuth2Client)


def create_save_token_func(session, token_model):
    """Create an ``save_token`` function that can be used in authorization
    server.
    :param session: SQLAlchemy session
    :param token_model: Token model class
    """

    def save_token(token, request):
        if request.user:
            user_id = request.user.get_user_id()
        else:
            user_id = None
        client = request.client
        item = token_model(client_id=client.client_id, user_id=user_id, **token)
        session.add(item)
        session.commit()

    return save_token


save_token = create_save_token_func(db.session, OAuth2Token)

authorization = AuthorizationServer(query_client=query_client, save_token=save_token,)
require_oauth = ResourceProtector()


def config_oauth(app):
    authorization.init_app(app)

    # support all grants
    authorization.register_grant(grants.ImplicitGrant)
    authorization.register_grant(grants.ClientCredentialsGrant)
    authorization.register_grant(AuthorizationCodeGrant, [CodeChallenge(required=True)])
    authorization.register_grant(PasswordGrant)
    authorization.register_grant(RefreshTokenGrant)

    # support revocation
    def create_revocation_endpoint(session, token_model):
        """Create a revocation endpoint class with SQLAlchemy session
        and token model.
        :param session: SQLAlchemy session
        :param token_model: Token model class
        """
        from authlib.oauth2.rfc7009 import RevocationEndpoint

        def create_query_token_func(session, token_model):
            """Create an ``query_token`` function for revocation, introspection
            token endpoints.
            :param session: SQLAlchemy session
            :param token_model: Token model class
            """

            def query_token(token, token_type_hint, client):
                q = session.query(token_model)
                q = q.filter_by(client_id=client.client_id, revoked=False)
                if token_type_hint == "access_token":
                    return q.filter_by(access_token=token).first()
                elif token_type_hint == "refresh_token":
                    return q.filter_by(refresh_token=token).first()
                # without token_type_hint
                item = q.filter_by(access_token=token).first()
                if item:
                    return item
                return q.filter_by(refresh_token=token).first()

            return query_token

        query_token = create_query_token_func(session, token_model)

        class _RevocationEndpoint(RevocationEndpoint):
            def query_token(self, token, token_type_hint, client):
                return query_token(token, token_type_hint, client)

            def revoke_token(self, token):
                token.revoked = True
                session.add(token)
                session.commit()

        return _RevocationEndpoint

    revocation_cls = create_revocation_endpoint(db.session, OAuth2Token)
    authorization.register_endpoint(revocation_cls)

    # protect resource
    def create_bearer_token_validator(session, token_model):
        """Create an bearer token validator class with SQLAlchemy session
        and token model.
        :param session: SQLAlchemy session
        :param token_model: Token model class
        """
        from authlib.oauth2.rfc6750 import BearerTokenValidator

        class _BearerTokenValidator(BearerTokenValidator):
            def authenticate_token(self, token_string):
                q = session.query(token_model)
                return q.filter_by(access_token=token_string).first()

            def request_invalid(self, request):
                return False

            def token_revoked(self, token):
                return token.revoked

        return _BearerTokenValidator

    bearer_cls = create_bearer_token_validator(db.session, OAuth2Token)
    require_oauth.register_token_validator(bearer_cls())
