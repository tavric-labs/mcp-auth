"""Black-box multi-method login: one server, two upstream providers, one login page."""

import json
import os
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from mcp_auth_client import OAuthState, authorization_url
from test_mcp_oauth_flow import _free_port, _wait_for_ready
from test_oidc_provider_flow import _jwk, _OIDCHandler, _serve

pytestmark = pytest.mark.e2e

CALLBACK = "http://127.0.0.1:39001/callback"
RESOURCE = "http://127.0.0.1:9/mcp"


class _AlphaProvider(_OIDCHandler):
    codes: dict[str, dict[str, str]] = {}


class _BetaProvider(_OIDCHandler):
    codes: dict[str, dict[str, str]] = {}


@dataclass
class Stack:
    url: str
    alpha_hits: type[_OIDCHandler]
    beta_hits: type[_OIDCHandler]


def _connector(provider_url: str, callback: str, client_id: str) -> dict[str, object]:
    return {
        "issuer": provider_url,
        "authorization_endpoint": provider_url + "/authorize",
        "token_endpoint": provider_url + "/token",
        "jwks_uri": provider_url + "/jwks",
        "client_id": client_id,
        "client_secret_env": "",
        "scopes": ["openid"],
        "token_endpoint_auth_method": "none",
        "allowed_upstream_callback_uris": [callback],
    }


@pytest.fixture(scope="module")
def stack(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Stack]:
    tmp_path = tmp_path_factory.mktemp("login-methods")
    port = _free_port()
    url = f"http://127.0.0.1:{port}"
    callback = url + "/identity/callback"

    servers = []
    for handler, kid_client in ((_AlphaProvider, "alpha-client"), (_BetaProvider, "beta-client")):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        handler.signing_key = key
        server, _thread, provider_url = _serve(handler)
        handler.issuer = provider_url
        handler.jwks = {"keys": [_jwk(key.public_key(), "mock-oidc-key")]}
        servers.append((server, provider_url, kid_client))

    (alpha, alpha_url, alpha_client), (beta, beta_url, beta_client) = servers
    connectors = tmp_path / "connectors.json"
    connectors.write_text(
        json.dumps(
            {
                "alpha": _connector(alpha_url, callback, alpha_client),
                "beta": _connector(beta_url, callback, beta_client),
            }
        )
    )
    methods = tmp_path / "login-methods.json"
    methods.write_text(
        json.dumps(
            {
                "methods": [
                    {"id": "alpha", "type": "oidc", "connector": "alpha", "label": "Alpha SSO"},
                    {"id": "beta", "type": "oidc", "connector": "beta", "label": "Beta SSO"},
                ]
            }
        )
    )
    binary = os.environ.get("MCP_AUTH_SERVER_BINARY")
    process = subprocess.Popen(
        [binary] if binary else ["go", "run", "./cmd/auth-server"],
        cwd=Path(__file__).parents[2] / "auth-server",
        env={
            **os.environ,
            "MCP_AUTH_ISSUER": url,
            "MCP_AUTH_RESOURCES": RESOURCE,
            "MCP_AUTH_ALLOWED_SCOPES": "tools:read",
            "MCP_AUTH_LISTEN_ADDR": f"127.0.0.1:{port}",
            "MCP_AUTH_LOCAL_DEVELOPMENT": "true",
            "MCP_AUTH_REQUIRE_HTTPS": "false",
            "MCP_AUTH_REGISTRATION_ENABLED": "true",
            "MCP_AUTH_CONNECTORS_FILE": str(connectors),
            "MCP_AUTH_LOGIN_METHODS_FILE": str(methods),
        },
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        _wait_for_ready(process, url + "/readyz")
        yield Stack(url, _AlphaProvider, _BetaProvider)
    finally:
        process.terminate()
        process.wait(timeout=10)
        alpha.shutdown()
        beta.shutdown()


def _start(stack: Stack, client: httpx.Client) -> tuple[OAuthState, str, str]:
    """Register a client and approve consent; return the PKCE state, client id and login id."""
    registration = client.post(
        stack.url + "/register",
        json={
            "client_name": "e2e",
            "redirect_uris": [CALLBACK],
            "token_endpoint_auth_method": "none",
        },
    )
    client_id = registration.json()["client_id"]
    state = OAuthState.generate()
    request = authorization_url(
        stack.url + "/authorize", client_id, CALLBACK, RESOURCE, {"tools:read"}, state
    )
    consent_page = client.get(request)
    assert consent_page.status_code == 200, consent_page.text
    consent_id = consent_page.text.split('name="consent_id" value="')[1].split('"')[0]
    consent = client.post(
        stack.url + "/authorize/consent", data={"consent_id": consent_id, "decision": "approve"}
    )
    assert consent.status_code == 303, consent.text
    login_url = consent.headers["Location"]
    assert urlsplit(login_url).path == "/login"
    return state, client_id, parse_qs(urlsplit(login_url).query)["login_id"][0]


def _finish(stack: Stack, client: httpx.Client, method: str, login_id: str) -> httpx.Response:
    """Choose a method, follow the provider and return the final redirect to the client."""
    chosen = client.post(f"{stack.url}/login/{method}", data={"login_id": login_id})
    assert chosen.status_code == 303, chosen.text
    upstream = client.get(chosen.headers["Location"])
    assert upstream.status_code == 302, upstream.text
    return client.get(upstream.headers["Location"])


def _redeem(stack: Stack, client_id: str, state: OAuthState, redirect: httpx.Response) -> dict:
    assert redirect.status_code == 302, redirect.text
    query = parse_qs(urlsplit(redirect.headers["Location"]).query)
    assert query["state"] == [state.state]
    token = httpx.post(
        stack.url + "/token",
        data={
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code": query["code"][0],
            "redirect_uri": CALLBACK,
            "code_verifier": state.code_verifier,
            "resource": RESOURCE,
        },
    )
    assert token.status_code == 200, token.text
    return dict(jwt.decode(token.json()["access_token"], options={"verify_signature": False}))


def test_login_page_offers_every_method(stack: Stack) -> None:
    with httpx.Client() as client:
        _state, _client_id, login_id = _start(stack, client)
        page = client.get(stack.url + "/login", params={"login_id": login_id})
    assert page.status_code == 200
    assert "Alpha SSO" in page.text and "Beta SSO" in page.text
    assert "/login/alpha" in page.text and "/login/beta" in page.text


@pytest.mark.parametrize("method", ["alpha", "beta"])
def test_each_method_signs_in_with_a_prefixed_subject(stack: Stack, method: str) -> None:
    with httpx.Client(follow_redirects=False) as client:
        state, client_id, login_id = _start(stack, client)
        claims = _redeem(stack, client_id, state, _finish(stack, client, method, login_id))
    # Both providers name the person "mock-user"; the prefix keeps them apart.
    assert claims["sub"] == f"{method}:mock-user"


def test_sign_in_is_refused_from_another_browser(stack: Stack) -> None:
    with httpx.Client(follow_redirects=False) as victim, httpx.Client() as attacker:
        _state, _client_id, login_id = _start(stack, attacker)
        # The login link reaches a browser that did not approve consent.
        response = victim.post(f"{stack.url}/login/alpha", data={"login_id": login_id})
        assert response.status_code == 400
        assert "expired" in response.text.lower()

        # The refused request did not use up the real browser's sign-in.
        retry = attacker.post(
            f"{stack.url}/login/alpha", data={"login_id": login_id}, follow_redirects=False
        )
        assert retry.status_code == 303


def test_login_id_is_single_use(stack: Stack) -> None:
    with httpx.Client(follow_redirects=False) as client:
        _state, _client_id, login_id = _start(stack, client)
        first = client.post(f"{stack.url}/login/alpha", data={"login_id": login_id})
        assert first.status_code == 303
        second = client.post(f"{stack.url}/login/alpha", data={"login_id": login_id})
        assert second.status_code == 400


def test_unknown_method_is_not_found(stack: Stack) -> None:
    with httpx.Client(follow_redirects=False) as client:
        _state, _client_id, login_id = _start(stack, client)
        response = client.post(f"{stack.url}/login/nope", data={"login_id": login_id})
    assert response.status_code == 404
