# tests/test_auth_session.py
"""Sesi login yang bertahan saat halaman dimuat ulang (cookie) dan berakhir ketika token kedaluwarsa atau logout."""
import base64
import json
import time
from types import SimpleNamespace

import pytest

from frontend.components import auth_panel
from frontend.utils import api_client


def _jwt(exp: float) -> str:
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")  # noqa: E731
    return f"{enc({'alg': 'HS256'})}.{enc({'sub': 'analis', 'exp': exp})}.tanda-tangan"


def test_token_expiry_and_seconds_left():
    now = time.time()
    token = _jwt(now + 3600)
    assert auth_panel.token_expiry(token) == pytest.approx(now + 3600)
    assert 3590 <= auth_panel.seconds_left(token, now) <= 3600
    assert auth_panel.seconds_left(_jwt(now - 5), now) == 0
    assert auth_panel.seconds_left("bukan-jwt") == 0 and auth_panel.token_expiry(None) is None


def test_cookie_script_sets_and_clears():
    set_js = auth_panel.cookie_script("abc.def.ghi", 3600, secure=True)
    assert "hast_session=abc.def.ghi" in set_js and "Max-Age=3600" in set_js
    assert "SameSite=Strict" in set_js and "Secure" in set_js
    clear_js = auth_panel.cookie_script(None, 0, secure=False)
    assert "hast_session=;" in clear_js and "Max-Age=0" in clear_js and "Secure" not in clear_js


@pytest.fixture
def fake_st(monkeypatch):
    fake = SimpleNamespace(session_state={}, context=SimpleNamespace(cookies={}))
    monkeypatch.setattr(auth_panel, "st", fake)
    return fake


def test_restore_from_valid_cookie(fake_st, monkeypatch):
    token = _jwt(time.time() + 1800)
    fake_st.context.cookies[auth_panel.SESSION_COOKIE] = token
    monkeypatch.setattr(auth_panel, "me_with_token", lambda t: {"username": "analis", "role": "analyst"})
    auth_panel._restore_from_cookie()
    assert fake_st.session_state["auth_token"] == token
    assert fake_st.session_state["auth_user"]["username"] == "analis"


def test_expired_or_rejected_cookie_is_cleared(fake_st, monkeypatch):
    fake_st.context.cookies[auth_panel.SESSION_COOKIE] = _jwt(time.time() - 60)
    auth_panel._restore_from_cookie()
    assert "auth_token" not in fake_st.session_state and fake_st.session_state["cookie_clear_pending"]

    fake_st.session_state.clear()
    fake_st.context.cookies[auth_panel.SESSION_COOKIE] = _jwt(time.time() + 600)

    def reject(token):
        raise api_client.ApiError("Token tidak valid", 401)
    monkeypatch.setattr(auth_panel, "me_with_token", reject)
    auth_panel._restore_from_cookie()
    assert "auth_token" not in fake_st.session_state and fake_st.session_state["cookie_clear_pending"]


def test_logout_and_expiry_end_session_without_restoring(fake_st, monkeypatch):
    token = _jwt(time.time() + 600)
    fake_st.context.cookies[auth_panel.SESSION_COOKIE] = token
    fake_st.session_state.update({"auth_token": token, "auth_user": {"username": "analis"}})
    auth_panel._end_session(expired=False)
    monkeypatch.setattr(auth_panel, "me_with_token", lambda t: {"username": "analis"})
    auth_panel._restore_from_cookie()  # cookie lama masih terbaca dalam sesi ini, tetapi tidak dipulihkan
    assert "auth_token" not in fake_st.session_state and fake_st.session_state["cookie_clear_pending"]

    fake_st.session_state.clear()
    fake_st.session_state.update({"auth_token": _jwt(time.time() - 1), "auth_user": {"username": "analis"},
                                  "skip_cookie_restore": True})
    auth_panel._enforce_expiry()
    assert "auth_token" not in fake_st.session_state and fake_st.session_state["session_expired"]


def test_api_401_ends_session(monkeypatch):
    import streamlit
    state = {"auth_token": "kedaluwarsa", "auth_user": {"username": "analis"}}
    monkeypatch.setattr(streamlit, "session_state", state)

    class Resp:
        status_code, content, headers, text = 401, b'{"detail": "Token kedaluwarsa"}', {"content-type": "json"}, ""

        def json(self):
            return {"detail": "Token kedaluwarsa"}
    monkeypatch.setattr(api_client.requests, "request", lambda *a, **k: Resp())
    with pytest.raises(api_client.ApiError):
        api_client.list_users()
    assert "auth_token" not in state and state["session_expired"] and state["cookie_clear_pending"]
