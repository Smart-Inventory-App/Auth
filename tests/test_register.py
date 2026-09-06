"""Tests para POST /auth/register."""
from tests.conftest import register_user, TEST_EMAIL, VALID_PASSWORD


def test_register_success(client):
    r = register_user(client)
    assert r.status_code == 201


def test_register_duplicate_email_returns_400(client):
    register_user(client)
    r = register_user(client)
    assert r.status_code == 400
    assert r.json()["detail"] == "auth.email_already_registered"


def test_register_password_too_short(client):
    r = client.post("/auth/register", json={"email": TEST_EMAIL, "password": "Ab1."})
    assert r.status_code == 400
    assert r.json()["detail"] == "auth.password_too_short"


def test_register_password_missing_uppercase(client):
    r = client.post("/auth/register", json={"email": TEST_EMAIL, "password": "patronus.3"})
    assert r.status_code == 400
    assert r.json()["detail"] == "auth.password_missing_uppercase"


def test_register_password_missing_lowercase(client):
    r = client.post("/auth/register", json={"email": TEST_EMAIL, "password": "PATRONUS.3"})
    assert r.status_code == 400
    assert r.json()["detail"] == "auth.password_missing_lowercase"


def test_register_password_missing_digit(client):
    r = client.post("/auth/register", json={"email": TEST_EMAIL, "password": "Patronus.X"})
    assert r.status_code == 400
    assert r.json()["detail"] == "auth.password_missing_digit"
