#!/usr/bin/env python3
"""Validate and materialize synthetic Jeeb data for an ephemeral lease."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from decimal import Decimal, InvalidOperation
from typing import Any


SEED_KEYS = {"users"}
USER_KEYS = {"id", "email", "username", "type", "wallets"}
WALLET_KEYS = {"id", "currencyId", "type", "balance", "note"}
USER_TYPES = {"regular", "jeeber", "admin"}
SUPPORTED_CURRENCY_IDS = {1, 2}
EMAIL_RE = re.compile(r"^[a-z0-9][a-z0-9._+-]{0,127}@[a-z0-9][a-z0-9.-]{0,126}$")
WALLET_TYPE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,49}$")
MONEY_RE = re.compile(r"^(?:0|[1-9][0-9]{0,18})(?:\.[0-9]{1,2})?$")
MAX_BALANCE = Decimal("9999999999999999999.99")


class SeedContractError(ValueError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SeedContractError(message)


def _strict_keys(value: dict[str, Any], expected: set[str], context: str) -> None:
    missing = sorted(expected - set(value))
    unknown = sorted(set(value) - expected)
    require(not missing, f"{context} is missing: {', '.join(missing)}")
    require(not unknown, f"{context} contains unknown fields: {', '.join(unknown)}")


def _uuid(value: Any, context: str) -> str:
    require(isinstance(value, str), f"{context} must be a UUID string")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise SeedContractError(f"{context} must be a UUID string") from exc
    require(parsed.int != 0 and value == str(parsed), f"{context} must be a canonical non-zero UUID")
    return value


def _plain_text(value: Any, context: str, maximum: int) -> str:
    require(isinstance(value, str) and 1 <= len(value) <= maximum, f"{context} must be 1..{maximum} characters")
    require(value == value.strip(), f"{context} must not have surrounding whitespace")
    require(all(32 <= ord(character) <= 126 for character in value), f"{context} must be printable ASCII")
    return value


def _balance(value: Any, context: str) -> Decimal:
    require(
        isinstance(value, str) and MONEY_RE.fullmatch(value) is not None,
        f"{context} must be a non-negative decimal string with at most two decimal places",
    )
    try:
        amount = Decimal(value)
    except InvalidOperation as exc:
        raise SeedContractError(f"{context} is invalid") from exc
    require(amount <= MAX_BALANCE, f"{context} exceeds wallet-service precision")
    return amount


def validate_seed_data(seed_data: Any) -> dict[str, Any]:
    require(isinstance(seed_data, dict), "seedData must be an object")
    _strict_keys(seed_data, SEED_KEYS, "seedData")
    users = seed_data["users"]
    require(isinstance(users, list) and 2 <= len(users) <= 50, "seedData.users must contain 2..50 users")

    user_ids: set[str] = set()
    wallet_ids: set[str] = set()
    emails: set[str] = set()
    user_types: set[str] = set()
    for user_index, user in enumerate(users):
        context = f"seedData.users[{user_index}]"
        require(isinstance(user, dict), f"{context} must be an object")
        _strict_keys(user, USER_KEYS, context)
        user_id = _uuid(user["id"], f"{context}.id")
        require(user_id not in user_ids, f"duplicate seed user ID: {user_id}")
        user_ids.add(user_id)

        email = user["email"]
        require(
            isinstance(email, str) and len(email) <= 256 and EMAIL_RE.fullmatch(email) is not None,
            f"{context}.email is invalid",
        )
        require(email not in emails, f"duplicate seed email: {email}")
        emails.add(email)
        _plain_text(user["username"], f"{context}.username", 100)

        user_type = user["type"]
        require(user_type in USER_TYPES, f"{context}.type must be regular, jeeber, or admin")
        user_types.add(user_type)
        wallets = user["wallets"]
        minimum_wallets = 0 if user_type == "admin" else 1
        require(isinstance(wallets, list), f"{context}.wallets must be an array")
        require(
            minimum_wallets <= len(wallets) <= len(SUPPORTED_CURRENCY_IDS),
            f"{context}.wallets must contain {minimum_wallets}..{len(SUPPORTED_CURRENCY_IDS)} wallets",
        )
        currencies: set[int] = set()
        for wallet_index, wallet in enumerate(wallets):
            wallet_context = f"{context}.wallets[{wallet_index}]"
            require(isinstance(wallet, dict), f"{wallet_context} must be an object")
            _strict_keys(wallet, WALLET_KEYS, wallet_context)
            wallet_id = _uuid(wallet["id"], f"{wallet_context}.id")
            require(wallet_id not in wallet_ids, f"duplicate seed wallet ID: {wallet_id}")
            wallet_ids.add(wallet_id)
            currency_id = wallet["currencyId"]
            require(
                type(currency_id) is int and currency_id in SUPPORTED_CURRENCY_IDS,
                f"{wallet_context}.currencyId must be 1 or 2",
            )
            require(currency_id not in currencies, f"{context} contains duplicate currencyId {currency_id}")
            currencies.add(currency_id)
            require(
                isinstance(wallet["type"], str) and WALLET_TYPE_RE.fullmatch(wallet["type"]) is not None,
                f"{wallet_context}.type is invalid",
            )
            _balance(wallet["balance"], f"{wallet_context}.balance")
            _plain_text(wallet["note"], f"{wallet_context}.note", 200)
        if user_type == "jeeber":
            require(currencies == SUPPORTED_CURRENCY_IDS, f"{context} jeeber wallets must include currencyId 1 and 2")

    require(
        user_types == USER_TYPES,
        "seedData must contain at least one regular user, one jeeber, and one admin",
    )
    return seed_data


def seed_digest(seed_data: dict[str, Any]) -> str:
    validate_seed_data(seed_data)
    return hashlib.sha256(canonical(seed_data)).hexdigest()


def seed_counts(seed_data: dict[str, Any]) -> dict[str, int]:
    validate_seed_data(seed_data)
    users = seed_data["users"]
    return {
        "users": len(users),
        "regularUsers": sum(user["type"] == "regular" for user in users),
        "jeebers": sum(user["type"] == "jeeber" for user in users),
        "admins": sum(user["type"] == "admin" for user in users),
        "wallets": sum(len(user["wallets"]) for user in users),
    }


def roles_for(user_type: str) -> tuple[list[str], str, str]:
    if user_type == "jeeber":
        return ["customer", "driver"], "driver", "jeeber"
    if user_type == "admin":
        return ["admin"], "admin", "admin"
    return ["customer"], "customer", "customer"


def wallet_total(user: dict[str, Any]) -> Decimal:
    return sum((_balance(wallet["balance"], "wallet balance") for wallet in user["wallets"]), Decimal("0"))


def _literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _uuid_list(values: list[str]) -> str:
    return "ARRAY[" + ",".join(f"{_literal(value)}::uuid" for value in values) + "]"


def build_user_seed_sql(seed_data: dict[str, Any]) -> bytes:
    validate_seed_data(seed_data)
    statements = ["BEGIN;", "SET LOCAL lock_timeout = '10s';"]
    for user in seed_data["users"]:
        roles, active_role, _ = roles_for(user["type"])
        role_array = "ARRAY[" + ",".join(_literal(role) for role in roles) + "]::text[]"
        referral = "EPH-" + user["id"].replace("-", "")[-12:].upper()
        statements.append(
            """
INSERT INTO public."Users"
    ("Id", "Email", "Password", "Username", "ReferralCode", "CreatedDate",
     "AvailableRoles", "ActiveRole", "IsSuspended")
VALUES
    ({user_id}::uuid, {email}, '', {username}, {referral}, CURRENT_TIMESTAMP,
     {roles}, {active_role}, FALSE)
ON CONFLICT ("Id") DO UPDATE SET
    "Email" = EXCLUDED."Email",
    "Username" = EXCLUDED."Username",
    "ReferralCode" = EXCLUDED."ReferralCode",
    "AvailableRoles" = EXCLUDED."AvailableRoles",
    "ActiveRole" = EXCLUDED."ActiveRole",
    "IsSuspended" = FALSE;
""".format(
                user_id=_literal(user["id"]),
                email=_literal(user["email"]),
                username=_literal(user["username"]),
                referral=_literal(referral),
                roles=role_array,
                active_role=_literal(active_role),
            )
        )
    ids = [user["id"] for user in seed_data["users"]]
    statements.extend(
        (
            "COMMIT;",
            "SELECT json_build_object('users', COUNT(*))::text "
            f"FROM public.\"Users\" WHERE \"Id\" = ANY({_uuid_list(ids)});",
        )
    )
    return "\n".join(statements).encode()


def build_wallet_seed_sql(seed_data: dict[str, Any]) -> bytes:
    validate_seed_data(seed_data)
    statements = ["BEGIN;", "SET LOCAL lock_timeout = '10s';"]
    for user in seed_data["users"]:
        if not user["wallets"]:
            continue
        _, _, holder_type = roles_for(user["type"])
        statements.append(
            """
INSERT INTO public.walletholder (holderid, holdername, holdertype, isactive, createdat)
VALUES ({holder_id}::uuid, {holder_name}, {holder_type}, TRUE, CURRENT_TIMESTAMP)
ON CONFLICT (holderid) DO UPDATE SET
    holdername = EXCLUDED.holdername,
    holdertype = EXCLUDED.holdertype,
    isactive = TRUE;
""".format(
                holder_id=_literal(user["id"]),
                holder_name=_literal(user["username"]),
                holder_type=_literal(holder_type),
            )
        )
        for wallet in user["wallets"]:
            amount = format(_balance(wallet["balance"], "wallet balance"), "f")
            statements.append(
                """
INSERT INTO public.wallets
    (walletid, holderid, currencyid, amount, type, note, isactive, createdat)
VALUES
    ({wallet_id}::uuid, {holder_id}::uuid, {currency_id}, {amount}::numeric,
     {wallet_type}, {note}, TRUE, CURRENT_TIMESTAMP)
ON CONFLICT (walletid) DO UPDATE SET
    holderid = EXCLUDED.holderid,
    currencyid = EXCLUDED.currencyid,
    amount = EXCLUDED.amount,
    type = EXCLUDED.type,
    note = EXCLUDED.note,
    isactive = TRUE;
""".format(
                    wallet_id=_literal(wallet["id"]),
                    holder_id=_literal(user["id"]),
                    currency_id=wallet["currencyId"],
                    amount=amount,
                    wallet_type=_literal(wallet["type"]),
                    note=_literal(wallet["note"]),
                )
            )
    wallet_ids = [wallet["id"] for user in seed_data["users"] for wallet in user["wallets"]]
    expected_total = format(sum((wallet_total(user) for user in seed_data["users"]), Decimal("0")), "f")
    statements.extend(
        (
            "COMMIT;",
            "SELECT json_build_object("
            "'wallets', COUNT(*), "
            "'balance', COALESCE(SUM(amount), 0)::text"
            ")::text FROM public.wallets "
            f"WHERE walletid = ANY({_uuid_list(wallet_ids)});",
            f"-- expected seeded balance: {expected_total}",
        )
    )
    return "\n".join(statements).encode()
