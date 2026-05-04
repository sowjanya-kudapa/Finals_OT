import os
import json
import logging
import uuid
import base64
import re
import asyncio
from collections import defaultdict

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
import aiohttp

# ======================================================
# LOGGING
# ======================================================
logger = logging.getLogger()
logger.setLevel(os.getenv("LOG_LEVEL", "INFO").upper())

# ======================================================
# GLOBAL API CALL COUNTER
# ======================================================
_api_call_counts = defaultdict(int)

def _log_api_call(endpoint_label: str) -> int:
    _api_call_counts[endpoint_label] += 1
    count = _api_call_counts[endpoint_label]
    logger.info("[API_CALL_COUNTER] endpoint='%s' | call_number=%d | total=%d",
                endpoint_label, count, sum(_api_call_counts.values()))
    return count

def _log_api_summary():
    total = sum(_api_call_counts.values())
    logger.info("[API_CALL_SUMMARY] total_api_calls=%d | breakdown=%s",
                total, json.dumps(dict(_api_call_counts)))

def _reset_api_counters():
    _api_call_counts.clear()


# ======================================================
# LOAD ALL CONFIG FROM SINGLE ENV VARIABLE
# ======================================================
onetrust_config = json.loads(os.environ["Onetrust_Reference_Value"])

AWS_REGION           = onetrust_config["REGION_NAME"]
SECRET_NAME          = onetrust_config["SECRET_NAME"]
TOKEN_URL            = onetrust_config["TOKEN_URL"]
PROFILES_URL         = onetrust_config["PROFILES_URL"]
CONSENT_URL          = onetrust_config["CONSENT_URL"]
COLLECTION_POINT_URL = onetrust_config["COLLECTION_POINT_URL"]
PURPOSE_TABLE        = onetrust_config["PURPOSE_TABLE"]
PREFERENCE_TABLE     = onetrust_config["PREFERENCE_TABLE"]
COUNTRY_TABLE        = onetrust_config["COUNTRY_TABLE"]
REQUEST_TIMEOUT      = float(onetrust_config["REQUEST_TIMEOUT"])
REQUESTS_CA_BUNDLE   = onetrust_config.get("REQUESTS_CA_BUNDLE", False)

SSL_CONTEXT = None
if REQUESTS_CA_BUNDLE and isinstance(REQUESTS_CA_BUNDLE, str):
    import ssl
    SSL_CONTEXT = ssl.create_default_context(cafile=REQUESTS_CA_BUNDLE)

# ======================================================
# AWS CLIENTS  (synchronous — used via run_in_executor)
# ======================================================
botocore_cfg = Config(
    region_name=AWS_REGION,
    retries={"max_attempts": 3, "mode": "standard"},
    read_timeout=10,
    connect_timeout=5,
)
secrets_client = boto3.client("secretsmanager", config=botocore_cfg)
dynamodb_res   = boto3.resource("dynamodb", config=botocore_cfg)
purpose_table  = dynamodb_res.Table(PURPOSE_TABLE)
pref_table     = dynamodb_res.Table(PREFERENCE_TABLE)
country_table  = dynamodb_res.Table(COUNTRY_TABLE)

# ======================================================
# EMAIL VALIDATOR
# ======================================================
EMAIL_REGEX = re.compile(
    r"^[a-zA-Z0-9_.%+\-]+@[a-zA-Z0-9\-]+(\.[a-zA-Z0-9\-]+)*\.[a-zA-Z]{2,6}$"
)

def validate_email(email: str) -> bool:
    if not email or not isinstance(email, str):
        return False
    return bool(EMAIL_REGEX.match(email.strip()))


# ======================================================
# DATE VALIDATOR
# Format A: "2026-04-03 04:47:26.276 +0000" -> "2026-04-03 04:47:26"
# Format B: "2026-04-03T04:47:25.000Z"      -> "2026-04-03T04:47:25"
# ======================================================
DATE_TRUNCATED_REGEX = re.compile(
    r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}$"
)

def _validate_strict_date(date_str: str):
    if not date_str or not isinstance(date_str, str):
        return None
    truncated = date_str.strip()[:19]
    if not DATE_TRUNCATED_REGEX.match(truncated):
        return None
    return truncated


# ======================================================
# IDENTIFIER FORMAT VALIDATOR
# Must match: ^[A-Za-z0-9]+(_[A-Za-z0-9]+){2,}$
# Valid:   SA_AU_Email,  SA_TR_SMS_Phone
# Invalid: SA,  SA_AU,  SA-AU-Email
# ======================================================
IDENTIFIER_REGEX = re.compile(r"^[A-Za-z0-9]+(_[A-Za-z0-9]+){2,}$")

def _validate_identifier_format(identifier: str) -> bool:
    return bool(IDENTIFIER_REGEX.match(identifier.strip()))


# ======================================================
# COMMON RESPONSE BUILDER
# ======================================================
def http_response(status: int, message: str, data: dict) -> dict:
    return {
        "isBase64Encoded": False,
        "statusCode": status,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({
            "statusCode": status,
            "message":    message,
            "data":       data,
        }),
    }


# ======================================================
# PARSE EVENT BODY
# ======================================================
def parse_event_body(event: dict) -> dict:
    body   = event.get("body")
    is_b64 = event.get("isBase64Encoded", False)

    if isinstance(body, dict):
        return body
    if body is None:
        return event
    if is_b64 and isinstance(body, str):
        body = base64.b64decode(body).decode("utf-8")
    if isinstance(body, str):
        return json.loads(body)
    raise ValueError("Unsupported body type; must be JSON string or dict")


# ======================================================
# SECRETS MANAGER  (sync wrapped for executor)
# ======================================================
def _get_secret_sync() -> dict:
    try:
        resp = secrets_client.get_secret_value(SecretId=SECRET_NAME)
    except ClientError as e:
        raise RuntimeError(f"Secrets Manager error [{e.response['Error']['Code']}]: {e}") from e
    secret = resp.get("SecretString")
    if not secret:
        raise ValueError("SecretString is empty or missing.")
    return json.loads(secret)

async def get_secret() -> dict:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _get_secret_sync)


# ======================================================
# ONETRUST TOKEN  (async)
# ======================================================
async def fetch_token(session: aiohttp.ClientSession, client_id: str, client_secret: str) -> str:
    call_num = _log_api_call("TOKEN_URL")
    logger.info("Fetching access token | call=%d", call_num)
    async with session.post(
        TOKEN_URL,
        data={
            "grant_type":    "client_credentials",
            "client_id":     client_id,
            "client_secret": client_secret,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        ssl=SSL_CONTEXT or False,
        timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT),
    ) as resp:
        logger.info("Token response | status=%d | call=%d", resp.status, call_num)
        if not resp.ok:
            text = await resp.text()
            raise RuntimeError(f"Token API HTTP {resp.status}: {text}")
        data = await resp.json()
    token = data.get("access_token")
    if not token:
        raise ValueError("No access_token in response.")
    logger.info("Access token fetched successfully | call=%d", call_num)
    return token


# ======================================================
# CHECK DATA SUBJECT PROFILE  (async)
# ======================================================
async def check_profile(session: aiohttp.ClientSession, access_token: str, email: str) -> bool:
    call_num = _log_api_call("PROFILES_URL_check")
    logger.info("Checking profile for email='%s' | call=%d", email, call_num)
    async with session.get(
        PROFILES_URL,
        headers={
            "Authorization":    f"Bearer {access_token}",
            "dataElementName":  "email_address",
            "dataElementValue": email,
        },
        ssl=SSL_CONTEXT or False,
        timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT),
    ) as resp:
        logger.info("Profile check response | status=%d | call=%d", resp.status, call_num)
        if resp.status == 404:
            logger.info("Profile not found (404) for email='%s'", email)
            return False
        if not resp.ok:
            text = await resp.text()
            raise RuntimeError(f"Profile check HTTP {resp.status}: {text}")
        data = await resp.json()
    total = data.get("totalElements", 0)
    if total > 0:
        logger.info("Profile already exists for email='%s'", email)
        return True
    logger.info("Profile does not exist for email='%s'", email)
    return False


# ======================================================
# FETCH FULL DATA SUBJECT PROFILE BY OT UUID  (async)
# ======================================================
async def fetch_data_subject_by_uuid(session: aiohttp.ClientSession, access_token: str, ot_uuid: str) -> dict:
    call_num = _log_api_call("PROFILES_URL_fetch_uuid")
    logger.info("Fetching profile by UUID='%s' | call=%d", ot_uuid, call_num)
    async with session.get(
        PROFILES_URL,
        params={"identifier": ot_uuid},
        headers={"Authorization": f"Bearer {access_token}"},
        ssl=SSL_CONTEXT or False,
        timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT),
    ) as resp:
        logger.info("Fetch by UUID response | status=%d | call=%d", resp.status, call_num)
        if not resp.ok:
            text = await resp.text()
            raise RuntimeError(f"Data subject fetch by UUID HTTP {resp.status}: {text}")
        data = await resp.json()
    content = data.get("content", [])
    if not content:
        logger.warning("No profile found for UUID='%s'", ot_uuid)
        return {}
    logger.info("Profile fetched successfully for UUID='%s'", ot_uuid)
    return content[0]


# ======================================================
# FETCH COLLECTION POINT TOKEN  (async)
# ======================================================
async def fetch_request_info(session: aiohttp.ClientSession, access_token: str) -> str:
    call_num = _log_api_call("COLLECTION_POINT_URL")
    logger.info("Fetching collection point token | call=%d", call_num)
    async with session.get(
        COLLECTION_POINT_URL,
        headers={"Authorization": f"Bearer {access_token}"},
        ssl=SSL_CONTEXT or False,
        timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT),
    ) as resp:
        logger.info("Collection point response | status=%d | call=%d", resp.status, call_num)
        if not resp.ok:
            text = await resp.text()
            raise RuntimeError(f"Collection point API HTTP {resp.status}: {text}")
        data = await resp.json()
    token = data.get("token")
    if not token:
        raise ValueError("No token found in collection point response.")
    logger.info("Collection point token fetched | call=%d", call_num)
    return token


# ======================================================
# SUBMIT CONSENT RECEIPT  (async)
# ======================================================
async def submit_consent(session: aiohttp.ClientSession, access_token: str, payload: dict) -> dict:
    call_num = _log_api_call("CONSENT_URL")
    logger.info("Submitting consent receipt | call=%d", call_num)
    async with session.post(
        CONSENT_URL,
        json=payload,
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type":  "application/json",
        },
        ssl=SSL_CONTEXT or False,
        timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT),
    ) as resp:
        logger.info("Consent receipt response | status=%d | call=%d", resp.status, call_num)
        if not resp.ok:
            text = await resp.text()
            raise RuntimeError(f"Consent receipt HTTP {resp.status}: {text}")
        data = await resp.json()
    logger.info("Consent receipt submitted successfully | call=%d", call_num)
    return data


# ======================================================
# DYNAMODB — PURPOSE LOOKUP  (sync wrapped for executor)
# ======================================================
def _get_purpose_id_sync(purpose_name: str) -> str:
    try:
        resp = purpose_table.get_item(Key={"Purpose_Name": purpose_name})
        item = resp.get("Item")
        if not item or "Purpose_ID" not in item:
            raise RuntimeError(f"Purpose '{purpose_name}' not found in {PURPOSE_TABLE}.")
        return item["Purpose_ID"]
    except ClientError as e:
        raise RuntimeError(f"DynamoDB error [{e.response['Error']['Code']}]: {e}") from e

async def get_purpose_id(purpose_name: str) -> str:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _get_purpose_id_sync, purpose_name)


# ======================================================
# DYNAMODB — PREFERENCE (SUBSCRIPTION) LOOKUP  (sync wrapped for executor)
# ======================================================
def _get_preference_item_sync(unique_subscription_id: str) -> dict:
    try:
        resp = pref_table.get_item(Key={"UniqueSubcriptionID": unique_subscription_id})
        item = resp.get("Item")
        if not item:
            raise RuntimeError(f"Subscription '{unique_subscription_id}' not found in {PREFERENCE_TABLE}.")
        return item
    except ClientError as e:
        raise RuntimeError(f"DynamoDB error [{e.response['Error']['Code']}]: {e}") from e

async def get_preference_item(unique_subscription_id: str) -> dict:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _get_preference_item_sync, unique_subscription_id)


# ======================================================
# DYNAMODB — COUNTRY CODE LOOKUP  (sync wrapped for executor)
# Called ONCE in handler and passed down — no duplicate calls
# ======================================================
def _get_country2code_sync(cs_country: str) -> str:
    if not cs_country or not cs_country.strip():
        raise ValueError("cs_country is missing or empty.")
    val_upper = cs_country.strip().upper()
    try:
        resp = country_table.get_item(Key={"country3code": val_upper})
        item = resp.get("Item")
        if item:
            country2code = item["country2code"].upper()
            logger.info("Country code: '%s' -> '%s'", val_upper, country2code)
            return country2code
    except ClientError as e:
        raise RuntimeError(f"DynamoDB error [{e.response['Error']['Code']}]: {e}") from e
    raise ValueError(
        f"Country '{cs_country}' not found in {COUNTRY_TABLE}. "
        "Please provide a valid 3-letter country code."
    )

async def get_country2code(cs_country: str) -> str:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _get_country2code_sync, cs_country)


# ======================================================
# PRE-FLIGHT VALIDATION  (pure sync — no I/O)
# ======================================================
def preflight_validate(cs_consents: list, cs_subscriptions: list) -> tuple:
    valid_consents      = []
    valid_subscriptions = []
    skipped_items       = []

    # ── CS_CONSENTS ────────────────────────────────────
    for idx, consent in enumerate(cs_consents):
        identifier    = consent.get("identifier")
        consent_val   = consent.get("consent")
        signature_raw = consent.get("signatureDate", "")
        pos           = f"cs_consents[{idx}]"

        if not identifier or not isinstance(identifier, str) or not identifier.strip():
            logger.warning("CONSENT_SKIP_NO_IDENTIFIER | %s | reason: identifier is missing or empty", pos)
            skipped_items.append({
                "type": "consent", "position": pos,
                "identifier": identifier,
                "reason": "Identifier is empty or missing",
            })
            continue

        if not _validate_identifier_format(identifier):
            logger.warning(
                "CONSENT_SKIP_INVALID_IDENTIFIER_FORMAT | %s | identifier='%s' | "
                "reason: must match ^[A-Za-z0-9]+(_[A-Za-z0-9]+){2,}$",
                pos, identifier,
            )
            skipped_items.append({
                "type": "consent", "position": pos,
                "identifier": identifier,
                "reason": "Invalid identifier format",
            })
            continue

        if not isinstance(consent_val, bool):
            logger.warning(
                "CONSENT_SKIP_INVALID_CONSENT_VALUE | %s | identifier='%s' | "
                "reason: invalid consent value '%s' — only true or false are valid",
                pos, identifier, consent_val,
            )
            skipped_items.append({
                "type": "consent", "position": pos, "identifier": identifier,
                "reason": f"Invalid consent value '{consent_val}' — only true or false are valid",
            })
            continue

        if not signature_raw:
            logger.warning(
                "CONSENT_SKIP_NO_SIGNATURE_DATE | %s | identifier='%s' | "
                "reason: signatureDate is missing or empty",
                pos, identifier,
            )
            skipped_items.append({
                "type": "consent", "position": pos, "identifier": identifier,
                "reason": "signatureDate is missing or empty",
            })
            continue

        normalized_date = _validate_strict_date(signature_raw)
        if not normalized_date:
            logger.warning(
                "CONSENT_SKIP_INVALID_SIGNATURE_DATE_FORMAT | %s | identifier='%s' | "
                "signatureDate='%s' | reason: expected YYYY-MM-DD[T|space]HH:MM:SS[.mmm...][Z|+offset]",
                pos, identifier, signature_raw,
            )
            skipped_items.append({
                "type": "consent", "position": pos,
                "identifier": identifier, "signatureDate": signature_raw,
                "reason": (
                    f"Invalid signatureDate format '{signature_raw}' — "
                    "expected YYYY-MM-DDTHH:MM:SS.mmmZ or YYYY-MM-DD HH:MM:SS.mmm +0000"
                ),
            })
            continue

        consent["signatureDate"] = normalized_date
        valid_consents.append(consent)

    # ── CS_SUBSCRIPTIONS ───────────────────────────────
    for idx, sub in enumerate(cs_subscriptions):
        identifier  = sub.get("identifier")
        opt_in      = sub.get("optIn")
        opt_in_date = sub.get("optInDate", "")
        pos         = f"cs_subscriptions[{idx}]"

        if not identifier or not isinstance(identifier, str) or not identifier.strip():
            logger.warning("SUBSCRIPTION_SKIP_NO_IDENTIFIER | %s | reason: identifier is missing or empty", pos)
            skipped_items.append({
                "type": "subscription", "position": pos,
                "identifier": identifier,
                "reason": "identifier is missing or empty",
            })
            continue

        if not isinstance(opt_in, bool):
            logger.warning(
                "SUBSCRIPTION_SKIP_INVALID_OPT_IN_VALUE | %s | identifier='%s' | "
                "reason: invalid optIn value '%s' — only true or false are valid",
                pos, identifier, opt_in,
            )
            skipped_items.append({
                "type": "subscription", "position": pos, "identifier": identifier,
                "reason": f"optIn must be true/false, got type='{type(opt_in).__name__}' value='{opt_in}'",
            })
            continue

        if not opt_in_date:
            logger.warning(
                "SUBSCRIPTION_SKIP_NO_OPT_IN_DATE | %s | identifier='%s' | "
                "reason: optInDate is missing or empty",
                pos, identifier,
            )
            skipped_items.append({
                "type": "subscription", "position": pos, "identifier": identifier,
                "reason": "optInDate is missing or empty",
            })
            continue

        normalized_date = _validate_strict_date(opt_in_date)
        if not normalized_date:
            logger.warning(
                "SUBSCRIPTION_SKIP_INVALID_OPT_IN_DATE | %s | identifier='%s' | "
                "optInDate='%s' | reason: expected YYYY-MM-DD[T|space]HH:MM:SS[.mmm...][Z|+offset]",
                pos, identifier, opt_in_date,
            )
            skipped_items.append({
                "type": "subscription", "position": pos, "identifier": identifier,
                "reason": (
                    f"Invalid optInDate format '{opt_in_date}' — "
                    "expected YYYY-MM-DDTHH:MM:SS.mmmZ or YYYY-MM-DD HH:MM:SS.mmm +0000"
                ),
            })
            continue

        sub["_normalized_optInDate"]  = normalized_date
        sub["_optInDate_was_invalid"] = False
        valid_subscriptions.append(sub)

    logger.info(
        "Preflight done | consents=%d | subscriptions=%d | skipped=%d",
        len(valid_consents), len(valid_subscriptions), len(skipped_items),
    )
    return valid_consents, valid_subscriptions, skipped_items


# ======================================================
# SUBSCRIPTION DATE RESOLUTION  (async)
# ======================================================
async def _resolve_subscription_dates(
    valid_subscriptions: list,
    country_code: str,
    skipped_items: list,
) -> tuple:

    global_first_date = None

    for sub in valid_subscriptions:
        identifier = sub.get("identifier", "").strip()
        opt_in     = sub.get("optIn")
        norm_date  = sub.get("_normalized_optInDate", "")

        if opt_in is not True or not norm_date:
            continue

        unique_id = f"{country_code}_{identifier}"
        try:
            await get_preference_item(unique_id)
            global_first_date = norm_date
            logger.info(
                "First valid optInDate found | identifier='%s' | country_key='%s' | "
                "optIn=True | date='%s' | will use for all subscriptions",
                identifier, unique_id, norm_date,
            )
            break
        except RuntimeError:
            logger.warning(
                "Skipping for date selection | identifier='%s' | "
                "reason: not found in preference table for country='%s'",
                identifier, country_code,
            )

    if not global_first_date:
        logger.warning(
            "SUBSCRIPTION_SKIP_NO_VALID_OPT_IN_DATE | "
            "reason: no valid subscription found with optIn=True and valid optInDate."
        )
        for sub in valid_subscriptions:
            skipped_items.append({
                "type":       "subscription",
                "identifier": sub.get("identifier", ""),
                "reason":     (
                    "Subscription skipped — no valid subscription found. "
                    "Ensure at least one subscription has a valid optIn (true/false) "
                    "and optInDate (YYYY-MM-DDTHH:MM:SS.mmmZ)"
                ),
            })
        return [], skipped_items

    logger.info(
        "interactionDate='%s' will be applied to all %d subscription(s)",
        global_first_date, len(valid_subscriptions),
    )

    for sub in valid_subscriptions:
        identifier    = sub.get("identifier", "").strip()
        original_date = sub.get("_normalized_optInDate", "")
        if original_date != global_first_date:
            logger.info(
                "Subscription '%s' | own date='%s' -> overridden to '%s'",
                identifier, original_date, global_first_date,
            )
        sub["_normalized_optInDate"] = global_first_date

    logger.info(
        "All %d subscription(s) assigned interactionDate='%s'",
        len(valid_subscriptions), global_first_date,
    )
    return valid_subscriptions, skipped_items


# ======================================================
# BUILD BASE PAYLOAD SKELETON
# ======================================================
def _base_payload(
    ot_uuid: str,
    email: str,
    first_name: str,
    last_name: str,
    cs_country: str,
    hcp_status: str,
    profile_type: str,
    request_info: str,
    interaction_date: str,
    purposes: list,
) -> dict:
    return {
        "identifier":            ot_uuid,
        "identifierType":        "Sanofi_OT_uuid",
        "additionalIdentifiers": {"email_address": email},
        "requestInformation":    request_info,
        "interactionDate":       interaction_date,
        "purposes":              purposes,
        "dsDataElements": {
            "first_name":      first_name,
            "last_name":       last_name,
            "hcp_countrycode": cs_country,
            "hcp_status":      hcp_status,
            "profile_type":    profile_type,
        },
    }


# ======================================================
# MAP consents -> purposes list  (async)
# ======================================================
async def _map_consents_to_purposes(consents: list, skipped_items: list) -> list:
    purposes = []
    for consent in consents:
        identifier  = consent.get("identifier")
        consent_val = consent.get("consent")

        if not consent.get("signatureDate"):
            logger.warning("Consent '%s' has no signatureDate, skipping", identifier)
            continue

        transaction_type = "CONFIRMED" if consent_val else "OPT_OUT"
        logger.info("Consent '%s' | value=%s | type=%s", identifier, consent_val, transaction_type)
        try:
            purpose_id = await get_purpose_id(identifier)
            logger.info("Consent '%s' mapped to PurposeID='%s'", identifier, purpose_id)
        except RuntimeError as e:
            logger.error("Consent '%s' skipped | %s", identifier, str(e))
            skipped_items.append({
                "type":       "consent",
                "identifier": identifier,
                "reason":     f"identifier '{identifier}' not found in purpose table — not a valid consent for this country",
            })
            continue
        purposes.append({
            "Id":              purpose_id,
            "TransactionType": transaction_type,
            "PurposeNote": {
                "noteType":     "UNSUBSCRIBE_REASON",
                "noteLanguage": "en-us",
                "noteText":     consent.get("source", ""),
            },
        })
    return purposes


# ======================================================
# MAP subscriptions -> purposes list  (async)
# ======================================================
async def _map_subscriptions_to_purposes(
    cs_subscriptions: list, country_code: str, skipped_items: list
) -> list:
    if not cs_subscriptions:
        return []

    purpose_choices = defaultdict(
        lambda: {"purpose_id": None, "pref_list_id": None, "choices": []}
    )

    for sub in cs_subscriptions:
        identifier = sub.get("identifier", "")
        opt_in     = sub.get("optIn", False)
        unique_id  = f"{country_code}_{identifier}"
        logger.info("Looking up subscription '%s'", unique_id)
        try:
            pref_item = await get_preference_item(unique_id)
        except RuntimeError as e:
            logger.error("Subscription '%s' skipped | %s", unique_id, str(e))
            skipped_items.append({
                "type":       "subscription",
                "identifier": identifier,
                "reason":     f"identifier '{identifier}' not found in preference table for country — not a valid subscription for this country",
            })
            continue
        purpose_id   = pref_item.get("PurposeID")
        pref_list_id = pref_item.get("PurposeListID")
        option_id    = pref_item.get("CustomePrefernceOptionid")
        if not purpose_id or not pref_list_id or not option_id:
            logger.error("Subscription '%s' skipped | missing fields in preference table", unique_id)
            skipped_items.append({
                "type":       "subscription",
                "identifier": identifier,
                "reason":     f"identifier '{identifier}' found in preference table but missing required fields (PurposeID / PurposeListID / OptionID)",
            })
            continue
        purpose_choices[purpose_id]["purpose_id"]   = purpose_id
        purpose_choices[purpose_id]["pref_list_id"] = pref_list_id
        purpose_choices[purpose_id]["choices"].append({
            "TransactionType": "OPT_IN" if opt_in else "OPT_OUT",
            "OptionId":        option_id,
        })
        logger.info("Subscription '%s' mapped to PurposeID='%s' | optIn=%s",
                    unique_id, purpose_id, opt_in)

    purposes = []
    for purpose_id, data in purpose_choices.items():
        purposes.append({
            "Id":              purpose_id,
            "TransactionType": "CHANGE_PREFERENCES",
            "CustomPreferences": [{
                "Id":      data["pref_list_id"],
                "Choices": data["choices"],
            }],
        })
        logger.info("Built CHANGE_PREFERENCES | PurposeID='%s' | choices=%d",
                    purpose_id, len(data["choices"]))
    return purposes


# ======================================================
# BUILD CONSENT PAYLOAD  (async)
# country_code passed in — no duplicate DynamoDB call
# ======================================================
async def build_consent_payload(
    event: dict,
    request_info: str,
    skipped_items: list,
    country_code: str,
) -> tuple:
    email        = event.get("email", "")
    first_name   = event.get("given_name") or ""
    last_name    = event.get("family_name") or ""
    cs_country   = event.get("cs_country", "")
    hcp_status   = event.get("hcp_status") or "ACTIVE"
    profile_type = event.get("profile_type") or "HCP"

    ot_uuid = f"OT_{uuid.uuid4()}"
    logger.info("Generated OT UUID: %s", ot_uuid)
    logger.info("hcp_status=%s | profile_type=%s", hcp_status, profile_type)

    cs_consents      = event.get("_valid_consents", [])
    cs_subscriptions = event.get("_valid_subscriptions", [])

    logger.info("Building payload | consents=%d | subscriptions=%d",
                len(cs_consents), len(cs_subscriptions))

    date_map: dict = defaultdict(lambda: {"consents": [], "subscriptions": []})

    for c in cs_consents:
        date_map[c.get("signatureDate", "")]["consents"].append(c)

    for s in cs_subscriptions:
        date_map[s["_normalized_optInDate"]]["subscriptions"].append(s)

    all_dates = list(dict.fromkeys(
        [c.get("signatureDate", "") for c in cs_consents]
        + ([cs_subscriptions[0]["_normalized_optInDate"]] if cs_subscriptions else [])
    ))

    logger.info("Date buckets (%d): %s", len(all_dates), all_dates)
    if cs_subscriptions:
        logger.info("All %d subscription(s) will use interactionDate='%s'",
                    len(cs_subscriptions), cs_subscriptions[0]["_normalized_optInDate"])

    def _build(interaction_date: str, purposes: list) -> dict:
        return _base_payload(
            ot_uuid=ot_uuid, email=email, first_name=first_name,
            last_name=last_name, cs_country=cs_country, hcp_status=hcp_status,
            profile_type=profile_type, request_info=request_info,
            interaction_date=interaction_date, purposes=purposes,
        )

    payloads = []
    for date in all_dates:
        bucket = date_map[date]
        consent_purposes, sub_purposes = await asyncio.gather(
            _map_consents_to_purposes(bucket["consents"], skipped_items),
            _map_subscriptions_to_purposes(bucket["subscriptions"], country_code, skipped_items),
        )
        all_purposes = consent_purposes + sub_purposes

        if not all_purposes:
            logger.warning("Date bucket '%s' has no valid purposes, skipping", date)
            continue

        logger.info(
            "Date bucket '%s' | consents=%d (->%d) | subscriptions=%d (->%d) | total purposes=%d -> 1 call",
            date,
            len(bucket["consents"]), len(consent_purposes),
            len(bucket["subscriptions"]), len(sub_purposes),
            len(all_purposes),
        )
        payloads.append(_build(date, all_purposes))

    logger.info("Total CONSENT_URL calls planned: %d", len(payloads))
    return "single", payloads, ot_uuid


# ======================================================
# PARALLEL CONSENT SUBMISSION  (async — asyncio.gather)
# Uses return_exceptions=True so ALL receipts are attempted
# even if some fail — failed ones are logged with full detail
# ======================================================
async def _submit_all_payloads(
    http_session: aiohttp.ClientSession,
    access_token: str,
    payloads: list,
) -> int:
    total = len(payloads)
    logger.info("Submitting %d receipt(s) concurrently with asyncio.gather", total)

    async def _submit_one(idx: int, single_payload: dict):
        interaction_date = single_payload.get("interactionDate", "unknown")
        logger.info("Submitting receipt %d/%d | interactionDate='%s'",
                    idx, total, interaction_date)
        logger.info("Receipt %d/%d payload: %s",
                    idx, total, json.dumps(single_payload, indent=4))
        await submit_consent(http_session, access_token, single_payload)
        logger.info("Receipt %d/%d submitted successfully | interactionDate='%s'",
                    idx, total, interaction_date)
        return interaction_date

    # return_exceptions=True — ALL receipts are attempted even if some fail.
    # Failed ones come back as Exception objects instead of raising immediately.
    results = await asyncio.gather(
        *[_submit_one(idx, p) for idx, p in enumerate(payloads, start=1)],
        return_exceptions=True,
    )

    # ── Inspect every result ───────────────────────────
    succeeded = []
    failed    = []

    for idx, result in enumerate(results, start=1):
        interaction_date = payloads[idx - 1].get("interactionDate", "unknown")

        if isinstance(result, Exception):
            # This receipt failed — log exactly which one and why
            logger.error(
                "Receipt %d/%d FAILED | interactionDate='%s' | error='%s'",
                idx, total, interaction_date, str(result),
            )
            failed.append({
                "receipt_number":   idx,
                "interaction_date": interaction_date,
                "error":            str(result),
            })
        else:
            # This receipt succeeded
            logger.info(
                "Receipt %d/%d CONFIRMED succeeded | interactionDate='%s'",
                idx, total, interaction_date,
            )
            succeeded.append({
                "receipt_number":   idx,
                "interaction_date": interaction_date,
            })

    # ── Log final submission summary ───────────────────
    logger.info(
        "Submission summary | total=%d | succeeded=%d | failed=%d",
        total, len(succeeded), len(failed),
    )

    if failed:
        logger.error(
            "FAILED RECEIPTS DETAIL: %s",
            json.dumps(failed, indent=2),
        )
    if succeeded:
        logger.info(
            "SUCCEEDED RECEIPTS DETAIL: %s",
            json.dumps(succeeded, indent=2),
        )

    # ── Decide outcome ─────────────────────────────────
    if len(failed) == total:
        # Every single receipt failed — nothing was recorded
        raise RuntimeError(
            f"All {total} consent receipt(s) failed to submit. "
            f"Failed interaction dates: {[f['interaction_date'] for f in failed]}"
        )

    if failed:
        # Some succeeded, some failed — partial submission
        logger.warning(
            "PARTIAL SUBMISSION: %d/%d receipt(s) failed. "
            "Profile created with partial consents. "
            "Failed dates: %s | Succeeded dates: %s",
            len(failed), total,
            [f["interaction_date"] for f in failed],
            [s["interaction_date"] for s in succeeded],
        )
        return len(succeeded)

    # All succeeded
    logger.info("%d/%d receipt(s) submitted successfully", total, total)
    return total


# ======================================================
# ASYNC CORE HANDLER
# ======================================================
async def _async_handler(event: dict) -> dict:

    _reset_api_counters()
    logger.info("Lambda invocation started | counters reset")

    # 1. Validate src query param
    query_params = event.get("queryStringParameters") or {}
    src = query_params.get("src", "").lower()
    if src != "ciam":
        logger.error("Invalid src param | received='%s'", src)
        return http_response(400, "Missing or invalid query parameter. Please pass 'src=ciam' in the request.", {})
    logger.info("src=ciam validated")

    # 2. Parse event body
    try:
        logger.info("Parsing request body | type=%s", type(event.get("body")))
        payload = parse_event_body(event)
    except Exception as e:
        logger.error("Failed to parse body | %s", str(e))
        return http_response(400, "Request body is invalid or not proper JSON.", {})

    # 3. Validate email
    email = payload.get("email")
    if not email:
        logger.error("email is missing in request")
        return http_response(400, "email is missing in the request.", {})
    if not validate_email(email):
        logger.error("Invalid email format | email='%s'", email)
        return http_response(400, "email format is invalid. Please provide a valid email address.", {})
    logger.info("Email validated | email='%s'", email)

    # 4. Validate cs_country and resolve 2-letter code — ONE DynamoDB call
    cs_country = payload.get("cs_country", "")
    try:
        country_code = await get_country2code(cs_country)
        logger.info("Country validated and resolved | '%s' -> '%s'", cs_country, country_code)
    except ValueError as e:
        logger.error("Country validation failed | %s", str(e))
        return http_response(400, str(e), {})
    except RuntimeError as e:
        logger.error("Country DynamoDB error | %s", str(e))
        return http_response(500, "Could not validate country. Please try again later.", {})

    # 4b. Pre-flight validation
    raw_consents      = payload.get("cs_consents", [])
    raw_subscriptions = payload.get("cs_subscriptions", [])

    valid_consents, valid_subscriptions, skipped_items = preflight_validate(
        raw_consents, raw_subscriptions
    )

    # 4c. Resolve subscription interaction dates
    valid_subscriptions, skipped_items = await _resolve_subscription_dates(
        valid_subscriptions, country_code, skipped_items
    )

    payload["_valid_consents"]      = valid_consents
    payload["_valid_subscriptions"] = valid_subscriptions

    if skipped_items:
        logger.warning("%d item(s) skipped during validation: %s",
                       len(skipped_items), json.dumps(skipped_items, indent=2))

    # Consents/subscriptions are MANDATORY
    if not valid_consents and not valid_subscriptions:
        logger.error(
            "Nothing to submit | no valid consents or subscriptions provided | "
            "raw_consents=%d | raw_subscriptions=%d | skipped=%d",
            len(raw_consents), len(raw_subscriptions), len(skipped_items),
        )
        _log_api_summary()
        return http_response(400,
            "At least one valid consent or subscription is required to create a profile in OneTrust.", {})

    # 5. Retrieve secrets
    try:
        secret        = await get_secret()
        client_id     = secret["client_id"]
        client_secret = secret["client_secret"]
    except Exception as e:
        logger.error("Failed to load secrets | %s", str(e))
        return http_response(500, "Could not load configuration. Please try again later.", {})

    # 6–11: All HTTP calls share a single aiohttp session
    connector = aiohttp.TCPConnector(limit=20, ssl=SSL_CONTEXT or False)
    async with aiohttp.ClientSession(connector=connector) as http_session:

        # 6. Fetch access token
        try:
            access_token = await fetch_token(http_session, client_id, client_secret)
        except Exception as e:
            logger.error("Failed to fetch token | %s", str(e))
            _log_api_summary()
            return http_response(502, "Could not connect to OneTrust to get an access token. Please try again later.", {})

        # 7. Check if profile exists
        try:
            profile_exists = await check_profile(http_session, access_token, email)
        except Exception as e:
            logger.error("Profile check failed | %s", str(e))
            _log_api_summary()
            return http_response(502, "Could not connect to OneTrust. Please try again later.", {})

        if profile_exists:
            logger.info("Profile already exists, no action needed")
            _log_api_summary()
            return http_response(200, "Profile already exists in OneTrust.", {"action": "none"})

        # 8. Fetch collection point token
        try:
            request_info = await fetch_request_info(http_session, access_token)
        except Exception as e:
            logger.error("Collection point fetch failed | %s", str(e))
            _log_api_summary()
            return http_response(502, "Could not connect to OneTrust. Please try again later.", {})

        # 9. Build consent payloads
        try:
            route, payloads_list, ot_uuid = await build_consent_payload(
                payload, request_info, skipped_items, country_code
            )
            logger.info("Payload built | route='%s' | total_receipts=%d", route, len(payloads_list))
        except ValueError as e:
            logger.error("Payload build validation error | %s", str(e))
            _log_api_summary()
            return http_response(400, str(e), {})
        except Exception as e:
            logger.error("Payload build failed | %s", str(e))
            _log_api_summary()
            return http_response(500,
                "Could not build the consent payload. Please check the request data and try again.", {})

        # 10. Submit payloads concurrently
        try:
            submitted_count = await _submit_all_payloads(
                http_session, access_token, payloads_list
            )
            if submitted_count == 0:
                logger.error("No receipts submitted | all payloads were empty")
                _log_api_summary()
                return http_response(400,
                    "No valid consent receipts to submit. No profile was created.", {})

            # Partial success — some failed but profile still created with what succeeded
            if submitted_count < len(payloads_list):
                logger.warning(
                    "Partial submission: %d of %d receipt(s) succeeded. "
                    "Check FAILED RECEIPTS DETAIL in logs for which interaction dates failed.",
                    submitted_count, len(payloads_list),
                )
                # Continue to fetch profile — it was still created

        except RuntimeError as e:
            # ALL receipts failed — nothing was recorded in OneTrust
            logger.error("All consent submissions failed | %s", str(e))
            _log_api_summary()
            return http_response(502,
                "Could not submit consent to OneTrust. Please try again later.", {})
        except Exception as e:
            logger.error("Unexpected error during submission | %s", str(e))
            _log_api_summary()
            return http_response(502,
                "Could not submit consent to OneTrust. Please try again later.", {})

        # 11. Fetch created profile (non-blocking sleep)
        try:
            logger.info("Waiting 0.5s before fetching created profile...")
            await asyncio.sleep(0.5)
            data_subject = await fetch_data_subject_by_uuid(http_session, access_token, ot_uuid)
            logger.info("Created profile fetched: %s", json.dumps(data_subject))
        except Exception as e:
            logger.error("Failed to fetch created profile | %s", str(e))
            _log_api_summary()
            return http_response(502,
                "Consent was recorded but could not fetch the profile from OneTrust. Please try again later.", {})

    _log_api_summary()

    return http_response(200,
        "Profile created and consent recorded successfully in OneTrust.",
        {
            "action":       "created",
            "data_subject": data_subject,
        }
    )


# ======================================================
# LAMBDA ENTRY POINT
# asyncio.run() creates a fresh event loop per invocation —
# correct pattern for AWS Lambda.
# ======================================================
def lambda_handler(event, context):
    return asyncio.run(_async_handler(event))
