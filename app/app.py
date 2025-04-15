#!/usr/bin/env python3
import os
import time
import json
import logging
from urllib.parse import urlencode
from flask import Flask, request, jsonify, redirect, render_template, session, url_for
from authlib.integrations.flask_oauth2 import AuthorizationServer, ResourceProtector
from authlib.jose import JsonWebKey, JsonWebSignature, jwt
from authlib.common.encoding import urlsafe_b64encode
from authlib.oauth2.rfc6749 import grants
from authlib.oauth2.rfc6750 import BearerTokenValidator
from authlib.oidc.core import UserInfo
from authlib.oidc.core.grants import OpenIDCode, OpenIDImplicitGrant, OpenIDHybridGrant
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import secrets
import uuid # Lägg till import för uuid

# Konfigurera loggning
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-key") # Krävs av Authlib för sessionshantering

# --- Konfiguration ---
BASE_URL = os.environ.get("BASE_URL", "http://localhost:8000")
ISSUER = os.environ.get("ISSUER", BASE_URL)

# --- Enkel in-memory databas för mock ---
# Användare
mock_users = {
    "testuser": {
        "sub": "testuser",
        "name": "Test Användare Alpha",
        "email": "test.alpha@example.com",
        "given_name": "Test",
        "family_name": "Alpha",
        "password": "password"
    },
    "betauser": {
        "sub": "betauser",
        "name": "Beta Test Användare",
        "email": "test.beta@example.com",
        "given_name": "Beta",
        "family_name": "Testare",
        "password": "password"
    },
     "gammauser": {
        "sub": "gammauser",
        "name": "Gamma Test Användare",
        "email": "test.gamma@example.com",
        "given_name": "Gamma",
        "family_name": "Testare",
        "password": "password"
    }
}

# Definiera IdP-profiler kopplade till användare
idp_hosts = [
    {"id": "idp_alpha", "name": "IdP Alpha (testuser)", "user": "testuser", "target_base_url": "https://idp.alpha.example.org"},
    {"id": "idp_beta", "name": "IdP Beta (betauser)", "user": "betauser", "target_base_url": "https://idp.beta.example.net"},
    {"id": "idp_gamma", "name": "IdP Gamma (gammauser)", "user": "gammauser", "target_base_url": "https://idp.gamma.example.com"},
]

# Klienter
mock_clients = {
    "confidential_client": {
        "client_id": "confidential_client",
        "client_secret": "confidential-secret",
        "client_id_issued_at": int(time.time()),
        "client_secret_expires_at": 0, # Never expires
        "client_metadata": {
            "client_name": "Confidential Test Client",
            "scope": "openid profile email",
            "redirect_uris": ["http://localhost:3000/callback", "http://127.0.0.1:3000/callback"],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "client_secret_basic"
        }
    },
    "public_client": {
        "client_id": "public_client",
        "client_secret": None, # Public clients have no secret
        "client_id_issued_at": int(time.time()),
        "client_secret_expires_at": 0,
        "client_metadata": {
            "client_name": "Public Test Client",
            "scope": "openid profile",
            "redirect_uris": ["http://localhost:3001/callback", "com.example.myapp:/oauth2redirect/example-provider"],
            "grant_types": ["authorization_code", "implicit"], # Implicit often used by public clients
            "response_types": ["code", "token", "id_token", "token id_token"], # Implicit requires token/id_token
            "token_endpoint_auth_method": "none" # Public clients don't authenticate at token endpoint
        }
    }
}

# Token/Code lagring
token_storage = {}
auth_code_storage = {}

# --- Nyckelhantering (JWK) ---
key_path = "app/private.pem"
private_key_obj = None # JsonWebKey object
public_jwk_dict = None # Public key as dict

# Helper för int till base64url string
def int_to_base64url_str(val):
    # Beräkna minsta antal bytes som behövs
    num_bytes = (val.bit_length() + 7) // 8
    # Konvertera int till bytes (big-endian är standard för JWK)
    byte_val = val.to_bytes(num_bytes, 'big')
    # Base64url-koda, dekoda till ascii, ta bort padding
    return urlsafe_b64encode(byte_val).decode('ascii').rstrip('=')

if os.path.exists(key_path):
    logger.info(f"Attempting to load private key from {key_path}")
    try:
        with open(key_path, "rb") as f:
            key_bytes = f.read()
            # Importera PEM till JsonWebKey object
            private_key_obj = JsonWebKey.import_key(key_bytes, {'use': 'sig', 'alg': 'RS256'}) # Lägg till alg här också
            # Skapa publik dict från laddat objekt
            public_jwk_dict = json.loads(private_key_obj.public_jwk())
            # Säkerställ att kid finns i den publika dicten (beräkna om nödvändigt)
            if 'kid' not in public_jwk_dict:
                 public_jwk_dict['kid'] = private_key_obj.thumbprint()
                 logger.info(f"Calculated missing kid for loaded key: {public_jwk_dict['kid']}")
            # Säkerställ use och alg
            public_jwk_dict.setdefault('use', 'sig')
            public_jwk_dict.setdefault('alg', 'RS256')

            logger.info(f"Successfully loaded private key (kid: {public_jwk_dict.get('kid')}).")
    except Exception as e:
        logger.error(f"Failed to load or import private key from {key_path}: {e}", exc_info=True)
        private_key_obj = None

if not private_key_obj:
    logger.info(f"Generating new RSA key pair and JWK...")
    try:
        # 1. Generera cryptography key object
        crypto_private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        crypto_public_key = crypto_private_key.public_key()

        # 2. Bygg den *publika* JWK dictionaryn (utan kid)
        private_numbers = crypto_private_key.private_numbers()
        public_numbers = crypto_public_key.public_numbers()

        public_jwk_dict_tmp = {
            "kty": "RSA", "use": "sig", "alg": "RS256",
            "n": int_to_base64url_str(public_numbers.n),
            "e": int_to_base64url_str(public_numbers.e),
        }

        # 3. Importera den publika dicten till ett TEMPORÄRT JsonWebKey objekt
        public_key_obj_tmp = JsonWebKey.import_key(public_jwk_dict_tmp, {'use': 'sig', 'alg': 'RS256'})

        # 4. Beräkna thumbprint (kid) FRÅN det temporära publika objektet
        kid = public_key_obj_tmp.thumbprint()
        logger.info(f"Calculated key thumbprint (kid): {kid}")

        # 5. Skapa den *slutliga* publika dicten genom att lägga till kid
        public_jwk_dict = public_jwk_dict_tmp.copy() # Gör en kopia
        public_jwk_dict['kid'] = kid

        # 6. Bygg den *privata* JWK dictionaryn med alla komponenter (inkl. kid)
        private_jwk_dict = {
            **public_jwk_dict, # Använd den slutliga publika dicten
            "d": int_to_base64url_str(private_numbers.d),
            "p": int_to_base64url_str(private_numbers.p),
            "q": int_to_base64url_str(private_numbers.q),
            "dp": int_to_base64url_str(private_numbers.dmp1),
            "dq": int_to_base64url_str(private_numbers.dmq1),
            "qi": int_to_base64url_str(private_numbers.iqmp),
        }

        # 7. Importera den *privata* dictionaryn till det *slutliga* privata JsonWebKey objektet
        private_key_obj = JsonWebKey.import_key(private_jwk_dict, {'use': 'sig', 'alg': 'RS256'})
        logger.info(f"Generated final private key object (kid: {kid}).")

        # 8. Exportera och spara PEM från cryptography-objektet
        pem = crypto_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        os.makedirs(os.path.dirname(key_path), exist_ok=True)
        with open(key_path, "wb") as f:
            f.write(pem)
        logger.info(f"Saved new private key to {key_path}")

    except Exception as e:
        logger.error(f"Failed during key generation or saving: {e}", exc_info=True)
        raise RuntimeError("Fatal error: Could not load or generate private key.") from e

# Säkerställ att public_jwk_dict finns
if not public_jwk_dict:
     raise RuntimeError("Fatal error: Public JWK dictionary could not be determined.")
if 'kid' not in public_jwk_dict:
     raise RuntimeError("Fatal error: Public JWK dictionary missing 'kid'.")

# Funktion för att hämta publika nycklar till JWKS endpoint
def load_jwks():
    # Returnera den förberedda publika dictionaryn i en lista
    return {"keys": [public_jwk_dict]}

# --- Authlib Server Setup ---

# Query client funktion
def query_client(client_id):
    client_info = mock_clients.get(client_id)
    if client_info:
        client = {**client_info, **client_info.get("client_metadata", {})}
        client.pop("client_metadata", None)
        return client
    return None

# Spara token funktion
def save_token(token, request):
    grant_user = request.user
    client = request.client # client är en dict när den anropas från /execute_flow
    user_id = grant_user.get("sub") if grant_user else None
    # Använd ['client_id'] istället för .client_id
    client_id = client['client_id']
    key = f"{client_id}:{user_id}:{token.get('token_type', 'bearer')}"
    # Lägg till sub i token om det saknas, hämtat från user
    if 'sub' not in token and user_id:
        token['sub'] = user_id
    token_storage[key] = token
    # Uppdatera loggning också
    logger.info(f"Saved token for client {client.get('client_id', 'N/A')}, user {user_id}: {token['token_type']}")

# Hämta token funktion (används sällan direkt med bearer tokens)
# För demonstration, även om ResourceProtector oftast validerar direkt
def query_token(access_token, token_type_hint):
     for key, token_data in token_storage.items():
         if token_data.get('access_token') == access_token and token_data.get('token_type') == token_type_hint:
             return token_data
     return None

# Bearer token validator
class MyBearerTokenValidator(BearerTokenValidator):
    def authenticate_token(self, token_string):
        for key, token_data in token_storage.items():
            if token_data.get('access_token') == token_string:
                if 'expires_at' in token_data and token_data['expires_at'] >= time.time():
                    return token_data
                else:
                    logger.warning(f"Authenticate token: Found token but it has expired.")
                    return None
        logger.warning(f"Authenticate token: Token not found.")
        return None

    def request_invalid(self, request):
        return False # Låt Authlib hantera detta

    def token_revoked(self, token):
        # Vi hanterar inte återkallning i denna mock
        return False

# Mock Request Object för interna anrop - FLYTTAD HIT
class MockAuthlibRequest:
    def __init__(self, user, client, data=None, redirect_uri=None, scope=None, response_type=None, nonce=None):
        self.user = user
        self.client = client
        self.data = data or {}
        self.redirect_uri = redirect_uri
        self.scope = scope
        self.response_type = response_type
        self.nonce = nonce

# Funktion för att SPARA authorization code (ersätter generate_...)
def save_authorization_code(code, request):
    grant_user = request.user
    client = request.client
    item = {
        'code': code,
        'client_id': client['client_id'],
        'redirect_uri': request.redirect_uri,
        'response_type': request.response_type,
        'scope': request.scope,
        'user_id': grant_user.get('sub') if grant_user else None,
        'auth_time': int(time.time()),
        'nonce': request.nonce,
        'code_challenge': request.data.get('code_challenge'),
        'code_challenge_method': request.data.get('code_challenge_method'),
    }
    auth_code_storage[code] = item
    logger.info(f"Saved auth code {code} for client {client.get('client_id', 'N/A')}, user {item['user_id']}")

# Funktion för att hämta sparad Authorization Code
def query_authorization_code(code, client):
     item = auth_code_storage.get(code)
     if item and item['client_id'] == client['client_id']:
         item['get_redirect_uri'] = lambda: item['redirect_uri']
         item['get_scope'] = lambda: item['scope']
         item['get_nonce'] = lambda: item.get('nonce')
         item['get_code_challenge'] = lambda: item.get('code_challenge')
         item['get_code_challenge_method'] = lambda: item.get('code_challenge_method')
         item['auth_time'] = item.get('auth_time', int(time.time()))
         return item
     elif item:
         logger.warning(f"Auth code {code} found, but client ID mismatch. Expected: {client.get('client_id')}, Found in code: {item.get('client_id')}")
     return None

# Funktion för att radera använd Authorization Code
def delete_authorization_code(authorization_code):
     code_val = authorization_code['code']
     if code_val in auth_code_storage:
         del auth_code_storage[code_val]
         logger.info(f"Deleted auth code {code_val}")

# Funktion för att autentisera användaren (anropas av Authorization Code Grant)
def authenticate_user(authorization_code):
    user_id = authorization_code.get('user_id')
    if user_id:
        return mock_users.get(user_id)
    return None

# Konfigurera servern
server = AuthorizationServer(
    app,
    query_client=query_client,
    save_token=save_token,
)

# Funktion för att generera ID Token - Skicka payload till serialize_compact
def generate_id_token(token, grant_request, user):
    # Definiera skyddad header
    protected_header = {'alg': 'RS256', 'kid': public_jwk_dict['kid']}

    # Skapa claims (payload)
    claims = {
        'iss': ISSUER, 'sub': user.get('sub'), 'aud': token['client_id'],
        'exp': token['expires_at'], 'iat': int(time.time()),
    }
    auth_time_val = getattr(grant_request, 'auth_time', None) or grant_request.get('auth_time', claims['iat'])
    claims['auth_time'] = auth_time_val
    nonce_val = getattr(grant_request, 'nonce', None) or grant_request.get('nonce')
    if nonce_val: claims['nonce'] = nonce_val
    scopes = set(token.get('scope', '').split())
    if 'profile' in scopes:
        claims.update({'name': user.get('name'), 'family_name': user.get('family_name'), 'given_name': user.get('given_name'),})
    if 'email' in scopes:
        claims.update({'email': user.get('email')})

    # Skapa JWS-objektet UTAN argument
    jws = JsonWebSignature()

    # Serialisera payload till bytes
    claims_bytes = json.dumps(claims, separators=(',', ':')).encode('utf-8')

    # Hämta den RÅA privata nyckeln från JsonWebKey-objektet
    try:
        raw_private_key = private_key_obj.get_private_key()
    except AttributeError:
        logger.error("Failed to get raw private key from private_key_obj")
        raise

    # Serialisera och signera med den RÅA privata nyckeln
    # Skicka med headern, payloaden (bytes) och nyckeln
    try:
        id_token_str = jws.serialize_compact(protected_header, claims_bytes, raw_private_key)
        logger.info(f"Generated ID token for user {user.get('sub')}")
        return id_token_str
    except Exception as e:
         logger.error(f"Error during serialize_compact with header+payload+raw key: {e}", exc_info=True)
         raise # Återkasta felet för att se det tydligt

# Registrera grants
# Authorization Code Grant (med OpenID Connect)
server.register_grant(
    OpenIDCode,
    [
        save_authorization_code,
        query_authorization_code,
        delete_authorization_code,
        authenticate_user
    ]
)
# Implicit Grant (med OpenID Connect) - för 'token' och 'id_token' response types
server.register_grant(OpenIDImplicitGrant)
# Hybrid Grant (med OpenID Connect) - för 'code token', 'code id_token' etc.
server.register_grant(OpenIDHybridGrant)

# --- Resource Protector Setup (för UserInfo endpoint) ---
require_oauth = ResourceProtector()
require_oauth.register_token_validator(MyBearerTokenValidator())

# --- Helperfunktioner för Curl ---
def get_curl_userinfo(access_token):
    userinfo_endpoint = url_for('userinfo', _external=True)
    return f'curl -H "Authorization: Bearer {access_token}" {userinfo_endpoint}'

def get_curl_refresh(refresh_token, client_id, client_secret):
    token_endpoint = url_for('issue_token', _external=True)
    auth = f"{client_id}:{client_secret}"
    # Base64 koda basic auth om secret finns
    import base64
    auth_header = f"-u {auth}" if client_secret else ""
    # Om ingen secret, skicka client_id i body
    data_payload = f"grant_type=refresh_token&refresh_token={refresh_token}"
    if not client_secret:
        data_payload += f"&client_id={client_id}"

    return f'curl -X POST {auth_header} -d "{data_payload}" {token_endpoint}'

# --- Endpoints ---
@app.route('/')
def homepage():
    return render_template('index.html', issuer=ISSUER, idp_hosts=idp_hosts)

def current_user():
    user_id = session.get('user_id')
    if user_id:
        return mock_users.get(user_id)
    return None

@app.route('/select_idp', methods=['POST'])
def select_idp():
    selected_idp_id = request.form.get('idp_host_id')
    selected_user = None
    selected_host_name = None
    selected_target_url = None # Variabel för target URL
    for host in idp_hosts:
        if host['id'] == selected_idp_id:
            selected_user = mock_users.get(host['user'])
            selected_host_name = host['name']
            selected_target_url = host['target_base_url'] # Spara target URL
            break

    if selected_user and selected_host_name and selected_target_url:
        session['user_id'] = selected_user['sub']
        session['idp_host_name'] = selected_host_name
        session['target_base_url'] = selected_target_url # Spara target URL i sessionen
        logger.info(f"IdP selected: {selected_idp_id}. User: {selected_user['sub']}. Host: {selected_host_name}. Target: {selected_target_url}")
        return redirect(url_for('consent'))
    else:
        logger.warning(f"Invalid idp_host_id received or host data incomplete: {selected_idp_id}")
        return redirect(url_for('homepage'))

@app.route('/consent')
def consent():
    user = current_user()
    idp_host_name = session.get('idp_host_name', 'Unknown IdP') # Hämta från session
    if not user:
        logger.info("No user in session, redirecting to homepage to select IdP.")
        return redirect(url_for('homepage'))

    # Hårdkoda för enkelhetens skull i mocken
    client_id = "confidential_client"
    client = query_client(client_id)
    if not client: return "Error: Default client 'confidential_client' not found.", 500

    scopes_list = ["openid", "profile", "email", "authorization_scope", "personal_identity_number", "commission"]
    scope_descriptions = {
        "openid": "Standard OIDC scope", "profile": "Read your basic profile information",
        "email": "Read your email address",
        "authorization_scope": '"authorizationScope" = Inera defined scope for "administrativt uppdrag"',
        "personal_identity_number": "Read your personal identity number", "commission": "Read your commission details"
    }
    scopes_with_desc = [(s, scope_descriptions.get(s, "No description")) for s in scopes_list]
    scopes_str = ' '.join(scopes_list)

    # Generera nonce och redirect_uri att skicka med till resultatsidan via formuläret
    nonce = 'consent_nonce_' + secrets.token_urlsafe(8)
    redirect_uri = client['redirect_uris'][0]

    # Skicka med idp_host_name till mallen
    return render_template('consent.html', user=user, client_id=client_id, client_name=client['client_name'],
                           scopes=scopes_with_desc, scopes_str=scopes_str, nonce=nonce, redirect_uri=redirect_uri,
                           idp_host_name=idp_host_name) # SKICKA MED NAMNET

# Endpoint för att exekvera flödet och omdirigera till dynamisk IdP URL
@app.route('/execute_flow', methods=['POST'])
def execute_flow():
    user = current_user()
    # Hämta sparad target base url från sessionen
    target_base_url = session.get('target_base_url')
    if not user or not target_base_url:
        logger.warning("User or target_base_url not found in session for /execute_flow")
        return redirect(url_for('homepage'))

    # Hämta parametrar från formuläret (behövs fortfarande för token-generering)
    client_id = request.form.get('client_id')
    scope = request.form.get('scope')
    nonce = request.form.get('nonce')
    redirect_uri = request.form.get('redirect_uri') # Används inte för omdirigering nu

    client = query_client(client_id)
    if not client:
        logger.error(f"Client not found in /execute_flow: {client_id}")
        return "Client not found", 400

    # --- Simulera Auth Code Flow (samma som förut) ---
    # (Vi behöver fortfarande göra detta för att ha giltiga tokens om någon
    # skulle försöka anropa t.ex. /userinfo manuellt efteråt)
    mock_auth_request = MockAuthlibRequest(
        user=user, client=client, redirect_uri=redirect_uri,
        scope=scope, response_type='code', nonce=nonce,
        data={'nonce': nonce}
    )
    code = secrets.token_urlsafe(48)
    save_authorization_code(code, mock_auth_request)
    auth_code_data = query_authorization_code(code, client)
    if not auth_code_data:
        logger.error("Failed to retrieve saved authorization code during execute_flow.")
        return "Error processing authorization code", 500

    expires_in = 3600
    token_payload = {
        'token_type': 'Bearer',
        'access_token': secrets.token_urlsafe(32),
        'refresh_token': secrets.token_urlsafe(40) if 'offline_access' in scope else None,
        'scope': scope,
        'expires_in': expires_in,
        'expires_at': int(time.time()) + expires_in,
        'client_id': client_id,
        'sub': user['sub']
    }
    try:
        id_token_str = generate_id_token(token_payload, auth_code_data, user)
        token_payload['id_token'] = id_token_str
    except Exception as e:
        logger.error(f"Failed to generate ID token during execute_flow: {e}", exc_info=True)
        # Omdirigera ändå? Eller visa fel? Vi omdirigerar för nu.
        pass # Fortsätt till omdirigering
    mock_save_token_request = MockAuthlibRequest(user=user, client=client)
    save_token(token_payload, mock_save_token_request)
    delete_authorization_code(auth_code_data)
    logger.info(f"Tokens generated and saved for user {user['sub']} before redirecting to target IdP.")
    # --- Slut på OIDC-flödessimulering ---

    # --- Bygg den slutliga mål-URL:en ---
    target_idp_path = "/idp" # Den fasta sökvägen du angav
    target_query_params = {
        'sign': 'false',
        'singleMethod': 'false',
        'id': str(uuid.uuid4()) # Generera ett unikt ID
    }
    # Säkerställ att base URL har rätt format innan vi bygger URL:en
    final_target_url_base = target_base_url.rstrip('/') + target_idp_path
    final_target_url = f"{final_target_url_base}?{urlencode(target_query_params)}"

    logger.info(f"Redirecting user to constructed target IdP URL: {final_target_url}")
    return redirect(final_target_url)

# NY Endpoint för att avsluta sessionen
@app.route('/endsession', methods=['POST'])
def end_session():
    user_id = session.pop('user_id', None) # Ta bort användaren från sessionen
    if user_id:
        logger.info(f"User session ended for user: {user_id}")
    else:
        logger.info("End session called, but no user was in session.")
    # Omdirigera till startsidan
    return redirect(url_for('homepage'))

# Token endpoint
@app.route('/token', methods=['POST'])
def issue_token():
    try:
        # Skicka med generate_id_token här
        token_response = server.create_token_response(generate_id_token=generate_id_token)
        logger.info(f"Created token response: Status={token_response.status_code}")
        return token_response
    except Exception as e:
        logger.error(f"Error creating token response: {e}", exc_info=True)
        return jsonify({"error": "invalid_request", "error_description": str(e)}), 400

# UserInfo endpoint
@app.route('/userinfo', methods=['GET', 'POST'])
@require_oauth('openid') # Kräver ett giltigt access token med minst 'openid' scope
def userinfo():
    token_info = request.oauth_token # Innehåller token data som sparades
    user_id = token_info.get('sub') # Försök hämta sub direkt från token

    if not user_id:
        logger.warning("Could not find 'sub' in validated token info for userinfo endpoint")
        # Som en fallback, försök leta upp token i lagringen igen för att hitta användaren
        # (detta bör inte vara nödvändigt om save_token lägger till 'sub')
        access_token_str = request.headers.get("Authorization", "").replace("Bearer ", "")
        for key, token_data in token_storage.items():
             if token_data.get('access_token') == access_token_str:
                 parts = key.split(':')
                 if len(parts) > 1 and parts[1] != 'None':
                     user_id = parts[1]
                     logger.info(f"Found user_id '{user_id}' via fallback lookup in userinfo")
                     break

    if not user_id:
        logger.error("Could not determine user_id for userinfo request.")
        return jsonify({"error": "invalid_token", "error_description": "Could not determine user subject."}), 401

    user = mock_users.get(user_id)
    if not user:
         logger.warning(f"User ID {user_id} from token not found in mock_users")
         return jsonify({"error": "invalid_token"}), 401

    # Skapa UserInfo dictionary baserat på scopes
    user_info_claims = {"sub": user.get("sub")}
    scopes = set(token_info.get('scope', '').split())
    if 'profile' in scopes:
        user_info_claims.update({
            'name': user.get('name'),
            'family_name': user.get('family_name'),
            'given_name': user.get('given_name'),
        })
    if 'email' in scopes:
         user_info_claims.update({
            'email': user.get('email'),
        })

    logger.info(f"Returning userinfo for user {user_id}: {user_info_claims}")
    return jsonify(user_info_claims)

# JWKS endpoint
@app.route('/jwks')
def jwks_uri():
    return jsonify(load_jwks())

# Discovery endpoint
@app.route('/.well-known/openid-configuration')
def openid_configuration():
    metadata = {
        "issuer": ISSUER,
        "authorization_endpoint": f"{BASE_URL}/authorize",
        "token_endpoint": f"{BASE_URL}/token",
        "userinfo_endpoint": f"{BASE_URL}/userinfo",
        "jwks_uri": f"{BASE_URL}/jwks",
        "scopes_supported": ["openid", "profile", "email"],
        "response_types_supported": ["code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token"],
        "response_modes_supported": ["query", "fragment"],
        "grant_types_supported": ["authorization_code", "implicit", "refresh_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
        "claims_supported": ["sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "name", "given_name", "family_name", "email"],
    }
    return jsonify(metadata)

if __name__ == '__main__':
    # Viktigt för utveckling: tillåt osäkra transporter (http)
    os.environ['AUTHLIB_INSECURE_TRANSPORT'] = '1'
    logger.info(f"Starting Authlib OIDC Mock Server on {BASE_URL}")
    # Kör med debug=True för enklare felsökning lokalt
    app.run(host='0.0.0.0', port=8000, debug=True) 