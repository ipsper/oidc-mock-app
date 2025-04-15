# Authlib OIDC Mock Server

Detta är en OpenID Connect (OIDC) mock-server byggd med Python, Flask och Authlib. Den är avsedd för utvecklings- och testsyften för att simulera en OIDC Identity Provider (IdP). Servern körs i en Docker-container.

## Användarmanual

### Syfte

Mock-servern låter dig simulera OIDC-autentiseringsflöden utan att behöva koppla upp dig mot en riktig IdP. Detta är användbart när du utvecklar eller testar klientapplikationer (Relying Parties) som använder OIDC.

### Flöde

Det huvudsakliga sättet att interagera med mock-servern är via dess webbgränssnitt:

1.  **Starta Servern:** Se "Driftmanual" nedan.
2.  **Öppna i webbläsare:** Gå till [http://localhost:8000](http://localhost:8000).
3.  **Välj IdP-profil:** På startsidan väljer du vilken simulerad identitetsleverantör (och därmed vilken testanvändare) du vill använda från dropdown-menyn. Klicka på "Continue with Selected IdP".
4.  **Samtyckessida:** Du omdirigeras till en sida som visar vilken användare du är "inloggad" som och vilka scopes (behörigheter) en exempelklient begär.
5.  **Auktorisera:** Klicka på "Authorise & View Results"-knappen. Detta simulerar att du godkänner begäran.
6.  **Resultatsida:** Servern genomför ett internt Authorization Code Flow och visar sedan resultatet, inklusive:
    *   Access Token
    *   Refresh Token (om tillgängligt)
    *   ID Token (avkodade claims)
    *   Exempel på `curl`-kommandon för att använda tokens (t.ex. mot UserInfo-endpointen).
7.  **Avsluta Session:** Från resultatsidan kan du klicka på "End Mock Session (Logout)" för att rensa den simulerade inloggningen eller "Start Over" för att gå tillbaka till IdP-valet.

### Direkt Testflöden

På startsidan finns även länkar ("Direct Test Flow Links") som startar ett OIDC-flöde direkt mot `/authorize`-endpointen med förkonfigurerade klienter och scopes. Dessa flöden använder den användare som senast valts och loggades in via IdP-valet. Om ingen användare valts används standardanvändaren.

### Tillgängliga Testanvändare/IdP-profiler

*   **IdP Alpha:** Använder `testuser` (Test Användare Alpha)
*   **IdP Beta:** Använder `betauser` (Beta Test Användare)
*   **IdP Gamma:** Använder `gammauser` (Gamma Test Användare)

(Alla användare har lösenordet `password` för den simulerade inloggningen, men detta används bara internt om man skulle bygga ut med en riktig inloggningssida).

### Standard OIDC Endpoints

Servern exponerar följande standard-endpoints:

*   `/.well-known/openid-configuration`: Discovery-dokument med serverns metadata.
*   `/jwks`: Serverns publika nycklar (JSON Web Key Set) för att validera ID Tokens.
*   `/authorize`: Auktoriseringsendpoint (startar flödet).
*   `/token`: Tokenendpoint (för att byta kod mot tokens, använda refresh token).
*   `/userinfo`: UserInfo-endpoint (för att hämta användarinformation med access token).

## Driftmanual

### Förutsättningar

*   Docker
*   Docker Compose

### Starta Servern

1.  Klona repot (om du inte redan gjort det).
2.  Navigera till projektets rotmapp i terminalen.
3.  Kör följande kommando:
    ```bash
    docker-compose up --build -d
    ```
    *   `--build`: Bygger Docker-imagen om den inte finns eller om koden ändrats.
    *   `-d`: Kör containern i bakgrunden (detached mode).

Servern är nu tillgänglig på [http://localhost:8000](http://localhost:8000).

### Stoppa Servern

För att stoppa containern, kör följande kommando i projektets rotmapp:

```bash
docker-compose down
```

### Konfiguration

Viss konfiguration kan justeras via miljövariabler i `docker-compose.yml`:

*   `BASE_URL`: Bas-URL:en för servern (t.ex. `http://localhost:8000`). Används för att bygga endpoint-URL:er.
*   `ISSUER`: OIDC Issuer Identifier. Standard är samma som `BASE_URL`.
*   `FLASK_SECRET_KEY`: En hemlig nyckel som används av Flask för sessionshantering. Standard är "dev-secret-key", **ändra detta om servern skulle exponeras externt (vilket inte rekommenderas för denna mock)**.

### Nyckelhantering

Servern använder ett RSA-nyckelpar för att signera ID Tokens.
*   Den privata nyckeln genereras automatiskt första gången servern startar (om den inte redan finns) och sparas i `app/private.pem`.
*   **Dela inte denna privata nyckel.** Om du behöver generera en ny, radera helt enkelt `app/private.pem` och starta om servern med `docker-compose up --build`.
*   Den publika nyckeln exponeras via `/jwks`-endpointen.

### Felsökning

*   **Visa loggar:** För att se loggutskrifter från servern (inklusive felmeddelanden), kör:
    ```bash
    docker-compose logs -f
    ```
    Tryck `Ctrl+C` för att sluta följa loggarna.
*   **Bygga om utan cache:** Om du misstänker problem med Docker-cachen vid bygge, använd:
    ```bash
    docker-compose build --no-cache
    ```

### Projektstruktur
