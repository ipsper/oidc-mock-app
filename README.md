# Authlib OIDC Mock Server

Detta är en OpenID Connect (OIDC) mock-server byggd med Python, Flask och Authlib. Den är avsedd för utvecklings- och testsyften för att simulera en OIDC Identity Provider (IdP) och dess omdirigeringsbeteende efter autentisering. Servern körs i en Docker-container.

## Användarmanual

### Syfte

Mock-servern låter dig simulera OIDC-autentiseringsflöden utan att behöva koppla upp dig mot en riktig IdP. Detta är användbart när du utvecklar eller testar klientapplikationer (Relying Parties) som använder OIDC, eller när du vill testa hur en omdirigering till en specifik IdP-URL beter sig efter ett simulerat OIDC-flöde.

### Flöde

Det huvudsakliga sättet att interagera med mock-servern är via dess webbgränssnitt:

1.  **Starta Servern:** Se "Driftmanual" nedan.
2.  **Öppna i webbläsare:** Gå till [http://localhost:8000](http://localhost:8000).
3.  **Välj IdP-profil:** På startsidan väljer du vilken simulerad identitetsleverantör du vill använda från dropdown-menyn. Alternativen visar nu IdP:ns namn och dess konfigurerade mål-URL (t.ex. `IdP Alpha - https://idp.alpha.example.org`). Klicka på "Continue with Selected IdP". Valet avgör vilken testanvändare som används internt och vilken standardkonfiguration för omdirigering som laddas.
4.  **Samtyckessida:** Du omdirigeras till en sida som visar:
    *   Vilken användare du är "inloggad" som (baserat på ditt IdP-val).
    *   Vilken IdP du valt (visas i rubriken).
    *   **IdP-konfiguration:** Ett avsnitt där du kan se och *ändra* parametrarna för den slutliga omdirigeringen till IdP:n:
        *   **Base URL:** Den grundläggande URL:en för den valda IdP:n (ej redigerbar här, konfigureras i `app.py`).
        *   **IdP Path:** Sökvägen som läggs till efter Base URL (t.ex. `/idp`).
        *   **Sign Parameter:** Värdet för `sign`-parametern (true/false).
        *   **Single Method Parameter:** Värdet för `singleMethod`-parametern (true/false).
        *   **Generate new UUID:** Om en ny unik identifierare (`id`-parameter) ska genereras för varje omdirigering. Om avbockad kan du ange ett statiskt UUID.
    *   **Requested Permissions:** Vilka scopes (behörigheter) en exempelklient begär (dessa är hårdkodade i mock-servern för demonstration).
5.  **Auktorisera och Omdirigera:** Justera IdP-konfigurationen om du vill och klicka sedan på "Authorise & Continue to IdP"-knappen. Detta kommer att:
    *   Simulera ett komplett OIDC-flöde internt (generera tokens etc., men de visas inte direkt).
    *   Bygga den slutliga URL:en baserat på den **Base URL** som hör till den valda IdP:n och de **konfigurationsvärden** du angett (eller lämnat som standard) på samtyckessidan.
    *   Omdirigera din webbläsare till den dynamiskt byggda URL:en.
    *   *Exempel:* Om du valde "IdP Alpha" och behöll standardvärdena, kan URL:en bli:
        ```
        https://idp.alpha.example.org/idp?sign=false&singleMethod=false&id=<genererat-uuid>
        ```
    *   *Exempel:* Om du ändrade Path till `/login` och satte Sign till `true`, kan URL:en bli:
        ```
        https://idp.alpha.example.org/login?sign=true&singleMethod=false&id=<genererat-uuid>
        ```

### Tillgängliga IdP-profiler och Standardkonfiguration

IdP-profilerna och deras standardkonfiguration för omdirigering definieras i listan `idp_hosts` i `app/app.py`. Varje profil innehåller:

*   `id`: En intern identifierare.
*   `name`: Namnet som visas i dropdown (initialt).
*   `user`: Vilken `mock_users`-nyckel som ska användas för den interna simuleringen.
*   `target_base_url`: Den grundläggande URL:en för omdirigeringen.
*   `idp_config`: En dictionary med standardvärden för omdirigeringen:
    *   `path`: Standard-sökvägen (t.ex. `/idp`).
    *   `params`: En dictionary med standard query-parametrar (t.ex. `sign`, `singleMethod`, `generate_uuid`).

Du kan enkelt lägga till eller ändra dessa profiler i `app.py` för att testa olika scenarier.

### Standard OIDC Endpoints

Även om huvudsyftet nu är att testa omdirigeringen, exponerar servern fortfarande följande standard OIDC-endpoints (används internt under flödessimuleringen och kan anropas manuellt för felsökning):

*   `/.well-known/openid-configuration`: Discovery-dokument med serverns metadata.
*   `/jwks`: Serverns publika nycklar (JSON Web Key Set).
*   `/authorize`: Omdirigerar nu till startsidan (används inte direkt).
*   `/token`: Tokenendpoint (för att byta kod mot tokens internt).
*   `/userinfo`: UserInfo-endpoint (för att hämta användarinformation med ett giltigt access token).

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

#### Miljövariabler (`docker-compose.yml`)

Viss grundläggande konfiguration kan justeras via miljövariabler i `docker-compose.yml`:

*   `BASE_URL`: Bas-URL:en för *mock-servern själv* (t.ex. `http://localhost:8000`). Används för att bygga mock-serverns egna endpoint-URL:er.
*   `ISSUER`: OIDC Issuer Identifier. Standard är samma som `BASE_URL`.
*   `FLASK_SECRET_KEY`: En hemlig nyckel som används av Flask för sessionshantering. Standard är "dev-secret-key".

#### IdP-profiler (`app/app.py`)

Som nämnts ovan konfigureras de olika IdP-profilerna, deras testanvändare och standardvärden för omdirigerings-URL:en direkt i `idp_hosts`-listan i `app/app.py`.

### Nyckelhantering

Servern använder ett RSA-nyckelpar för att signera ID Tokens (som genereras internt).
*   Den privata nyckeln (`app/private.pem`) genereras automatiskt första gången servern startar om den inte finns.
*   **Dela inte denna privata nyckel.** Radera filen och starta om servern för att generera en ny.
*   Den publika nyckeln exponeras via `/jwks`-endpointen.

### CSS Styling

All CSS för webbgränssnittet (startsida, samtyckessida) finns samlad i en enda fil: `app/static/style.css`. Detta gjordes för enkelhetens skull i detta projekt.

### Felsökning

*   **Visa loggar:**
    ```bash
    docker-compose logs -f
    ```
*   **Bygga om utan cache:**
    ```bash
    docker-compose build --no-cache
    ```

### Projektstruktur

### file struktur 
├── app/
│ ├── static/
│ │ └── style.css # All CSS
│ ├── templates/
│ │ ├── index.html # Startsida (IdP-val)
│ │ └── consent.html # Samtyckessida med konfiguration
│ ├── app.py # Flask-applikation, OIDC-logik, IdP-konfig
│ └── private.pem # Autogenererad privat nyckel (Ignoreras av Git)
├── .gitignore # Specifierar vilka filer Git ska ignorera
├── docker-compose.yml # Docker Compose konfiguration
├── Dockerfile # Docker build instruktioner
└── README.md # Denna fil