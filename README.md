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
    *   **Nödvändiga Behörigheter:** Information om den specifika behörigheten `authorization_scope` som krävs.
5.  **Auktorisera och Omdirigera:** Justera IdP-konfigurationen om du vill och klicka sedan på "Authorise & Continue to IdP"-knappen. Detta kommer att:
    *   Simulera ett komplett OIDC-flöde internt (generera tokens etc., men de visas inte direkt). Data från detta flöde sparas i sessionen för felsökning.
    *   Bygga den slutliga URL:en baserat på den **Base URL** som hör till den valda IdP:n och de **konfigurationsvärden** du angett (eller lämnat som standard) på samtyckessidan.
    *   Omdirigera din webbläsare till den dynamiskt byggda URL:en.

### Felsökning av Flöde (Debug)

På startsidan finns en länk "View All Logs (JSON)" och en knapp "Clear All Logs".

*   **View All Logs (JSON):** Öppnar en ny flik som visar all felsökningsdata som sparats i din session från tidigare körda flöden. Datan är strukturerad per IdP-profil och innehåller indata, simuleringssteg, eventuella fel och den slutliga omdirigerings-URL:en för varje körning.
*   **Clear All Logs:** Tar bort all sparad felsökningsdata från din session.

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

Servern exponerar fortfarande följande standard OIDC-endpoints (används internt och kan anropas manuellt):

*   `/.well-known/openid-configuration`: Discovery-dokument.
*   `/jwks`: Serverns publika nycklar.
*   `/authorize`: Omdirigerar nu till startsidan.
*   `/token`: Tokenendpoint (används internt).
*   `/userinfo`: UserInfo-endpoint.
*   `/debug_json`: Endpoint som returnerar all sparad debug-data som JSON.

## Driftmanual

### Förutsättningar

*   Git
*   Docker
*   Docker Compose

### Hämta och Starta Servern

1.  **Hämta koden:**
    *   **Om du inte har koden sedan tidigare (första gången):** Klona repot. Ersätt `<repository-url>` med den faktiska URL:en till ditt Git-repository.
        ```bash
        git clone <repository-url>
        cd <repository-directory> # Gå in i den nya mappen
        ```
    *   **Om du redan har koden och vill uppdatera:** Navigera till projektets rotmapp i terminalen och hämta de senaste ändringarna.
        ```bash
        git pull
        ```

2.  **Bygg och starta Docker-containern:**
    Kör följande kommando i projektets rotmapp (där `docker-compose.yml` finns):
    ```bash
    docker-compose up --build -d
    ```
    *   `--build`: Viktigt för att bygga om Docker-imagen om koden (t.ex. `app.py` eller `Dockerfile`) har ändrats, vilket ofta sker efter `git pull`.
    *   `-d`: Kör containern i bakgrunden (detached mode).

Servern är nu tillgänglig på [http://localhost:8000](http://localhost:8000).

### Stoppa Servern

För att stoppa containern, kör följande kommando i projektets rotmapp:

```bash
docker-compose down
```

### Konfiguration

#### Miljövariabler (`docker-compose.yml`)

Grundläggande konfiguration för *mock-servern själv*:

*   `BASE_URL`: Mock-serverns bas-URL (t.ex. `http://localhost:8000`).
*   `ISSUER`: OIDC Issuer Identifier (standard: `BASE_URL`).
*   `FLASK_SECRET_KEY`: Hemlig nyckel för Flask-sessioner (standard: "dev-secret-key").

#### IdP-profiler (`app/app.py`)

Konfiguration av de simulerade IdP:erna och deras omdirigeringsbeteende görs i `idp_hosts`-listan i `app/app.py`.

### Nyckelhantering

Servern använder ett RSA-nyckelpar (`app/private.pem`) för att signera ID Tokens internt. Genereras automatiskt. Radera filen och starta om för att skapa en ny.

### CSS Styling

All CSS finns i `app/static/style.css`.

### Felsökning (Server)

*   **Visa loggar:** `docker-compose logs -f`
*   **Bygga om utan cache:** `docker-compose build --no-cache`

### Projektstruktur

Här är en översikt över projektets filstruktur:

```ascii
.
├── app/
│   ├── static/
│   │   └── style.css         # All CSS för webbgränssnittet
│   ├── templates/
│   │   ├── index.html        # Startsida (IdP-val & Debug-åtkomst)
│   │   └── consent.html      # Samtyckessida med IdP-konfiguration
│   ├── app.py                # Flask-applikation, OIDC-logik, IdP-konfig, Debug-endpoints
│   └── private.pem           # (Auto-genererad) Privat RSA-nyckel för ID Token signering
├── .gitignore                # Specifierar filer som Git ska ignorera (bör inkludera *.pem)
├── docker-compose.yml        # Docker Compose konfiguration (portar, miljövariabler)
├── Dockerfile                # Instruktioner för att bygga Docker-imagen
└── README.md                 # Denna informationsfil
```

Filer finns redan i konversationen.