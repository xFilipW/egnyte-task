# Password Strength Service

Mikrousługa oceniająca siłę hasła, zaprojektowana z myślą o klientach z branż
regulowanych (opieka zdrowotna, administracja, finanse).
Do usługi dołączony jest lekki frontend zbudowany na **shadcn/ui**, który
demonstruje działanie API na żywo.

---

## Szybki start

```bash
npm install
npm run dev      # uruchamia API (port 4000) + frontend (Vite, port 5173) równocześnie
```

- Frontend: http://localhost:5173 (Vite proxuje `/api` na usługę)
- API: http://localhost:4000

Inne komendy:

```bash
npm test         # testy jednostkowe silnika oceny (node:test)
npm run server   # samo API (z auto-restartem)
npm run build    # build produkcyjny frontendu -> dist/
npm start        # produkcyjnie: API serwuje też zbudowany frontend z dist/
```

Zmienne środowiskowe (opcjonalne w trybie dev, wymagane na produkcji):

```bash
cp .env.example .env   # skopiuj szablon i uzupełnij wartości
```

### Docker

```bash
docker build -t password-strength .
docker run -p 4000:4000 password-strength
```

Obraz jest dwuetapowy (`multi-stage`): etap build kompiluje frontend, etap
produkcyjny zawiera wyłącznie zależności runtime i uruchamia serwer jako
nieuprzywilejowany użytkownik (`non-root`).

### CI

Każdy push i pull request do `main` uruchamia trzy równoległe joby w GitHub
Actions (`.github/workflows/ci.yml`): testy jednostkowe, lint i build frontendu.

---

## API

### `POST /api/v1/password/evaluate`

Żądanie:

```json
{
  "username": "okenobi",
  "email": "o.kenobi@jedi-council.com",
  "password": "Hello there!"
}
```

Odpowiedź (skrót):

```json
{
  "acceptable": false,
  "score": 1,
  "scorePercent": 25,
  "label": "weak",
  "guesses": 120000,
  "guessesLog10": 5.08,
  "crackTime": {
    "offlineFastHashing": { "seconds": 0.0000012, "display": "instantly" },
    "offlineSlowHashing": { "seconds": 12, "display": "12 seconds" },
    "onlineNoThrottling": { "seconds": 12000, "display": "3 hours" },
    "onlineThrottled":    { "seconds": 4320000, "display": "50 days" }
  },
  "policy": {
    "passed": false,
    "minAcceptableScore": 3,
    "checks": [ { "id": "min_length", "label": "...", "passed": true, "severity": "required" } ]
  },
  "feedback": { "warning": "This is similar to a commonly used password.", "suggestions": ["..."] },
  "meta": { "length": 12, "engine": "zxcvbn-ts", "standard": "NIST SP 800-63B", "evaluatedAt": "..." }
}
```

Pomocnicze endpointy: `GET /api/health`, `GET /api/v1/password/policy`.

---

## Dlaczego tak? — decyzje projektowe

Ocena siły hasła jest celowo oparta na tym, **jak realnie zgaduje atakujący**,
a nie na liczeniu klas znaków.

1. **Długość ponad wymuszaną złożoność (NIST SP 800-63B).** Nowoczesne wytyczne
   (NIST 800-63B) *odradzają* reguły typu „musi zawierać symbol i cyfrę”, bo
   prowadzą do przewidywalnych haseł (`Password1!`). Zamiast tego premiujemy
   długość i losowość, a słabość wykrywamy analizą, nie regułami składni.

2. **Silnik `zxcvbn-ts`.** Zamiast naiwnej entropii używamy estymatora `zxcvbn`
   (fork utrzymywany w TS), który modeluje realne ataki: słowniki, hasła z
   wycieków, układy klawiatury (`qwerty`), sekwencje (`abcd`, `1234`),
   powtórzenia, daty i podmiany l33t (`P@ssw0rd`). Zwraca liczbę prób do
   złamania oraz czas w różnych scenariuszach.

3. **Kontekst użytkownika.** `username` i `email` (oraz ich fragmenty, np.
   `kenobi`, `jedi-council`) trafiają do silnika jako „user inputs”, więc hasło
   zbudowane z danych osobowych jest surowo karane. Dodatkowo twarda reguła
   `no_personal_info` blokuje hasła zawierające te wartości.

4. **Odpowiedź zorientowana na atakującego.** Zwracamy czas złamania w czterech
   scenariuszach — od „online z throttlingiem” (formularz logowania) po
   „offline, szybki hash” (wyciek bazy z MD5/SHA-1). To realistycznie pokazuje
   ryzyko, bo bezpieczeństwo hasła zależy od tego, jak jest przechowywane.

5. **Brama polityki (hard gate) niezależna od wyniku.** Oprócz wyniku 0–4
   sprawdzamy twarde wymagania: min. 8 znaków (rekomendacja 12+), akceptacja do
   128 znaków (nie obcinamy długich haseł/passphrase), brak danych osobowych,
   brak trafienia w hasła pospolite/z wycieków oraz próg odporności
   `score >= 3`. `acceptable = true` tylko gdy wszystkie wymagane reguły
   przechodzą. Próg jest jednym miejscem (`POLICY` w `server/evaluator.js`),
   więc łatwo go zaostrzyć np. do `score >= 4` dla środowisk wysokiego ryzyka.

### Przypadki brzegowe

- **Puste / brak hasła** → `400 invalid_request`.
- **Ekstremalnie długie wejście** (> 4096 znaków) → `413`, zanim trafi do
  estymatora (ochrona przed DoS). W zakresie polityki dopuszczamy do 128 znaków.
- **Hasło = nazwa użytkownika / e-mail** → reguła `no_personal_info` nie
  przechodzi, wynik jest zaniżony.
- **Unicode / spacje / emoji** — obsługiwane; długość liczona jest po znakach,
  passphrase ze spacjami są w pełni wspierane.

---

## Bezpieczeństwo usługi

- **Hasło nie jest nigdy logowane ani przechowywane.** Ocena to funkcja czysta;
  surowe hasło nie pojawia się w odpowiedzi (jest to pokryte testem).
- **Helmet** — bezpieczne nagłówki HTTP, wyłączony `x-powered-by`.
- **Limit rozmiaru ciała** (`10kb`) — ochrona przed wyczerpaniem pamięci.
- **Rate limiting** (60 żądań / min / IP) — endpoint jest z założenia publiczny
  („wyrocznia siły”), więc ograniczamy nadużycia.
- **CORS** konfigurowalny przez `CORS_ORIGIN`.

---

## Architektura

```
server/
  evaluator.js         # czysta logika oceny (NIST + zxcvbn-ts) — testowalna
  evaluator.test.js    # testy jednostkowe (node:test)
  index.js             # Express: routing, walidacja, helmet, rate limit, CORS
src/
  components/ui/       # komponenty shadcn/ui (Button, Card, Input, Alert, ...)
  lib/                 # cn(), klient API, mapowanie prezentacji
  App.jsx              # UI: formularz + wynik na żywo (debounce)
.github/workflows/
  ci.yml               # GitHub Actions: testy + lint + build przy każdym push/PR
Dockerfile             # multi-stage build, non-root user, obraz produkcyjny
.env.example           # szablon zmiennych środowiskowych (PORT, CORS_ORIGIN)
```

**Frontend (shadcn/ui):** Tailwind v4 (`@tailwindcss/vite`) + komponenty
shadcn/ui w wariancie *new-york*. Alias `@` → `src`, motyw i zmienne CSS w
`src/index.css`, konfiguracja w `components.json`.

**Rozdzielenie warstw:** logika oceny nie zna HTTP, a warstwa HTTP nie zna
detali oceny — dzięki temu silnik jest łatwy do testowania i ponownego użycia
(np. jako biblioteka lub w innym transportcie).
