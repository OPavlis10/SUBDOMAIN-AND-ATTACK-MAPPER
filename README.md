# Subdomain & Attack Surface Mapper

Nástroj pro pasivní mapování útočné plochy domény. Zadáte doménu, nástroj z veřejných zdrojů objeví její subdomény, obohatí je o technická metadata, ohodnotí rizikovost podle názvu a vykreslí výsledek jako interaktivní síťový graf v samostatném HTML souboru.

---

## Etické a právní upozornění

Nástroj používá výhradně pasivní zdroje (veřejné certificate transparency logy, veřejné DNS resolvery, Wayback Machine) a standardní DNS/HTTP dotazy. Neprovádí exploitaci, skenování zranitelností, brute force přihlašovacích údajů ani jakoukoli jinou aktivitu, která by cílový systém narušovala.

Přesto platí: **nástroj používejte pouze na domény, které vlastníte, nebo ke kterým máte písemné svolení k testování** (bug bounty scope, podepsaná pentest smlouva, interní audit vlastní infrastruktury). V řadě jurisdikcí je i pouhý neautorizovaný průzkum cizí infrastruktury právně problematický. Odpovědnost za použití nese uživatel.

Výstupy skenů (`results.json`, `report.html`) obsahují data o infrastruktuře třetích stran a nepatří do veřejných repozitářů. Jsou proto v `.gitignore`.

Ukázkový výstup v [`subdomain-mapper/sample/`](subdomain-mapper/sample/) je ručně sestavený pro rezervovanou doménu `example.com` s dokumentačními IP adresami (RFC 5737); nepochází z žádného skutečného skenu. Vykreslený report: [sample/report.html](https://opavlis10.github.io/SUBDOMAIN-AND-ATTACK-MAPPER/subdomain-mapper/sample/report.html).

---

## Co nástroj dělá

Pipeline má čtyři kroky.

**Krok 1 — sběr subdomén.** Tři nezávislé zdroje běží paralelně. Certificate transparency logy přes crt.sh jsou nejbohatší pasivní zdroj, protože každý vydaný TLS certifikát se v nich objeví. DNS brute force zkouší resolvovat prefixy z wordlisty (363 položek seřazených podle reálné úspěšnosti) a odhalí hosty, které nikdy nedostaly certifikát. Wayback Machine CDX API vrací historické URL a často odhalí hosty, které dnes už nikde jinde vidět nejsou. Výsledky se sloučí a deduplikují, u každého hosta se pamatuje, ze kterých zdrojů pochází.

**Krok 2 — obohacení.** Ke každému nálezu se doplní IP adresy, HTTP status kód, `<title>` stránky, `Server` hlavička a případný redirect. Requesty jdou paralelně s krátkým timeoutem. Hosti, kteří neresolvují, se HTTP dotazem neobtěžují. Nakonec se dopočítá, které subdomény sdílí IP adresu — to je nejsilnější dostupný signál sdílené infrastruktury.

**Krok 3 — klasifikace rizika.** Keyword-based heuristika nad názvem hosta. Vysoké riziko znamená interní nebo privilegovanou plochu (`admin`, `vpn`, `internal`, `staging`, `jenkins`, `git`, `portal`, `backup`, `grafana`, `vault`…), střední riziko neprodukční prostředí (`dev`, `test`, `qa`, `beta`, `sandbox`, `api`…), nízké riziko běžný veřejný provoz. Matchuje se na hranicích labelů, takže `api.example.com` sedí na „api", ale `rapid.example.com` ne. Vyhrává nejvyšší závažnost — `dev-admin` je vysoké riziko, ne střední.

**Krok 4 — vizualizace.** Force-directed graf v D3.js. Centrální node je cílová doména, subdomény kolem ní jako satelity. Barva podle rizika, velikost podle toho, kolik toho host odhaluje (živý, odpovídá na HTTP, sdílí IP). Přerušované hrany spojují hosty na stejné IP. Klik na node otevře detail panel, hover zvýrazní sousedství a ztlumí zbytek grafu.

---

## Instalace

```bash
git clone https://github.com/<vas-ucet>/subdomain-mapper.git
cd subdomain-mapper
python -m venv .venv && source .venv/bin/activate   # na Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Pro samotné CLI stačí `requests`, `dnspython` a `urllib3`. `streamlit` a `pandas` jsou potřeba jen pro webové UI.

---

## Použití

### CLI

```bash
python -m scanner.main example.com
```

Vygeneruje `results.json` a `report.html` v aktuálním adresáři.

Rychlý sken bez Wayback Machine, jen prvních 100 prefixů:

```bash
python -m scanner.main example.com --wordlist-size 100 --no-wayback
```

Pomalá síť, delší timeouty, méně paralelismu:

```bash
python -m scanner.main example.com --timeout 6 --dns-timeout 5 --workers 15
```

Vlastní cesty a vynechání HTML reportu:

```bash
python -m scanner.main example.com -o out/data.json -r none
```

| Přepínač | Výchozí | Význam |
|---|---|---|
| `-o, --output` | `results.json` | cesta k JSON výstupu |
| `-r, --report` | `report.html` | cesta k HTML reportu, `none` přeskočí |
| `-w, --wordlist-size` | vše (363) | použít jen prvních N prefixů wordlisty |
| `-t, --timeout` | `3.0` | HTTP timeout v sekundách |
| `--dns-timeout` | `3.0` | DNS timeout v sekundách |
| `-c, --workers` | `40` | počet paralelních workerů |
| `--no-wayback` | vypnuto | přeskočit Wayback Machine |
| `-q, --quiet` | vypnuto | jen chyby |

### Webové UI

```bash
streamlit run app.py
```

Zadání domény do pole, posuvníky pro parametry, progress bar během skenu, výsledek ve třech záložkách (graf, filtrovatelná tabulka, surový JSON) a tlačítka pro stažení obou výstupů.

### Přegenerování reportu z existujícího JSONu

```bash
python -m viz.build_report results.json -o report.html
```

Užitečné, když upravíte `viz/template.html` a nechcete kvůli tomu skenovat znovu.

---

## Ovládání reportu

Report je jeden samostatný HTML soubor. Data jsou v něm vložená jako JSON, jediná externí závislost je D3.js z CDN. Funguje z disku i na GitHub Pages, žádný backend není potřeba.

Klik na node otevře detail panel s IP adresami, HTTP statusem, titlem, server hlavičkou, zdrojem nálezu a seznamem hostů na stejné IP (na které se dá proklikat). Tah myší přesune node, kolečko zoomuje, `Esc` zavře detail.

Vyhledávací pole hledá napříč hostname, IP, titlem, server hlavičkou i status kódem. Chipy filtrují podle rizika a podle zdroje nálezu. Přepínače skryjí neresolvující hosty, popisky nodů nebo hrany sdílených IP.

---

## Struktura repozitáře

```
scanner/
  crtsh.py         # sběr z certificate transparency logů
  dns_brute.py     # paralelní DNS brute force, detekce wildcardu
  wayback.py       # Wayback Machine CDX dotaz
  enrich.py        # HTTP/IP obohacení, linkování sdílených IP
  classify.py      # keyword-based klasifikace rizika
  main.py          # orchestrace pipeline, CLI, výstup do JSON
wordlists/
  subdomains.txt   # 363 prefixů seřazených podle úspěšnosti
viz/
  template.html    # D3 graf, data se vkládají místo __DATA__
  build_report.py  # spojí JSON + template do finálního report.html
app.py             # Streamlit UI
requirements.txt
```

---

## Formát výstupu

```json
{
  "target": "example.com",
  "scanned_at": "2026-08-07T09:14:22+00:00",
  "duration_seconds": 41.3,
  "summary": {
    "total": 87,
    "alive": 62,
    "http_ok": 54,
    "by_risk": { "high": 6, "medium": 14, "low": 67 },
    "by_source": { "crt.sh": 71, "dns-brute": 23, "wayback": 38 },
    "unique_ips": 19
  },
  "results": [
    {
      "hostname": "staging.example.com",
      "ips": ["203.0.113.42"],
      "alive": true,
      "status": 200,
      "scheme": "https",
      "title": "Staging — Example",
      "server": "nginx",
      "redirect": null,
      "shared_with": ["dev.example.com"],
      "sources": ["crt.sh", "dns-brute"],
      "risk": "high",
      "risk_keywords": ["staging"]
    }
  ]
}
```

---

## Poznámky k chování

crt.sh bývá pomalý a rate-limitovaný. Modul má tři pokusy s exponenciálním backoffem a při neúspěchu vrací prázdný set místo aby shodil celý běh — ostatní dva zdroje pak výsledek dodají samy.

Zóny s wildcard DNS záznamem (`*.example.com`) by při brute force vrátily tisíce falešných pozitiv. Před samotným brute force se proto zkusí resolvovat dva nesmyslné labely a vše, co se trefí do stejných IP, se zahodí.

HTTP probe ignoruje chyby TLS certifikátu. Recon cíle mají běžně expirované nebo self-signed certifikáty a jejich přeskočení by znamenalo ztrátu právě těch nejzajímavějších nálezů.

Klasifikace rizika je heuristika nad názvem, ne posouzení skutečné zranitelnosti. `admin.example.com` může být dokonale zabezpečený a `www.example.com` děravý. Slouží k prioritizaci ruční kontroly, ne jako výsledek auditu.

---

## Licence

MIT
