# brennocm.github.io

Source of [brennocm.github.io](https://brennocm.github.io): articles, certification reviews, projects and a few browser tools on information security. Every page exists in Portuguese and English.

The site is static HTML, CSS and JavaScript with no build step and no framework, published by GitHub Pages from the `main` branch.

## Contents

| Path | What it is |
| --- | --- |
| `index.html`, `index-en.html` | Home page with the article list |
| `articles/pt-br/`, `articles/en-us/` | 17 articles: write-ups, certification reviews (eJPT, CAP, CBP, CNSP, Security+, CCSP-AWS) and project deep dives |
| `projects.html`, `projects-en.html` | Projects, each with a summary, screenshot and links |
| `about-me.html`, `about-me-en.html` | About and résumé |
| `tools/` | Browser tools that process everything locally |
| `assets/`, `img/` | Styles, scripts and images |

### Tools

| Tool | What it does |
| --- | --- |
| BaseMetric | CVSS v3.1 score calculator |
| IntelQuery | Builds advanced Google dorks for OSINT |
| JWT Sentinel | Decodes and analyzes JWTs without sending them anywhere |
| PicInfo | Reads image metadata (EXIF) in the browser |
| SafeCheck | Estimates password strength and entropy in the browser |

## Run locally

```bash
git clone https://github.com/brennocm/brennocm.github.io.git
cd brennocm.github.io
python3 -m http.server 8000
```

Then open `http://localhost:8000`.

## License

No license is granted: the articles and images are © brennocm. Ask before republishing them.
