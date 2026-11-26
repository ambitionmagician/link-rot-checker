# Link Rot Checker

Save the script as `link_rot_checker.py`. Requires Python 3.8 or newer; no packages to install.

    python link_rot_checker.py --help
    python link_rot_checker.py README.md references.txt --out audit.md
    python link_rot_checker.py bibliography.txt --workers 4 --timeout 15 --user-agent "BibliographyAudit/1.0" --out audit.json

The checker reads UTF-8 files, checks each distinct HTTP(S) URL spelling once, and prints counts. Reports include every occurrence's file and one-based line number, the HTTP status if available, and the final URL. Output files are replaced, not appended to.

- **ok:** the request succeeded at the original address.
- **redirect:** the request succeeded at a different address.
- **client-error / server-error:** the final HTTP response was 4xx / 5xx.
- **unreachable:** no usable response, including DNS, TLS, malformed URL, or redirect failures.

Exit status: **0** for no dead links (including empty inputs), **1** for any dead link, **2** for usage, input, or report errors.

## Behavior and limits

- Uses HEAD first and falls back to GET for HTTP errors or transient connection failures. It does not read successful GET response bodies. Transient failures get at most one retry per URL. A transient HEAD retry doubles as the GET fallback. A valid `Retry-After` longer than ten seconds suppresses the retry instead of retrying early.
- The timeout applies to individual socket operations, not the entire run. DNS, redirects, and retries may take longer. Concurrency is global, not per host; use `--workers 1` for a small site's bibliography. This is not a `robots.txt` crawler.
- The scanner recognizes bare URLs, common inline Markdown destinations, and angle-bracket URLs. It balances delimiters and trims common trailing prose punctuation from bare URLs. For a literal trailing punctuation mark, enclose the URL in angle brackets. This is not a full Markdown parser: it scans code and comments too, and does not decode Markdown escapes, join wrapped URLs, or resolve relative links.
- An HTTP success does not prove a page still contains the intended material. Fragments are not checked, and login walls, bot filters, and soft 404 pages can affect results.
- Check only trusted files: URLs and redirects can reach local or private services. Embedded URL login information is rejected. URLs, including query strings, appear in reports; do not supply secret-bearing links.
