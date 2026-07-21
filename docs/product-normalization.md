# Threat Product Normalization

## Purpose

The Product Normalizer resolves a vendor/product name supplied by threat
intelligence into one active `CatalogProduct`. It reads normalized product
names and `ProductAlias` records and returns a deterministic result. It does
not update Threats, Assets, catalog records, aliases, or collector data.

This sprint performs product normalization only. It does not perform
threat-to-asset matching.

## Public API

`ProductNormalizer.normalize(vendor_name, product_name)` returns a dictionary:

```python
{
    "matched": True,
    "catalog_product_id": 1,
    "vendor_name": "Fortinet",
    "product_name": "FortiGate",
    "match_type": "Vendor + Exact Alias",
    "matched_alias": "FortiOS",
    "confidence": 100,
}
```

On a successful match, vendor and product names are the canonical catalog
values. On failure, they are the trimmed inputs, identifier and alias are
`None`, match type is `None`, and confidence is `0`.

Only active aliases belonging to active catalog products are eligible.

## Algorithm

The service first trims surrounding whitespace. A blank product cannot match.
It then runs two bounded, read-only candidate queries:

1. active aliases whose lower-cased Alias equals the lower-cased input product;
2. active catalog products whose lower-cased ProductName equals the lower-cased
   input product.

Exact casing is evaluated in Python before case-insensitive fallback. This keeps
the matching stages stable even when SQL Server uses a case-insensitive
collation.

Candidates are evaluated in this order:

1. Vendor + Exact Alias
2. Exact Alias only
3. Vendor + ProductName
4. Exact ProductName
5. Case-insensitive comparison:
   - Vendor + Alias
   - Alias only
   - Vendor + ProductName
   - ProductName only

No fuzzy matching, AI, regular expressions, CPE parsing, or punctuation
rewriting is used.

A stage succeeds only when its candidates resolve to exactly one distinct
CatalogProduct. Ambiguous candidates are not selected arbitrarily. Evaluation
continues through the remaining stages; the final result is unmatched if no
stage produces one unique product.

## Confidence

| Match type | Confidence |
| --- | ---: |
| Vendor + Exact Alias | 100 |
| Exact Alias | 95 |
| Vendor + ProductName | 100 |
| Exact ProductName | 95 |
| Case-insensitive Vendor + Alias | 90 |
| Case-insensitive Alias | 85 |
| Case-insensitive Vendor + ProductName | 90 |
| Case-insensitive ProductName | 85 |
| Unmatched | 0 |

Confidence is a fixed indicator of rule specificity, not a statistical
probability.

## CLI usage

Vendor is optional so alias-only normalization can be tested. Product is
required.

Windows PowerShell:

```powershell
flask normalize-product --vendor Fortinet --product FortiOS
```

Bash:

```bash
flask normalize-product \
    --vendor Fortinet \
    --product FortiOS
```

Expected output:

```text
Matched : Yes
Catalog Product : FortiGate
Alias : FortiOS
Confidence : 100
```

An unmatched request returns `Matched : No`, `None` for Catalog Product and
Alias, and confidence `0`.

## Manual test steps

1. Apply the Sprint 7B catalog DDL manually if it has not already been applied.
   Sprint 7C itself has no database changes.
2. In Product Catalog, create:
   - Vendor: Fortinet
   - Product: FortiGate
   - Active: checked
3. Add an active `FortiOS` alias.
4. Run:

   ```powershell
   flask normalize-product --vendor Fortinet --product FortiOS
   ```

5. Confirm FortiGate, FortiOS, and confidence 100 are returned.
6. Repeat using lower-case vendor and product values and confirm the
   case-insensitive fallback returns a lower confidence.
7. Run an unknown product and confirm an unmatched result.
8. Disable the alias or catalog product and confirm it no longer matches.
9. Confirm Product Catalog, Assets, Threats, collectors, and Dashboard data are
   unchanged after each command.

Automated tests can be run without production SQL access:

```powershell
python -B -m unittest discover -s tests -v
```

The tests use an isolated in-memory database.

## Known limitations

- Matching uses names only; it does not consider versions.
- Alias-only matches can be ambiguous when different products share an alias.
- Vendor spelling variants require explicit aliases or a future vendor
  normalization strategy.
- Whitespace is trimmed only at the beginning and end. Internal whitespace,
  punctuation, word order, and abbreviations are not rewritten.
- Case-insensitive candidate lookup depends on SQL `LOWER` behavior; exact
  Unicode case-folding edge cases may vary by database collation.
- Inactive products and aliases are intentionally ignored.
- Results are not persisted or audited.

## Future improvements

Future work may add version-aware resolution, vendor normalization, explainable
ambiguity reporting, batch threat normalization, persisted normalization
history, CPE support, and operator review workflows. Asset matching must remain a
separate later stage so product resolution can be tested and audited
independently.