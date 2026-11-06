# Inputs for a light wordlist-transformation profile

## Private local reference

Local recovered results may be sensitive. Findings derived from those results,
including aggregate characteristics and sample sizes, are intentionally omitted
from this public-facing note. Local samples are also selection-biased: they
contain only passwords recovered by existing candidate sources and cannot
establish how unrecovered passwords are formed.

## Published evidence

- Das et al., *The Tangled Web of Password Reuse* (NDSS 2014), examines breached
  credentials and user transformations. It discusses capitalization, numeric and
  symbol affixes, and leet substitutions. Its RockYou-based analysis informs
  insertion choices. The authors use bounded, ordered transformation families
  rather than combining every possible change. [Primary paper](https://www.cs.cmu.edu/~anupamd/paper/NDSS2014.pdf).
- Nisenoff et al., *A Two-Decade Retrospective Analysis of a University's
  Vulnerability to Attacks Exploiting Reused Passwords* (USENIX Security 2023),
  reports that changing the first character's case and appending `1` or `!` were
  particularly successful tweaks. Its context includes breaches such as LinkedIn,
  Chegg, LiveJournal, Dropbox and MySpace. [Primary paper](https://www.usenix.org/system/files/usenixsecurity23-nisenoff-retrospective.pdf).

These studies examine account passwords and cross-service reuse. Applying their
patterns to Wi-Fi candidates is a design inference to validate locally, not a
claim that their success rates transfer to this project.

## Agreed profile direction

Prefer original/lowercase/initial-capital forms, a curated numeric suffix pool,
limited years, and a small selection of punctuation and familiar substitutions.
Keep the expansion near the requested budget rather than multiplying every
family from the full profile. Do not pad a word with duplicate guesses merely to
reach a count. Retain normal exact-byte handling and eligible length limits.

Even roughly 1,000 combinations across the current 2.14-million-entry source
means roughly 2.14 billion combinations per record before filtering/deduplication.
Reducing the profile addresses workload size; durable checkpoints address lost
unfinished work. Runtime still needs measurement on the selected backend.
