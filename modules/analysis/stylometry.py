"""Pure-Python stylometry metrics for a bag of short text samples.

Works on the concatenation of every ``bio`` / ``description`` we've
harvested from discovered profiles. These are short (typical 20-200
chars each), so we don't bother with heavyweight NLP — just the
classic stylometric primitives:

* word count, avg word length
* sentence count, avg sentence length
* lexical diversity (unique / total)
* punctuation and uppercase ratios
* emoji count
* top 10 content words (stopword-filtered)

The output is reproducible: same input → same report.
"""

from __future__ import annotations

import re
from collections import Counter

from modules.analysis.models import StylometryReport

# Conservative cross-language stopword list (EN + TR since the project
# is Turkish/English bilingual). Not exhaustive — we just want to strip
# the worst noise before reporting "top words".
_STOPWORDS = frozenset(
    {
        "the", "and", "a", "an", "of", "to", "in", "is", "it", "you", "i",
        "for", "on", "with", "as", "at", "this", "that", "be", "are",
        "was", "have", "has", "but", "not", "or", "by", "from", "my", "we",
        "ve", "de", "da", "bir", "bu", "ile", "ama", "için", "çok", "daha",
        "gibi", "her", "ben", "sen", "biz", "siz", "onlar", "var", "yok",
    }
)

_WORD_RE = re.compile(r"[A-Za-zÀ-ÖØ-öø-ÿĞğİıŞşÇçÖöÜü]+", re.UNICODE)
_SENTENCE_RE = re.compile(r"[.!?]+")
_PUNCT_RE = re.compile(r"[^\w\s]", re.UNICODE)
_EMOJI_RE = re.compile(
    "["
    "\U0001F300-\U0001F6FF"
    "\U0001F900-\U0001F9FF"
    "\U0001FA70-\U0001FAFF"
    "\U00002600-\U000027BF"
    "]",
    flags=re.UNICODE,
)


def compute_stylometry(samples: list[str]) -> StylometryReport:
    """Return a stylometric fingerprint for ``samples``.

    Empty input → an all-zero report.
    """
    cleaned = [s for s in samples if s and s.strip()]
    if not cleaned:
        return StylometryReport()

    joined = "\n".join(cleaned)
    total_chars = len(joined)

    words = _WORD_RE.findall(joined)
    total_words = len(words)
    if total_words == 0:
        return StylometryReport(sample_count=len(cleaned), total_chars=total_chars)

    unique_words = len({w.lower() for w in words})
    avg_word_length = sum(len(w) for w in words) / total_words
    lexical_diversity = unique_words / total_words

    sentence_splits = [s for s in _SENTENCE_RE.split(joined) if s.strip()]
    sentence_count = max(1, len(sentence_splits))
    avg_sentence_length = total_words / sentence_count

    punct_chars = _PUNCT_RE.findall(joined)
    punctuation_ratio = len(punct_chars) / total_chars

    uppercase_chars = sum(1 for c in joined if c.isupper())
    alpha_chars = sum(1 for c in joined if c.isalpha())
    uppercase_ratio = (uppercase_chars / alpha_chars) if alpha_chars else 0.0

    emoji_count = len(_EMOJI_RE.findall(joined))

    content_words = [
        w.lower() for w in words if len(w) >= 3 and w.lower() not in _STOPWORDS
    ]
    top = Counter(content_words).most_common(10)

    return StylometryReport(
        sample_count=len(cleaned),
        total_chars=total_chars,
        total_words=total_words,
        avg_word_length=avg_word_length,
        avg_sentence_length=avg_sentence_length,
        lexical_diversity=lexical_diversity,
        punctuation_ratio=punctuation_ratio,
        uppercase_ratio=uppercase_ratio,
        emoji_count=emoji_count,
        top_words=tuple((w, c) for w, c in top),
    )
