import hashlib
import re


def sanitize_username(username: str) -> str:
    return username.strip().lstrip("@")


def md5_hash(text: str) -> str:
    return hashlib.md5(text.lower().strip().encode(), usedforsecurity=False).hexdigest()


def extract_emails_from_text(text: str) -> list[str]:
    if not text:
        return []
    pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
    return list(set(re.findall(pattern, text)))


def extract_urls_from_text(text: str) -> list[str]:
    if not text:
        return []
    pattern = r"https?://[^\s<>\"')\]]+"
    return list(set(re.findall(pattern, text)))


def normalize_name(name: str) -> str:
    if not name:
        return ""
    return re.sub(r"\s+", " ", name.strip().lower())


def fuzzy_name_match(name1: str, name2: str) -> float:
    if not name1 or not name2:
        return 0.0
    n1 = normalize_name(name1)
    n2 = normalize_name(name2)
    if n1 == n2:
        return 1.0
    parts1 = set(n1.split())
    parts2 = set(n2.split())
    if not parts1 or not parts2:
        return 0.0
    intersection = parts1 & parts2
    union = parts1 | parts2
    return len(intersection) / len(union)
