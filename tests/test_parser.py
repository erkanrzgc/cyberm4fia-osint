"""Parser smoke tests: alias coverage and help text."""
import pytest

from main import build_parser


@pytest.fixture
def parser():
    return build_parser()


def test_breach_and_hibp_aliases_share_dest(parser):
    ns_breach = parser.parse_args(["alice", "--breach"])
    ns_hibp = parser.parse_args(["alice", "--hibp"])
    assert ns_breach.breach is True
    assert ns_hibp.breach is True


def test_tor_and_toor_aliases(parser):
    ns_tor = parser.parse_args(["alice", "--tor"])
    ns_toor = parser.parse_args(["alice", "-toor"])
    assert ns_tor.tor is True
    assert ns_toor.tor is True


def test_help_lists_new_flags(parser, capsys):
    with pytest.raises(SystemExit):
        parser.parse_args(["--help"])
    out = capsys.readouterr().out
    for flag in ("--breach", "--hibp", "--tor", "-toor", "--photo", "--whois", "--dns", "--subdomain"):
        assert flag in out, f"{flag} missing from --help"


def test_full_flag_present(parser):
    ns = parser.parse_args(["alice", "--full"])
    assert ns.full is True


def test_category_csv_parses(parser):
    ns = parser.parse_args(["alice", "--category", "social,dev,gaming"])
    assert ns.category == "social,dev,gaming"
