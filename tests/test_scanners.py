import json
from pathlib import Path
from scanners.credentials import CredentialScanner
from scanners.shadow_ai import ShadowAIScanner
from scanners.oauth import OAuthScanner
from scanners.nhi import NHIScanner
ROOT=Path(__file__).parent/"sample_inputs"
def test_credentials():
    findings=CredentialScanner().scan(ROOT/"secrets.env")
    assert len(findings)>=2 and "1234" not in str(findings[0].evidence)
def test_shadow_ai(): assert len(ShadowAIScanner().scan(ROOT/"traffic.csv"))==1
def test_oauth(): assert len(OAuthScanner().scan(ROOT/"oauth.json"))==1
def test_nhi(): assert len(NHIScanner().scan(ROOT/"identities.csv"))==2
