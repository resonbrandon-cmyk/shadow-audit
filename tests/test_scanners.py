from pathlib import Path
from scanners.credentials import CredentialScanner
from scanners.shadow_ai import ShadowAIScanner
from scanners.oauth import OAuthScanner
from scanners.nhi import NHIScanner

BASE = Path(__file__).parent / 'sample_inputs'

def test_credentials(): assert len(CredentialScanner().scan(BASE / 'secrets.env')) == 2
def test_shadow_ai(): assert len(ShadowAIScanner().scan(BASE / 'traffic.csv')) == 1
def test_oauth(): assert len(OAuthScanner().scan(BASE / 'oauth.json')) == 1
def test_nhi(): assert len(NHIScanner().scan(BASE / 'identities.csv')) == 1
