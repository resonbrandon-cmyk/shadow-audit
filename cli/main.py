import argparse
from pathlib import Path
from scanners.credentials import CredentialScanner
from scanners.shadow_ai import ShadowAIScanner
from scanners.oauth import OAuthScanner
from scanners.nhi import NHIScanner
from reporting.generator import generate_markdown

SCANNERS = {'credentials': CredentialScanner(), 'shadow_ai': ShadowAIScanner(), 'oauth': OAuthScanner(), 'nhi': NHIScanner()}
parser = argparse.ArgumentParser(prog='shadow-audit')
sub = parser.add_subparsers(dest='command', required=True)
run = sub.add_parser('run'); run.add_argument('--client', required=True); run.add_argument('--modules', required=True); run.add_argument('--input', required=True)
args = parser.parse_args()
if args.command == 'run':
    findings = []
    for module in args.modules.split(','):
        findings.extend(SCANNERS[module].scan(Path(args.input)))
    output = generate_markdown(args.client, findings, Path('reports') / 'audit.md')
    print(f'Generated {output} with {len(findings)} finding(s).')
