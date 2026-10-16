from .base import Scanner

class PublicExposureScanner(Scanner):
    name = 'public_exposure'
    def scan(self, source):
        # Network calls are intentionally disabled by default for local, offline audits.
        return []
