import os
from .patterns import find_patterns
from .validator import validate
from .utils import hash_string

class CredentialScanner:
    def __init__(self, root_path):
        self.root_path = root_path

    def scan(self):
        results = []
        for root, _, files in os.walk(self.root_path):
            for file in files:
                if file.endswith(('.py', '.env', '.txt', '.cfg', '.json')):
                    path = os.path.join(root, file)
                    with open(path, 'r', errors='ignore') as f:
                        content = f.read()
                    
                    found = find_patterns(content)
                    for pattern_name, matched_value in found:
                        is_credible, reason = validate(pattern_name, matched_value)
                        if is_credible:
                            snippet = matched_value[:80]
                            results.append({
                                'file': path,
                                'type': pattern_name,
                                'hash': hash_string(snippet),
                                'snippet': snippet
                            })
        return results
