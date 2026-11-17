"""Run all unit tests and write the report's machine-readable evidence."""
import io
import json
from pathlib import Path
import platform
import sys
import time
import unittest

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))
if __name__ == '__main__':
    stream = io.StringIO()
    start = time.perf_counter()
    result = unittest.TextTestRunner(stream=stream, verbosity=2).run(unittest.defaultTestLoader.discover(str(BASE/'tests')))
    evidence = {'result':'PASS' if result.wasSuccessful() else 'FAIL','tests':result.testsRun,
                'failures':len(result.failures),'errors':len(result.errors),'seconds':round(time.perf_counter()-start,4),
                'python':platform.python_version(),'platform':platform.platform()}
    (BASE/'evidence/unit_tests.txt').write_text(stream.getvalue(),encoding='utf-8')
    (BASE/'evidence/unit_tests.json').write_text(json.dumps(evidence,ensure_ascii=False,indent=2),encoding='utf-8')
    print(stream.getvalue())
    raise SystemExit(0 if result.wasSuccessful() else 1)
