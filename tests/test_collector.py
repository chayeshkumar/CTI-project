# tests/test_collector.py
import unittest
from collector import score_indicator

class TestScoring(unittest.TestCase):
    def test_malware(self):
        score = score_indicator(['malware'])
        self.assertTrue(score >= 50)

    def test_phishing(self):
        score = score_indicator(['phishing'])
        self.assertTrue(score >= 30)

if __name__ == '__main__':
    unittest.main()
