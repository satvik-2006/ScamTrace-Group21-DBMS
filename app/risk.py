"""Transparent educational scoring: NOT a trained fraud classifier."""
import re

RULES = [
    ('Urgent pressure', 16, r'urgent|immediately|24 hours|expire|blocked|disconnection|suspend|arrest'),
    ('Payment or deposit request', 24, r'refund|collect request|deposit|fee|pay |payment|transfer|send money|rs\s?\d'),
    ('Impersonation claim', 18, r'bank|police|customs|courier|kyc|sbi|hdfc|government|official'),
    ('External link', 12, r'https?://|\b[a-z0-9.-]+\.(?:com|in|net|org)\b'),
    ('High-return promise', 20, r'lottery|prize|winner|double|crypto|guaranteed profit|investment'),
]
BASE = {'Phishing': 24, 'UPI Fraud': 27, 'Job Scam': 15, 'Lottery Scam': 13, 'Investment Scam': 20, 'Impersonation Call': 22}

def score_report(title: str, description: str, category: str):
    full = (title + ' ' + description).lower()
    detections = [(name, weight) for name, weight, pattern in RULES if re.search(pattern, full)]
    score = min(100, BASE.get(category, 10) + sum(w for _, w in detections))
    level = 'CRITICAL' if score >= 85 else 'HIGH' if score >= 65 else 'MEDIUM' if score >= 35 else 'LOW'
    return score, level, detections
