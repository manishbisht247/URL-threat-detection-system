import re
import math
import urllib.parse as urlparse
from collections import Counter

def extract_essential_features(url):
    """Extract the 25 most important lexical features for URL threat detection"""
    parsed = urlparse.urlparse(url)
    domain = parsed.netloc
    path = parsed.path
    query = parsed.query
    
    features = {}
    
    # Basic structural features
    features['url_length'] = len(url)
    features['domain_length'] = len(domain)
    features['path_length'] = len(path)
    features['subdomain_count'] = len(domain.split('.')) - 2 if len(domain.split('.')) > 2 else 0
    features['path_depth'] = len([p for p in path.split('/') if p])
    
    # Character-based features
    features['dot_count'] = url.count('.')
    features['hyphen_count'] = url.count('-')
    features['slash_count'] = url.count('/')
    features['at_count'] = url.count('@')
    
    # Character ratios
    digits = sum(c.isdigit() for c in url)
    letters = sum(c.isalpha() for c in url)
    features['digit_letter_ratio'] = digits / max(letters, 1)
    features['special_char_ratio'] = sum(not c.isalnum() for c in url) / len(url)
    
    # Entropy features
    features['url_entropy'] = calculate_entropy(url)
    features['domain_entropy'] = calculate_entropy(domain)
    
    # Suspicious patterns
    features['has_ip'] = 1 if re.search(r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+", url) else 0
    features['has_at_symbol'] = 1 if '@' in url else 0
    
    # Suspicious content
    suspicious_words = ['secure', 'account', 'verify', 'paypal', 'login']
    features['suspicious_word_count'] = sum(word in url.lower() for word in suspicious_words)
    
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf']
    features['has_suspicious_tld'] = 1 if any(tld in domain.lower() for tld in suspicious_tlds) else 0
    
    return features

def calculate_entropy(text):
    """Calculate Shannon entropy"""
    if not text:
        return 0
    counter = Counter(text.lower())
    length = len(text)
    entropy = 0
    for count in counter.values():
        prob = count / length
        if prob > 0:
            entropy -= prob * math.log2(prob)
    return entropy

def is_ip_address(address):
    """Check if address is an IP address"""
    try:
        import ipaddress
        ipaddress.ip_address(address)
        return True
    except:
        return False