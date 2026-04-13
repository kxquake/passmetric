import math
import secrets
import re
import nltk
import string
from typing import List, Dict, Tuple, Optional, Set
from dataclasses import dataclass
from enum import Enum
import os

# Import common words from nltk
import nltk
try:
    from nltk.corpus import words
    
    # Try to access the corpus to see if it's downloaded
    try:
        common_words = set(words.words())
    except LookupError:
        print("Downloading missing NLTK 'words' dataset...")
        nltk.download('words', quiet=True)
        common_words = set(words.words())
        
except ImportError:
    print("NLTK not installed. Install with: pip install nltk")
    common_words = set()

class StrengthLevel(Enum):
    VERY_WEAK = 0
    WEAK = 1
    MEDIUM = 2
    STRONG = 3
    VERY_STRONG = 4

@dataclass
class EvaluationResult:
    password: str
    strength_level: StrengthLevel
    score: float  # 0-100
    entropy_bits: float
    character_diversity: int
    issues: List[str]
    warnings: List[str]
    recommendations: List[str]
    details: Dict[str, any]

class PasswordEvaluator:

    # Common weak passwords and patterns
    COMMON_PASSWORDS = {
        "password", "123456", "12345678", "qwerty", "abc123", "monkey",
        "1234567", "letmein", "trustno1", "dragon", "baseball", "iloveyou",
        "master", "sunshine", "ashley", "bailey", "passw0rd", "shadow",
        "123123", "654321", "superman", "qazwsx", "michael", "football"
    }

    # keyboard patterns to check against
    KEYBOARD_PATTERNS = ["qwerty", "asdfgh", "zxcvbn", "qwertyuiop", "asdfghjkl", "zxcvbnm",
        "1234567890", "!@#$%^&*()", "qazwsx", "wsxedc", "edcrfv", "rfvtgb", "tgbnhy", "yhnujm", "ujm,./"]
    
    # Common l33t speak substitutions
    LEET_SPEAK = {
        'a': ['4', '@'], 'e': ['3'], 'i': ['1', '!'], 'o': ['0'],
        's': ['5', '$'], 't': ['7'], 'l': ['1'], 'g': ['9']
    }

    #Sequence patterns
    SEQUENCE_PATTERNS = [
        "abcdefghijklmnopqrstuvwxyz",
        "qwertyuiopasdfghjklzxcvbnm",
        "0123456789"
    ]

    def __init__(self):
        pass

    def evaluate_password(self, password: str) -> EvaluationResult:
        if not password:
            return self._create_result(
                password='',
                strength=StrengthLevel.VERY_WEAK,
                score=0,
                entropy=0,
                diversity=0,
                issues=["Password cannot be empty."],
                warnings=[],
                details={},
                recommendations=["Use a password with at least 12 characters, including uppercase, lowercase, digits, and symbols."],
            )
        
    
        entropy = self.calculate_entropy(password)
        diversity = self._calculate_diversity(password)

        issues = []
        warnings = []
        recommendations = []
        details = {}

        # Length checks
        length_results = self._check_length(password)
        issues.extend(length_results['issues'])
        warnings.extend(length_results['warnings'])
        recommendations.extend(length_results['recommendations'])
        details['length'] = length_results

         # Composition check
        composition_result = self._check_composition(password)
        warnings.extend(composition_result['warnings'])
        recommendations.extend(composition_result['recommendations'])
        details['composition'] = composition_result
        
        # Common password check
        common_result = self._check_common_passwords(password)
        issues.extend(common_result['issues'])
        details['common_password'] = common_result
        
        # Dictionary word check
        dictionary_result = self._check_dictionary_words(password)
        warnings.extend(dictionary_result['warnings'])
        recommendations.extend(dictionary_result['recommendations'])
        details['dictionary'] = dictionary_result
        
        # Pattern check
        pattern_result = self._check_patterns(password)
        issues.extend(pattern_result['issues'])
        warnings.extend(pattern_result['warnings'])
        details['patterns'] = pattern_result
        
        # Sequence check
        sequence_result = self._check_sequences(password)
        warnings.extend(sequence_result['warnings'])
        details['sequences'] = sequence_result
        
        # Keyboard pattern check
        keyboard_result = self._check_keyboard_patterns(password)
        warnings.extend(keyboard_result['warnings'])
        details['keyboard'] = keyboard_result
        
        # Year check
        year_result = self._check_years(password)
        warnings.extend(year_result['warnings'])
        details['years'] = year_result
        
        # L33t speak check
        leet_result = self._check_leet_speak(password)
        warnings.extend(leet_result['warnings'])
        recommendations.extend(leet_result['recommendations'])
        details['leet_speak'] = leet_result
        
        # Repetition check
        repetition_result = self._check_repetition(password)
        warnings.extend(repetition_result['warnings'])
        details['repetition'] = repetition_result
        
        # Calculate final score and strength level
        score, strength = self._calculate_final_score(
            password, entropy, diversity, issues, warnings
        )
        
        # Add general recommendations based on strength
        if strength in [StrengthLevel.VERY_WEAK, StrengthLevel.WEAK]:
            recommendations.append("Consider using the password generator for a strong password")

        details['entropy_bits'] = entropy
        details['character_diversity'] = diversity
        details['score'] = score
        
        return self._create_result(
            password=password,
            strength=strength,
            score=score,
            entropy=entropy,
            diversity=diversity,
            issues=issues,
            warnings=warnings,
            recommendations=recommendations,
            details=details
        )
    
    def calculate_entropy(self, password: str) -> float:
        if not password:
            return 0.0
        
        charset_size = 0
        if any(c.islower() for c in password):
            charset_size += 26 # lowercase letters
        if any(c.isupper() for c in password):
            charset_size += 26 # uppercase letters
        if any(c.isdigit() for c in password):
            charset_size += 10 # digits
        if any(c in string.punctuation for c in password):
            charset_size += len(string.punctuation) # symbols

    # Calculate entropy using Shannon's formula: H = log2(charset_size) * length
        if charset_size == 0:
            return 0.0
    
        entropy = math.log2(charset_size) * len(password)
        return round(entropy, 2)
    

    def _calculate_diversity(self, password: str) -> int:
        return len(set(password))
    
    def _check_length(self, password: str) -> Dict:
        length = len(password)
        result = {'length': length, 'issues': [], 'warnings': [], 'recommendations': []}
        
        if length < 8:
            result['issues'].append(f"Password is too short ({length} characters)")
            result['recommendations'].append("Use at least 12 characters (NIST recommendation)")
        elif length < 12:
            result['warnings'].append(f"Password could be longer ({length} characters)")
            result['recommendations'].append("Consider using 16+ characters for better security")
        elif length >= 16:
            result['strength'] = "excellent"
        
        return result
       
    def _check_composition(self, password: str) -> Dict:
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = any(c in string.punctuation for c in password)

        result = {'has_lower': has_lower, 'has_upper': has_upper, 'has_digit': has_digit, 'has_symbol': has_symbol,
            'warnings': [], 'recommendations': []}

        if not has_lower:
            result['warnings'].append("Password does not contain lowercase letters")
            result['recommendations'].append("Include lowercase letters (a-z)")
        if not has_upper:
            result['warnings'].append("Password does not contain uppercase letters")
            result['recommendations'].append("Include uppercase letters (A-Z)")
        if not has_digit:
            result['warnings'].append("Password does not contain digits")
            result['recommendations'].append("Include digits (0-9)")
        if not has_symbol:
            result['warnings'].append("Password does not contain symbols")
            result['recommendations'].append(f"Include symbols ({string.punctuation})")

        return result
    
    def _check_common_passwords(self, password: str) -> Dict:
        # Check if password is in the common passwords list or contains common passwords as substrings

        result = {'is_common': False, 'issues': []} 
        if password.lower() in self.COMMON_PASSWORDS:
            result['is_common'] = True
            result['issues'].append("Password is a commonly used password")
            return result
        

        for common_pwd in self.COMMON_PASSWORDS:
            if common_pwd in password.lower():
                result['is_common'] = True
                result['issues'].append(f"Contains common password: '{common_pwd}'")
                break
        
        return result
    
    def _check_dictionary_words(self, password: str) -> Dict:
        # Check if password contains common dictionary words
        result = {'contains_dictionary_word': False, 'warnings': [], 'recommendations': []}
        password_lower = password.lower()
        for word in common_words:
            if len(word) >= 4 and word in password_lower:
                result['contains_dictionary_word'] = True
                result['warnings'].append(f"Contains dictionary word: '{word}'")
                result['recommendations'].append("Avoid using common words or combine them with random characters")
                break
        
        return result
    
    def _check_patterns(self, password: str) -> Dict:
        # Check for repeated patterns (e.g., "abcabc", "123123") and all same character
        result = {'patterns_found': [], 'issues': [], 'warnings': []}
        
        if len(set(password)) == 1:
            result['patterns_found'].append("all_same_character")
            result['issues'].append("Password uses only one repeated character")

        for i in range(2, len(password) // 2 + 1):
            pattern = password[:i]
            if password == pattern * (len(password) // i):
                result['patterns_found'].append(f"repeated_pattern:{pattern}")
                result['issues'].append(f"Password is a repeated pattern: '{pattern}'")
                break
        
        return result
    
    def _check_sequences(self, password: str) -> Dict:
        # Check for sequential characters (e.g., "abcd", "1234")
        result = {'sequences_found': [], 'warnings': []}
        password_lower = password.lower()
        
        for seq in self.SEQUENCE_PATTERNS:
            for i in range(len(seq) - 3):
                forward_seq = seq[i:i+4]
                reverse_seq = forward_seq[::-1]
                if forward_seq in password_lower:
                    result['sequences_found'].append(forward_seq)
                    result['warnings'].append(f"Contains sequential characters: '{forward_seq}'")
                if reverse_seq in password_lower:
                    result['sequences_found'].append(reverse_seq)
                    result['warnings'].append(f"Contains sequential characters: '{reverse_seq}'")
        
        return result
    
    def _check_keyboard_patterns(self, password: str) -> Dict:
        # Check for common keyboard patterns (e.g., "qwerty", "asdf")
        result = {'keyboard_patterns_found': [], 'warnings': []}
        password_lower = password.lower()
        
        for pattern in self.KEYBOARD_PATTERNS:
            if pattern in password_lower:
                result['keyboard_patterns_found'].append(pattern)
                result['warnings'].append(f"Contains keyboard pattern: '{pattern}'")
        
        return result
    
    def _check_years(self, password: str) -> Dict:
        # Check for 4-digit numbers that look like years (e.g., "1990", "2020")
        result = {'years_found': [], 'warnings': []}
        
        # Find 4-digit numbers that look like years
        year_pattern = r'(19\d{2}|20\d{2})'
        matches = re.findall(year_pattern, password)
        
        if matches:
            result['years_found'] = matches
            result['warnings'].append(f"Contains year(s): {', '.join(matches)}")
        
        return result
    
    def _check_leet_speak(self, password: str) -> Dict:
        # Check for common l33t speak substitutions (e.g., "p@ssw0rd" for "password")
        result = {'leet_speak_found': [], 'warnings': [], 'recommendations': []}
        password_lower = password.lower()
        
        for char, subs in self.LEET_SPEAK.items():
            for sub in subs:
                if sub in password_lower:
                    result['leet_speak_found'].append(f"{char} -> {sub}")
                    result['warnings'].append(f"Contains l33t speak substitution: '{char}' replaced with '{sub}'")
                    result['recommendations'].append("Avoid common l33t substitutions as they are well-known to attackers")
        
        return result
    
    def _check_repetition(self, password: str) -> Dict:
        # Check for repeated characters (e.g., "aaabbb", "1111")
        result = {'repeated_characters': [], 'warnings': []}
        
        for char in set(password):
            count = password.count(char)
            if count > 3:
                result['repeated_characters'].append(f"{char} repeated {count} times")
                result['warnings'].append(f"Character '{char}' is repeated {count} times, which can weaken the password")
        
        return result
    
    def _calculate_final_score(self, password: str, entropy: float, diversity: int, issues: List[str], warnings: List[str]) -> Tuple[float, StrengthLevel]:
        base_score = min(100, (entropy / 128) * 100)  # Normalize entropy to a 0-100 scale (128 bits is considered very strong)

        length = len(password)
        if length < 8:
            base_score *= 0.3
        elif length < 12:
            base_score *= 0.6
        elif length < 16:
            base_score *= 1.1
        
        diversity_ratio = diversity / len(password) if len(password) > 0 else 0
        if diversity_ratio < 0.5:
            base_score *= 0.8
        elif diversity_ratio > 0.8:
            base_score *= 1.05

        penalty = len(issues) * 20 + len(warnings) * 5
        final_score = max(0, base_score - penalty)

        final_score = min(100, final_score)

        # Determine strength level based on final score
        if final_score >= 80:
            strength = StrengthLevel.VERY_STRONG
        elif final_score >= 60:
            strength = StrengthLevel.STRONG
        elif final_score >= 40:
            strength = StrengthLevel.MEDIUM
        elif final_score >= 20:
            strength = StrengthLevel.WEAK
        else:
            strength = StrengthLevel.VERY_WEAK
        
        return round(final_score, 1), strength
    
    def _create_result(self, password: str, strength: StrengthLevel, score: float, entropy: float, diversity: int, issues: List[str], warnings: List[str], recommendations: List[str], details: Dict) -> EvaluationResult:
        return EvaluationResult(
            password=password,
            strength_level=strength,
            score=score,
            entropy_bits=entropy,
            character_diversity=diversity,
            issues=issues,
            warnings=warnings,
            recommendations=recommendations,
            details=details
        )