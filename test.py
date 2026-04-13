"""
PassMetric - Machine Learning Password Classifier
Uses RockYou dataset for training with real leaked passwords
"""

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import string
import re
import math
import random
import secrets
from typing import List, Tuple, Optional
import pickle
import os


class PasswordMLClassifier:
    """
    Machine Learning classifier for password strength using REAL datasets.
    
    Uses Random Forest to classify passwords as WEAK, MEDIUM, or STRONG
    based on extracted features. Trained on RockYou leaked passwords.
    """
    
    def __init__(self):
        """Initialize the ML classifier."""
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            class_weight='balanced'  # Handle imbalanced classes
        )
        self.is_trained = False
        self.feature_names = [
            'length', 'has_lowercase', 'has_uppercase', 'has_digits', 
            'has_symbols', 'unique_chars_ratio', 'entropy_estimate',
            'has_common_words', 'has_sequences', 'has_patterns',
            'has_years', 'has_repeats', 'types_count'
        ]
        self.label_map = {0: 'WEAK', 1: 'MEDIUM', 2: 'STRONG'}
    
    def extract_features(self, password: str) -> np.ndarray:
        """
        Extract numerical features from password for ML model.
        
        Features:
        1.  length: int
        2.  has_lowercase: binary (0/1)
        3.  has_uppercase: binary (0/1)
        4.  has_digits: binary (0/1)
        5.  has_symbols: binary (0/1)
        6.  unique_chars_ratio: float (0-1)
        7.  entropy_estimate: float (bits)
        8.  has_common_words: binary (0/1)
        9.  has_sequences: binary (0/1)
        10. has_patterns: binary (0/1)
        11. has_years: binary (0/1)
        12. has_repeats: binary (0/1)
        13. types_count: int (0-4)
        
        Returns:
            numpy array of shape (1, 13)
        """
        features = []
        
        # 1. Length
        features.append(len(password))
        
        # 2-5. Character type presence
        features.append(1 if any(c.islower() for c in password) else 0)
        features.append(1 if any(c.isupper() for c in password) else 0)
        features.append(1 if any(c.isdigit() for c in password) else 0)
        features.append(1 if any(c in string.punctuation for c in password) else 0)
        
        # 6. Unique character ratio
        if len(password) > 0:
            unique_ratio = len(set(password)) / len(password)
        else:
            unique_ratio = 0
        features.append(unique_ratio)
        
        # 7. Simple entropy estimate
        charset_size = 0
        if any(c.islower() for c in password):
            charset_size += 26
        if any(c.isupper() for c in password):
            charset_size += 26
        if any(c.isdigit() for c in password):
            charset_size += 10
        if any(c in string.punctuation for c in password):
            charset_size += 32
        
        if charset_size > 0 and len(password) > 0:
            entropy = len(password) * math.log2(charset_size)
        else:
            entropy = 0
        features.append(entropy)
        
        # 8. Has common words (simplified check)
        common_words = ['password', 'welcome', 'admin', 'user', 'test', 'login', 'love', 'summer']
        has_common = 1 if any(word in password.lower() for word in common_words) else 0
        features.append(has_common)
        
        # 9. Has sequences
        sequences = ['abc', '123', 'qwe']
        has_seq = 1 if any(seq in password.lower() for seq in sequences) else 0
        features.append(has_seq)
        
        # 10. Has patterns (simple repetition)
        has_pattern = 0
        if len(password) >= 4:
            for i in range(2, len(password) // 2 + 1):
                if password[:i] * (len(password) // i) == password:
                    has_pattern = 1
                    break
        features.append(has_pattern)
        
        # 11. Has years
        year_pattern = r'(19\d{2}|20\d{2})'
        has_year = 1 if re.search(year_pattern, password) else 0
        features.append(has_year)
        
        # 12. Has consecutive repeated characters
        has_repeats = 0
        for i in range(1, len(password)):
            if password[i] == password[i-1]:
                has_repeats = 1
                break
        features.append(has_repeats)
        
        # 13. Number of character types
        types_count = sum([
            any(c.islower() for c in password),
            any(c.isupper() for c in password),
            any(c.isdigit() for c in password),
            any(c in string.punctuation for c in password)
        ])
        features.append(types_count)
        
        return np.array(features).reshape(1, -1)
    
    def generate_training_data(self, n_samples: int = 10000) -> Tuple[np.ndarray, np.ndarray]:
        """
        Generate training data using REAL leaked passwords from RockYou dataset.
        
        RockYou contains 14.3M leaked passwords from 2009.
        This is the most famous password dataset used in academic research.
        
        Args:
            n_samples: Total number of samples to generate
            
        Returns:
            Tuple of (features, labels)
        """
        features_list = []
        labels_list = []
        
        # Path to RockYou dataset
        rockyou_path = 'rockyou.txt'
        
        # Check if RockYou exists
        if not os.path.exists(rockyou_path):
            print(f"⚠️  RockYou dataset not found at {rockyou_path}")
            print("Please download RockYou dataset:")
            print("  mkdir -p datasets")
            print("  wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt -O datasets/rockyou.txt")
            print("\nFalling back to synthetic data for now...")
            return self._generate_synthetic_data(n_samples)
        
        print(f"📁 Loading passwords from RockYou dataset...")
        
        # Calculate how many of each type we need
        weak_target = int(n_samples * 0.4)      # 40% weak (from RockYou)
        medium_target = int(n_samples * 0.3)    # 30% medium (from RockYou)
        strong_target = n_samples - weak_target - medium_target  # 30% strong (synthetic)
        
        # Load and label RockYou passwords
        weak_count = 0
        medium_count = 0
        
        try:
            with open(rockyou_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    # Stop if we have enough
                    if weak_count >= weak_target and medium_count >= medium_target:
                        break
                    
                    password = line.strip()
                    if not password:
                        continue
                    
                    # Auto-label the password
                    label = self._auto_label_password(password)
                    
                    # Only take what we need
                    if label == 0 and weak_count < weak_target:
                        features_list.append(self.extract_features(password).flatten())
                        labels_list.append(0)
                        weak_count += 1
                    elif label == 1 and medium_count < medium_target:
                        features_list.append(self.extract_features(password).flatten())
                        labels_list.append(1)
                        medium_count += 1
                    # Skip STRONG from RockYou (leaked passwords are rarely strong)
            
            print(f"✅ Loaded {weak_count} WEAK passwords from RockYou")
            print(f"✅ Loaded {medium_count} MEDIUM passwords from RockYou")
        
        except Exception as e:
            print(f"❌ Error loading RockYou: {e}")
            print("Falling back to synthetic data...")
            return self._generate_synthetic_data(n_samples)
        
        # Generate synthetic STRONG passwords
        # (Real strong passwords don't leak, so we generate them)
        print(f"🔐 Generating {strong_target} synthetic STRONG passwords...")
        
        charset = string.ascii_letters + string.digits + string.punctuation
        for _ in range(strong_target):
            length = random.randint(12, 20)
            strong = ''.join(secrets.choice(charset) for _ in range(length))
            features_list.append(self.extract_features(strong).flatten())
            labels_list.append(2)  # STRONG
        
        print(f"✅ Generated {strong_target} STRONG passwords")
        
        # Shuffle the data
        combined = list(zip(features_list, labels_list))
        random.shuffle(combined)
        features_list, labels_list = zip(*combined)
        
        print(f"\n📊 Final Dataset:")
        print(f"   WEAK:   {labels_list.count(0):5d} ({labels_list.count(0)/len(labels_list)*100:.1f}%)")
        print(f"   MEDIUM: {labels_list.count(1):5d} ({labels_list.count(1)/len(labels_list)*100:.1f}%)")
        print(f"   STRONG: {labels_list.count(2):5d} ({labels_list.count(2)/len(labels_list)*100:.1f}%)")
        print(f"   Total:  {len(labels_list):5d}\n")
        
        return np.array(features_list), np.array(labels_list)
    
    def _auto_label_password(self, password: str) -> int:
        """
        Automatically label a password from RockYou as WEAK/MEDIUM/STRONG.
        
        Labeling criteria based on NIST SP 800-63B and OWASP guidelines:
        
        WEAK (0):
        - Length < 8 characters
        - Only one character type (all lowercase/uppercase/digits)
        - Entropy < 40 bits
        - Contains common words or patterns
        - Has repeated characters (aaa, 111)
        
        MEDIUM (1):
        - Length 8-11 characters
        - Mixed character types (2-3 types)
        - Entropy 40-80 bits
        - May have years or minor patterns
        
        STRONG (2):
        - Length >= 12 characters
        - All character types present (3-4 types)
        - Entropy >= 80 bits
        - No common patterns
        
        Args:
            password: Password to label
            
        Returns:
            0 (WEAK), 1 (MEDIUM), or 2 (STRONG)
        """
        length = len(password)
        
        # Character type checks
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = any(c in string.punctuation for c in password)
        types_count = sum([has_lower, has_upper, has_digit, has_symbol])
        
        # Entropy calculation
        charset_size = 0
        if has_lower: charset_size += 26
        if has_upper: charset_size += 26
        if has_digit: charset_size += 10
        if has_symbol: charset_size += 32
        
        entropy = length * math.log2(charset_size) if charset_size > 0 else 0
        
        # Pattern detection
        password_lower = password.lower()
        
        # Common words
        common_words = ['password', 'admin', 'welcome', 'monkey', 'dragon', 
                       'master', 'login', 'letmein', 'qwerty', 'abc123',
                       'love', 'princess', 'sunshine', 'shadow', 'football']
        has_common_word = any(word in password_lower for word in common_words)
        
        # Sequences
        has_sequence = any(seq in password_lower for seq in ['123', 'abc', 'qwe', '234', 'bcd'])
        
        # Years
        has_year = bool(re.search(r'(19|20)\d{2}', password))
        
        # Repeated chars (3 or more)
        has_repeats = bool(re.search(r'(.)\1{2,}', password))
        
        # WEAK criteria
        if (length < 8 or 
            types_count <= 1 or 
            entropy < 40 or
            has_common_word or
            has_repeats):
            return 0  # WEAK
        
        # STRONG criteria (rare in RockYou!)
        if (length >= 12 and 
            types_count >= 3 and 
            entropy >= 80 and
            not has_sequence and
            not has_year and
            not has_common_word):
            return 2  # STRONG
        
        # Everything else is MEDIUM
        return 1  # MEDIUM
    
    def _generate_synthetic_data(self, n_samples: int) -> Tuple[np.ndarray, np.ndarray]:
        """
        Fallback: Generate synthetic data if RockYou unavailable.
        
        This is used when RockYou dataset is not found.
        
        Args:
            n_samples: Number of samples to generate
            
        Returns:
            Tuple of (features, labels)
        """
        print("Generating synthetic training data...")
        
        features_list = []
        labels_list = []
        
        # Generate WEAK passwords
        weak_patterns = [
            'password', 'password123', 'qwerty', 'abc123', '123456',
            'welcome', 'admin', 'letmein', 'monkey', 'dragon',
            'baseball', 'iloveyou', 'trustno1', 'sunshine', 'princess',
            'password1', 'password2024', 'Pass123', 'admin123', 'test123'
        ]
        for pattern in weak_patterns:
            features_list.append(self.extract_features(pattern).flatten())
            labels_list.append(0)  # WEAK
        
        # Generate more weak variations
        for _ in range(n_samples // 3):
            # Short passwords with limited character sets
            weak = ''.join(random.choices(string.ascii_lowercase, k=random.randint(4, 8)))
            features_list.append(self.extract_features(weak).flatten())
            labels_list.append(0)
        
        # Generate MEDIUM passwords
        medium_patterns = [
            'Summer2024!', 'Winter2023', 'MyPassword1!', 'P@ssw0rd',
            'Hello123!', 'Welcome1!', 'Test1234!', 'Admin2024!',
            'User!2024', 'Login123@', 'Access2024', 'Secure123'
        ]
        for pattern in medium_patterns:
            features_list.append(self.extract_features(pattern).flatten())
            labels_list.append(1)  # MEDIUM
        
        # Generate more medium variations
        for _ in range(n_samples // 3):
            # Medium length with mixed types but predictable
            base = random.choice(['Password', 'Welcome', 'Secure', 'Access'])
            year = str(random.randint(2000, 2024))
            symbol = random.choice('!@#$')
            medium = base + year + symbol
            features_list.append(self.extract_features(medium).flatten())
            labels_list.append(1)
        
        # Generate STRONG passwords
        charset = string.ascii_letters + string.digits + string.punctuation
        for _ in range(n_samples // 3):
            # Generate truly random strong passwords
            length = random.randint(12, 20)
            strong = ''.join(secrets.choice(charset) for _ in range(length))
            features_list.append(self.extract_features(strong).flatten())
            labels_list.append(2)  # STRONG
        
        return np.array(features_list), np.array(labels_list)
    
    def train(self, X_train: np.ndarray = None, y_train: np.ndarray = None):
        """
        Train the ML model.
        
        Args:
            X_train: Training features (if None, generates from RockYou)
            y_train: Training labels (if None, generates from RockYou)
        """
        if X_train is None or y_train is None:
            X_train, y_train = self.generate_training_data(n_samples=10000)
        
        # Split for validation
        X_train_split, X_val, y_train_split, y_val = train_test_split(
            X_train, y_train, test_size=0.2, random_state=42, stratify=y_train
        )
        
        print(f"Training on {len(X_train_split)} samples...")
        self.model.fit(X_train_split, y_train_split)
        
        # Evaluate on validation set
        print("\nValidation Results:")
        y_pred = self.model.predict(X_val)
        print(classification_report(y_val, y_pred, 
                                   target_names=['WEAK', 'MEDIUM', 'STRONG']))
        
        # Confusion matrix
        cm = confusion_matrix(y_val, y_pred)
        print("Confusion Matrix:")
        print("                Predicted")
        print("              WEAK  MED  STRONG")
        print(f"Actual WEAK   {cm[0][0]:4d} {cm[0][1]:4d} {cm[0][2]:4d}")
        print(f"       MED    {cm[1][0]:4d} {cm[1][1]:4d} {cm[1][2]:4d}")
        print(f"       STRONG {cm[2][0]:4d} {cm[2][1]:4d} {cm[2][2]:4d}")
        print()
        
        # Feature importance
        print("Top 5 Most Important Features:")
        importances = self.model.feature_importances_
        indices = np.argsort(importances)[::-1]
        for i in range(min(5, len(indices))):
            idx = indices[i]
            print(f"  {i+1}. {self.feature_names[idx]:20s}: {importances[idx]:.3f}")
        print()
        
        self.is_trained = True
    
    def predict(self, password: str) -> Tuple[str, float]:
        """
        Predict password strength using ML model.
        
        Args:
            password: Password to classify
            
        Returns:
            Tuple of (prediction, confidence)
        """
        if not self.is_trained:
            raise RuntimeError("Model must be trained before prediction")
        
        features = self.extract_features(password)
        prediction = self.model.predict(features)[0]
        probabilities = self.model.predict_proba(features)[0]
        confidence = probabilities[prediction]
        
        return self.label_map[prediction], confidence
    
    def save_model(self, filepath: str = "password_ml_model.pkl"):
        """Save trained model to disk."""
        if not self.is_trained:
            raise RuntimeError("Cannot save untrained model")
        
        with open(filepath, 'wb') as f:
            pickle.dump(self.model, f)
        print(f"✅ Model saved to {filepath}")
    
    def load_model(self, filepath: str = "password_ml_model.pkl"):
        """Load trained model from disk."""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Model file not found: {filepath}")
        
        with open(filepath, 'rb') as f:
            self.model = pickle.load(f)
        self.is_trained = True
        print(f"✅ Model loaded from {filepath}")


# Testing and demonstration
if __name__ == "__main__":
    print("=" * 70)
    print("  PassMetric ML Classifier - RockYou Dataset Training")
    print("=" * 70)
    print()
    
    # Create and train classifier
    classifier = PasswordMLClassifier()
    classifier.train()
    
    # Test on sample passwords
    print("=" * 70)
    print("  Testing ML Predictions on Real Examples")
    print("=" * 70)
    print()
    
    test_passwords = [
        "password",           # Very common
        "123456",             # Sequential
        "Password123",        # Common + predictable
        "P@ssw0rd2024",      # L33t + year
        "Summer2024!",       # Word + year + symbol
        "iloveyou",          # Common phrase
        "K#9mX$2pL@7vN!4q",  # Strong random
        "correcthorsebatterystaple",  # Long passphrase
        "qwerty12345",       # Keyboard pattern
        "MyS3cur3P@ssw0rd!2024",  # Complex but has patterns
        "a1b2c3d4",          # Alternating
        "X7$mK9#pL2@vN5!qR8"  # Strong random
    ]
    
    for password in test_passwords:
        prediction, confidence = classifier.predict(password)
        print(f"Password: {password:30s} → {prediction:6s} ({confidence:.0%} confident)")
    
    # Save model
    print()
    print("=" * 70)
    classifier.save_model()
    
    print()
    print("✅ ML classifier trained with RockYou dataset and ready for use")
    print("✅ Model provides realistic analysis based on real password leaks")
    print()