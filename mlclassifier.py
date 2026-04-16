import random
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import string
import re
from typing import List, Tuple
import pickle
import os
import secrets
import math

class PasswordMLClassifier:
    def __init__(self):
        self.model = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42, class_weight='balanced')
        self.is_trained = False
        self.feature_names = [
            'length',
            'has_lowercase',
            'has_uppercase',
            'has_digits',
            'has_symbols',
            'entropy',
            'unique_char_ratio',
            'has_repeats',
            'has_common_words',
            'has_keyboard_patterns',
            'has_years'
        ]
        self.label_mapping = {0: 'WEAK', 1: 'MEDIUM', 2: 'STRONG'}

    def _extract_features(self, password: str) -> np.ndarray:
        features = []

        features.append(1 if any(c.islower() for c in password) else 0)
        features.append(1 if any(c.isupper() for c in password) else 0)
        features.append(1 if any(c.isdigit() for c in password) else 0)
        features.append(1 if any(c in string.punctuation for c in password) else 0)

        # Length feature
        if len(password) > 0:
            unique_ratio = len(set(password)) / len(password)
        else:
            unique_ratio = 0
        features.append(unique_ratio)
        
        # Entropy estimation
        charset_size = 0
        if any(c.islower() for c in password):
            charset_size += 26
        if any(c.isupper() for c in password):
            charset_size += 26
        if any(c.isdigit() for c in password):
            charset_size += 10
        if any(c in string.punctuation for c in password):
            charset_size += 32
        
        
        import math
        if charset_size > 0 and len(password) > 0:
            entropy = len(password) * math.log2(charset_size)
        else:
            entropy = 0
        features.append(entropy)
        
        
        # Check for common words and patterns
        common_words = ['password', 'welcome', 'admin', 'user', 'test', 'login', 'love', 'summer']
        has_common = 1 if any(word in password.lower() for word in common_words) else 0
        features.append(has_common)
        
        # Check for keyboard patterns 
        sequences = ['abc', '123', 'qwe']
        has_seq = 1 if any(seq in password.lower() for seq in sequences) else 0
        features.append(has_seq)
        
       # Check for repeated patterns (e.g., 'abcabc', '123123')
        has_pattern = 0
        if len(password) >= 4:
            for i in range(2, len(password) // 2 + 1):
                if password[:i] * (len(password) // i) == password:
                    has_pattern = 1
                    break
        features.append(has_pattern)
        
        # Check for years (e.g., '2020', '1999')
        year_pattern = r'(19\d{2}|20\d{2})'
        has_year = 1 if re.search(year_pattern, password) else 0
        features.append(has_year)
        
        # Check for repeated characters (e.g., 'aa', '111')
        has_repeats = 0
        for i in range(1, len(password)):
            if password[i] == password[i-1]:
                has_repeats = 1
                break
        features.append(has_repeats)
        
        # Count character types
        types_count = sum([
            any(c.islower() for c in password),
            any(c.isupper() for c in password),
            any(c.isdigit() for c in password),
            any(c in string.punctuation for c in password)
        ])
        features.append(types_count)
        
        return np.array(features).reshape(1, -1)
    
    def generate_training_data(self, n_samples: int = 1000) -> Tuple[np.ndarray, np.ndarray]:
        features_list = []
        labels_list = []

        # Look for rockyou.txt alongside this file in backend/
        rockyou_path = os.path.join(os.path.dirname(__file__), 'rockyou.txt')

        #check if rockyou.txt exists
        if not os.path.exists(rockyou_path):
            raise FileNotFoundError("RockYou dataset not found")
        

        #
        weak_target = int(n_samples * 0.4)
        medium_target = int(n_samples * 0.3)
        strong_target = n_samples - weak_target - medium_target

        weak_count = 0
        medium_count = 0

        # Load from RockYou and auto-label
        try:
            with open(rockyou_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    
                    if weak_count >= weak_target and medium_count >= medium_target:
                        break
                    
                    password = line.strip()
                    if not password:
                        continue
                    
                    # Auto-label the password
                    label = self._auto_label_password(password)
                    
                    # Only include WEAK and MEDIUM from RockYou to avoid biasing the model with leaked strong passwords
                    if label == 0 and weak_count < weak_target:
                        features_list.append(self._extract_features(password).flatten())
                        labels_list.append(0)
                        weak_count += 1
                    elif label == 1 and medium_count < medium_target:
                        features_list.append(self._extract_features(password).flatten())
                        labels_list.append(1)
                        medium_count += 1

            
            print(f"Loaded {weak_count} WEAK passwords from RockYou")
            print(f"Loaded {medium_count} MEDIUM passwords from RockYou")
        
        except Exception as e:
            print(f"Error loading RockYou: {e}")

        
        charset = string.ascii_letters + string.digits + string.punctuation
        for _ in range(strong_target):
            length = random.randint(12, 20)
            strong = ''.join(secrets.choice(charset) for _ in range(length))
            features_list.append(self._extract_features(strong).flatten())
            labels_list.append(2)  # STRONG
        
        print(f"Generated {strong_target} STRONG passwords")
        
        # Shuffle the data
        combined = list(zip(features_list, labels_list))
        random.shuffle(combined)
        features_list, labels_list = zip(*combined)
        
        print(f"\nFinal Dataset:")
        print(f"   WEAK:   {labels_list.count(0):5d} ({labels_list.count(0)/len(labels_list)*100:.1f}%)")
        print(f"   MEDIUM: {labels_list.count(1):5d} ({labels_list.count(1)/len(labels_list)*100:.1f}%)")
        print(f"   STRONG: {labels_list.count(2):5d} ({labels_list.count(2)/len(labels_list)*100:.1f}%)")
        print(f"   Total:  {len(labels_list):5d}\n")
        
        return np.array(features_list), np.array(labels_list)
    
    def _auto_label_password(self, password: str) -> int:
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
    
    
    
    def train(self, X_train: np.ndarray = None, y_train: np.ndarray = None):
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
        if not self.is_trained:
            raise RuntimeError("Model must be trained before prediction")
        
        features = self._extract_features(password)
        prediction = self.model.predict(features)[0]
        probabilities = self.model.predict_proba(features)[0]
        confidence = probabilities[prediction]
        
        return self.label_mapping[prediction], confidence