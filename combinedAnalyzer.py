"""
PassMetric Combined Password Analyzer
Integrates Password Generator, Evaluator, and ML Classifier
"""

import numpy as np
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
import random
import secrets
import string

# Import all components
from passGen import PasswordGenerator, PasswordRequirements
from passevaluator import PasswordEvaluator, EvaluationResult, StrengthLevel
from mlclassifier import PasswordMLClassifier


@dataclass
class CombinedAnalysis:
    """Complete password analysis combining all methods."""
    password_length: int
    rule_based: Dict
    ml_based: Optional[Dict]
    combined_strength: str
    details: Dict
    summary: str

# Combined Analyzer Class that integrates all components into a single interface for comprehensive password analysis and generation.
class CombinedPasswordAnalyzer:
    
    def __init__(self, model_path: str = 'password_ml_model.pkl'):
        """Initialize all components with auto-loading ML model."""
        self.evaluator = PasswordEvaluator()
        self.generator = PasswordGenerator()
        self.ml_classifier = PasswordMLClassifier()
        
        # ── Auto-load or auto-train the ML model ──
        self._model_path = model_path
        self._auto_load_ml_model()

    def _auto_load_ml_model(self):
        """Load saved model if it exists, otherwise train and save."""
        import os
        if os.path.exists(self._model_path):
            try:
                self.ml_classifier.load_model(self._model_path)
                print(f"[ML] Model loaded from {self._model_path}")
                return
            except Exception as e:
                print(f"[ML] Failed to load model: {e}")

        # Look for rockyou.txt alongside this file in backend/
        rockyou_path = os.path.join(os.path.dirname(__file__), 'rockyou.txt')
        if os.path.exists(rockyou_path):
            print("[ML] No saved model found. Training from RockYou dataset...")
            try:
                self.ml_classifier.train()
                self.ml_classifier.save_model(self._model_path)
                print(f"[ML] Model trained and saved to {self._model_path}")
            except Exception as e:
                print(f"[ML] Training failed: {e}. ML predictions unavailable.")
        else:
            print("[ML] No model or dataset found. ML predictions unavailable.")
    

    def analyze_password(self, password: str, include_ml: bool = None) -> Dict:
        if include_ml is None:
            include_ml = self.ml_classifier.is_trained
            
        # Rule-based evaluation (always works)
        rule_result = self.evaluator.evaluate_password(password)
        
        # ML prediction (if available and requested)
        ml_prediction = None
        ml_confidence = None
        if include_ml and self.ml_classifier.is_trained:
            try:
                ml_prediction, ml_confidence = self.ml_classifier.predict(password)
            except Exception as e:
                print(f"Warning: ML prediction failed: {e}")
        
        # Combine results
        combined_strength = self._determine_combined_strength(rule_result, ml_prediction)
        
        # Build comprehensive analysis
        analysis = {
            'password_length': len(password),
            
            'rule_based': {
                'strength': rule_result.strength_level.name,
                'score': rule_result.score,
                'entropy_bits': rule_result.entropy_bits,
                'character_diversity': rule_result.character_diversity,
                'issues': rule_result.issues,
                'warnings': rule_result.warnings,
                'recommendations': rule_result.recommendations
            },
            
            'ml_based': {
                'prediction': ml_prediction,
                'confidence': ml_confidence
            } if ml_prediction else None,
            
            'combined_strength': combined_strength,
            
            'details': rule_result.details,
            
            'summary': self._generate_summary(
                len(password),
                rule_result.strength_level.name,
                rule_result.score,
                rule_result.entropy_bits,
                ml_prediction,
                combined_strength
            )
        }
        
        return analysis
    
    # Combine rule-based and ML assessments conservatively to ensure users get a safe evaluation. 
    def _determine_combined_strength(self, rule_result: EvaluationResult, 
                                     ml_prediction: Optional[str]) -> str:

        # Map strength levels to numeric values for comparison
        strength_values = {
            'VERY_WEAK': 0,
            'WEAK': 1,
            'MEDIUM': 2,
            'STRONG': 3,
            'VERY_STRONG': 4
        }
        
        rule_strength = rule_result.strength_level.name
        rule_value = strength_values.get(rule_strength, 0)
        
        # If no ML prediction, use rule-based only
        if ml_prediction is None:
            return rule_strength
        
        # Map ML prediction to strength values
        ml_strength_map = {
            'WEAK': 1,      # ML WEAK → Rule WEAK
            'MEDIUM': 2,    # ML MEDIUM → Rule MEDIUM
            'STRONG': 3     # ML STRONG → Rule STRONG
        }
        ml_value = ml_strength_map.get(ml_prediction, 0)
        
        # Take the minimum (conservative approach)
        combined_value = min(rule_value, ml_value)
        
        # Map back to strength name
        value_to_strength = {v: k for k, v in strength_values.items()}
        return value_to_strength.get(combined_value, 'VERY_WEAK')
    
    def _generate_summary(self, length: int, rule_strength: str, score: float,
                         entropy: float, ml_prediction: Optional[str],
                         combined_strength: str) -> str:
        summary_parts = [
            f"Password Strength: {combined_strength.replace('_', ' ').title()}",
            f"Score: {score:.1f}/100",
            f"Entropy: {entropy:.1f} bits",
            f"Length: {length} chars"
        ]
        
        if ml_prediction:
            summary_parts.append(f"ML Prediction: {ml_prediction}")
        
        return " | ".join(summary_parts)
    
    def generate_secure_password(self, 
                                requirements: Optional[PasswordRequirements] = None) -> str:

        return self.generator.generate_password(requirements)
    
    def generate_passphrase(self, word_count: int = 4, separator: str = "-",
                           capitalize: bool = True, add_number: bool = True) -> str:

        return self.generator.generate_passphrase(word_count, separator, capitalize, add_number)
    
    def get_password_suggestions(self, current_password: str, count: int = 3) -> List[str]:

        suggestions = []
        
        # Analyze current password to understand weaknesses
        analysis = self.analyze_password(current_password, include_ml=False)
        
        for _ in range(count):
            # Generate strong random password
            req = PasswordRequirements(
                length=random.randint(14, 18),
                include_lowercase=True,
                include_uppercase=True,
                include_digits=True,
                include_symbols=True,
                exclude_similar=True,
                require_all_types=True
            )
            suggestion = self.generator.generate_password(req)
            suggestions.append(suggestion)
        
        return suggestions
    
    def compare_passwords(self, password1: str, password2: str) -> Dict:

        analysis1 = self.analyze_password(password1, include_ml=False)
        analysis2 = self.analyze_password(password2, include_ml=False)
        
        score1 = analysis1['rule_based']['score']
        score2 = analysis2['rule_based']['score']
        
        if score1 > score2:
            winner = 'password1'
            explanation = f"Password 1 is stronger ({score1:.1f} vs {score2:.1f})"
        elif score2 > score1:
            winner = 'password2'
            explanation = f"Password 2 is stronger ({score2:.1f} vs {score1:.1f})"
        else:
            winner = 'tie'
            explanation = f"Both passwords have equal strength ({score1:.1f})"
        
        return {
            'winner': winner,
            'password1_score': score1,
            'password2_score': score2,
            'explanation': explanation,
            'password1_analysis': analysis1,
            'password2_analysis': analysis2
        }
    
    def train_ml_model(self, n_samples: int = 10000):
        print("\n" + "="*70)
        print("  Training ML Classifier")
        print("="*70)
        print()
        
        self.ml_classifier.train()
        
        # Save the trained model
        try:
            self.ml_classifier.save_model("password_ml_model.pkl")
        except Exception as e:
            print(f"Warning: Could not save model: {e}")
        
        print("\nML classifier trained and ready for use")


# Demo and testing
if __name__ == "__main__":
    print("="*70)
    print("  PassMetric Combined Password Analyzer - Demo")
    print("="*70)
    print()
    
    # Create analyzer
    analyzer = CombinedPasswordAnalyzer()
    
    # Test password analysis
    print("Testing Password Analysis:")
    print("-"*70)
    
    test_passwords = [
        "password",
        "Password123",
        "P@ssw0rd2024",
        "Summer2024!",
        "K#9mX$2pL@7vN!4q",
        "correcthorsebatterystaple"
    ]
    
    for pwd in test_passwords:
        analysis = analyzer.analyze_password(pwd, include_ml=False)
        print(f"\nPassword: {pwd}")
        print(f"  Strength: {analysis['combined_strength']}")
        print(f"  Score: {analysis['rule_based']['score']:.1f}/100")
        print(f"  Entropy: {analysis['rule_based']['entropy_bits']:.1f} bits")
        if analysis['rule_based']['issues']:
            print(f"  Issues: {', '.join(analysis['rule_based']['issues'][:2])}")
    
    # Test password generation
    print("\n" + "="*70)
    print("Testing Password Generation:")
    print("-"*70)
    
    # Generate strong password
    strong_pwd = analyzer.generate_secure_password()
    print(f"\nGenerated Password: {strong_pwd}")
    
    # Analyze it immediately
    analysis = analyzer.analyze_password(strong_pwd, include_ml=False)
    print(f"Strength: {analysis['combined_strength']} ({analysis['rule_based']['score']:.1f}/100)")
    
    # Generate passphrase
    passphrase = analyzer.generate_passphrase(word_count=4)
    print(f"\nGenerated Passphrase: {passphrase}")
    
    # Test suggestions
    print("\n" + "="*70)
    print("Testing Password Suggestions:")
    print("-"*70)
    
    weak_password = "password123"
    suggestions = analyzer.get_password_suggestions(weak_password, count=3)
    print(f"\nSuggestions for '{weak_password}':")
    for i, suggestion in enumerate(suggestions, 1):
        print(f"  {i}. {suggestion}")
    
    print("\n" + "="*70)
    print("✅ Combined Analyzer Demo Complete")
    print("="*70)