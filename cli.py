"""
PassMetric - Complete Password Manager CLI
Integrates all features: Vault, Analysis, Generation, ML Classifier
"""

import sys
import os
from getpass import getpass
from typing import Optional
from datetime import datetime

from backend.vault import PasswordVault, VaultEntry
from backend.combinedAnalyzer import CombinedPasswordAnalyzer
from backend.passGen import PasswordRequirements


class PassMetricCompleteCLI:
    """Complete command-line interface for PassMetric password manager."""
    
    def __init__(self):
        """Initialize the CLI."""
        self.vault = PasswordVault("passmetric_vault.enc")
        self.analyzer = CombinedPasswordAnalyzer()
        self.running = True
    
    def clear_screen(self):
        """Clear the terminal screen."""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def print_header(self):
        """Print the application header."""
        print("="*70)
        print("                      PassMetric v1.0                            ")
        print("          Complete Password Manager & Security Analyzer          ")
        print("="*70)
        print()
    
    def print_status(self):
        """Print current status."""
        vault_status = "🔓 Unlocked" if self.vault.is_unlocked else "🔒 Locked"
        ml_status = "✅ Trained" if self.analyzer.ml_classifier.is_trained else "⚠️  Not Trained"
        
        print(f"Vault: {vault_status} | ML Classifier: {ml_status}")
        if self.vault.is_unlocked:
            entry_count = len(self.vault.get_all_entries())
            print(f"Stored Passwords: {entry_count}")
    
    def print_main_menu(self):
        """Print the main menu."""
        print("\n" + "-"*70)
        print("MAIN MENU")
        print("-"*70)
        
        if not self.vault.vault_exists():
            print("⚠️  No vault found - Create one first!")
            print()
            print("1. Create New Vault")
            print("2. Password Analysis & Generation")
            print("3. ML Model Training")
            print("4. Help")
            print("5. Exit")
        elif not self.vault.is_unlocked:
            print("🔒 Vault is locked - Unlock to access passwords")
            print()
            print("1. Unlock Vault")
            print("2. Password Analysis & Generation")
            print("3. ML Model Training")
            print("4. Help")
            print("5. Exit")
        else:
            print("✅ Vault is unlocked")
            print()
            print("VAULT OPERATIONS:")
            print("  1. View All Passwords")
            print("  2. Add New Password")
            print("  3. Search Passwords")
            print("  4. Update Password")
            print("  5. Delete Password")
            print("  6. Password Health Audit")
            print("  7. Lock Vault")
            print()
            print("PASSWORD TOOLS:")
            print("  8. Generate Secure Password")
            print("  9. Analyze Password Strength")
            print("  10. Get Password Suggestions")
            print("  11. Compare Passwords")
            print()
            print("SYSTEM:")
            print("  12. Train ML Model")
            print("  13. Help")
            print("  14. Exit")
        
        print("-"*70)
    
    def get_user_choice(self, prompt: str = "Enter your choice: ") -> str:
        """Get user input."""
        try:
            return input(prompt).strip()
        except (KeyboardInterrupt, EOFError):
            print("\n\nExiting...")
            sys.exit(0)
    
    # ==================== VAULT OPERATIONS ====================
    
    def create_vault_menu(self):
        """Create a new vault."""
        print("\n" + "="*70)
        print("  CREATE NEW VAULT")
        print("="*70)
        
        print("\nYour vault will be encrypted with a master password.")
        print("⚠️  IMPORTANT: Choose a STRONG master password!")
        print("⚠️  If you forget it, your passwords CANNOT be recovered.")
        
        # Get master password
        while True:
            master_password = getpass("\nEnter master password: ")
            if not master_password:
                print("❌ Password cannot be empty")
                continue
            
            # Analyze master password strength
            analysis = self.analyzer.analyze_password(master_password, include_ml=False)
            strength = analysis['combined_strength']
            score = analysis['rule_based']['score']
            
            print(f"\nMaster Password Strength: {strength} ({score:.1f}/100)")
            
            if score < 60:
                print("⚠️  WARNING: This password is weak for a master password!")
                print("💡 Recommendation: Use at least 16 characters with mixed types")
                
                if self.get_user_choice("Use this password anyway? [y/N]: ").lower() != 'y':
                    continue
            
            # Confirm password
            confirm = getpass("Confirm master password: ")
            if master_password != confirm:
                print("❌ Passwords don't match. Try again.")
                continue
            
            break
        
        # Create vault
        if self.vault.create_vault(master_password):
            print("\n✅ Vault created successfully!")
            print(f"📁 Location: {self.vault.vault_file}")
        else:
            print("\n❌ Failed to create vault")
    
    def unlock_vault_menu(self):
        """Unlock the vault."""
        print("\n" + "="*70)
        print("  UNLOCK VAULT")
        print("="*70)
        
        master_password = getpass("\nEnter master password: ")
        
        if self.vault.unlock_vault(master_password):
            print("\n✅ Vault unlocked successfully!")
            entry_count = len(self.vault.get_all_entries())
            print(f"📊 {entry_count} password(s) stored")
        else:
            print("\n❌ Failed to unlock vault")
            print("Incorrect master password or vault corrupted")
    
    def view_all_passwords_menu(self):
        """View all stored passwords."""
        print("\n" + "="*70)
        print("  ALL STORED PASSWORDS")
        print("="*70)
        
        entries = self.vault.get_all_entries()
        
        if not entries:
            print("\n📭 No passwords stored yet")
            return
        
        print(f"\nFound {len(entries)} password(s):\n")
        
        for i, entry in enumerate(entries, 1):
            print(f"{i}. {entry.website}")
            print(f"   Username: {entry.username}")
            print(f"   Password: {'*' * len(entry.password)} (hidden)")
            print(f"   Created: {entry.created_at[:10]}")
            if entry.notes:
                print(f"   Notes: {entry.notes}")
            print()
        
        # Option to reveal passwords
        if self.get_user_choice("Show passwords? [y/N]: ").lower() == 'y':
            print("\n" + "="*70)
            print("  REVEALED PASSWORDS")
            print("="*70)
            print()
            
            for i, entry in enumerate(entries, 1):
                print(f"{i}. {entry.website}")
                print(f"   Username: {entry.username}")
                print(f"   Password: {entry.password}")
                
                # Quick analysis
                analysis = self.analyzer.analyze_password(entry.password, include_ml=False)
                strength = analysis['combined_strength'].replace('_', ' ')
                score = analysis['rule_based']['score']
                
                if score < 40:
                    print(f"   ⚠️  Strength: {strength} ({score:.1f}/100) - WEAK!")
                elif score < 70:
                    print(f"   💡 Strength: {strength} ({score:.1f}/100)")
                else:
                    print(f"   ✅ Strength: {strength} ({score:.1f}/100)")
                print()
    
    def add_password_menu(self):
        """Add a new password to the vault."""
        print("\n" + "="*70)
        print("  ADD NEW PASSWORD")
        print("="*70)
        
        # Get details
        website = self.get_user_choice("\nWebsite/Service: ")
        if not website:
            print("❌ Website cannot be empty")
            return
        
        username = self.get_user_choice("Username/Email: ")
        if not username:
            print("❌ Username cannot be empty")
            return
        
        # Password options
        print("\nPassword Options:")
        print("1. Enter existing password")
        print("2. Generate new secure password")
        
        choice = self.get_user_choice("Choice: ")
        
        if choice == '2':
            # Generate password
            password = self.analyzer.generate_secure_password()
            print(f"\n✅ Generated: {password}")
            
            # Analyze it
            analysis = self.analyzer.analyze_password(password, include_ml=False)
            print(f"Strength: {analysis['combined_strength']} ({analysis['rule_based']['score']:.1f}/100)")
            
            if self.get_user_choice("\nUse this password? [Y/n]: ").lower() == 'n':
                password = getpass("Enter password manually: ")
        else:
            password = getpass("\nEnter password: ")
        
        if not password:
            print("❌ Password cannot be empty")
            return
        
        # Analyze password
        analysis = self.analyzer.analyze_password(password, include_ml=False)
        strength = analysis['combined_strength']
        score = analysis['rule_based']['score']
        
        print(f"\nPassword Strength: {strength} ({score:.1f}/100)")
        
        if score < 40:
            print("⚠️  WARNING: This is a weak password!")
            if analysis['rule_based']['issues']:
                print("Issues:")
                for issue in analysis['rule_based']['issues'][:3]:
                    print(f"  • {issue}")
            
            if self.get_user_choice("\nStore anyway? [y/N]: ").lower() != 'y':
                return
        
        notes = self.get_user_choice("Notes (optional): ")
        
        # Add to vault
        entry = self.vault.add_entry(website, username, password, notes)
        
        if entry:
            print(f"\n✅ Password saved for {website}")
            print(f"Entry ID: {entry.entry_id}")
        else:
            print("\n❌ Failed to save password")
    
    def search_passwords_menu(self):
        """Search for passwords."""
        print("\n" + "="*70)
        print("  SEARCH PASSWORDS")
        print("="*70)
        
        query = self.get_user_choice("\nSearch query: ")
        if not query:
            return
        
        results = self.vault.search_entries(query)
        
        if not results:
            print(f"\n📭 No passwords found matching '{query}'")
            return
        
        print(f"\n✅ Found {len(results)} result(s):\n")
        
        for i, entry in enumerate(results, 1):
            print(f"{i}. {entry.website}")
            print(f"   Username: {entry.username}")
            print(f"   Password: {'*' * len(entry.password)}")
            print(f"   Entry ID: {entry.entry_id}")
            if entry.notes:
                print(f"   Notes: {entry.notes}")
            print()
        
        # Option to reveal
        if self.get_user_choice("Reveal passwords? [y/N]: ").lower() == 'y':
            print()
            for entry in results:
                print(f"{entry.website}: {entry.password}")
    
    def update_password_menu(self):
        """Update an existing password."""
        print("\n" + "="*70)
        print("  UPDATE PASSWORD")
        print("="*70)
        
        # Show all entries
        entries = self.vault.get_all_entries()
        if not entries:
            print("\n📭 No passwords stored")
            return
        
        print("\nStored passwords:")
        for i, entry in enumerate(entries, 1):
            print(f"{i}. {entry.website} ({entry.username})")
        
        # Get selection
        try:
            choice = int(self.get_user_choice("\nSelect entry number (or 0 to cancel): "))
            if choice == 0:
                return
            if choice < 1 or choice > len(entries):
                print("❌ Invalid selection")
                return
            
            entry = entries[choice - 1]
        except ValueError:
            print("❌ Invalid input")
            return
        
        print(f"\nUpdating: {entry.website}")
        print("Leave blank to keep current value")
        
        # Get new values
        new_website = self.get_user_choice(f"Website [{entry.website}]: ") or None
        new_username = self.get_user_choice(f"Username [{entry.username}]: ") or None
        
        print("\nPassword options:")
        print("1. Keep current password")
        print("2. Enter new password")
        print("3. Generate new password")
        
        pwd_choice = self.get_user_choice("Choice [1]: ") or "1"
        
        new_password = None
        if pwd_choice == '2':
            new_password = getpass("New password: ")
        elif pwd_choice == '3':
            new_password = self.analyzer.generate_secure_password()
            print(f"Generated: {new_password}")
        
        new_notes = self.get_user_choice(f"Notes [{entry.notes}]: ") or None
        
        # Update entry
        if self.vault.update_entry(entry.entry_id, new_website, new_username, new_password, new_notes):
            print("\n✅ Password updated successfully")
        else:
            print("\n❌ Failed to update password")
    
    def delete_password_menu(self):
        """Delete a password."""
        print("\n" + "="*70)
        print("  DELETE PASSWORD")
        print("="*70)
        
        # Show all entries
        entries = self.vault.get_all_entries()
        if not entries:
            print("\n📭 No passwords stored")
            return
        
        print("\nStored passwords:")
        for i, entry in enumerate(entries, 1):
            print(f"{i}. {entry.website} ({entry.username})")
        
        # Get selection
        try:
            choice = int(self.get_user_choice("\nSelect entry to delete (or 0 to cancel): "))
            if choice == 0:
                return
            if choice < 1 or choice > len(entries):
                print("❌ Invalid selection")
                return
            
            entry = entries[choice - 1]
        except ValueError:
            print("❌ Invalid input")
            return
        
        # Confirm deletion
        print(f"\n⚠️  About to delete: {entry.website} ({entry.username})")
        if self.get_user_choice("Are you sure? [y/N]: ").lower() != 'y':
            print("Cancelled")
            return
        
        # Delete entry
        if self.vault.delete_entry(entry.entry_id):
            print("\n✅ Password deleted")
        else:
            print("\n❌ Failed to delete password")
    
    def password_health_audit_menu(self):
        """Audit all passwords for security issues."""
        print("\n" + "="*70)
        print("  PASSWORD HEALTH AUDIT")
        print("="*70)
        
        entries = self.vault.get_all_entries()
        
        if not entries:
            print("\n📭 No passwords to audit")
            return
        
        print(f"\n🔍 Analyzing {len(entries)} password(s)...\n")
        
        weak_passwords = []
        reused_passwords = {}
        old_passwords = []
        
        # Analyze each password
        for entry in entries:
            analysis = self.analyzer.analyze_password(entry.password, include_ml=self.analyzer.ml_classifier.is_trained)
            score = analysis['rule_based']['score']
            strength = analysis['combined_strength']
            
            # Check for weak passwords
            if score < 60:
                weak_passwords.append({
                    'entry': entry,
                    'score': score,
                    'strength': strength,
                    'issues': analysis['rule_based']['issues']
                })
            
            # Check for reuse
            if entry.password in reused_passwords:
                reused_passwords[entry.password].append(entry.website)
            else:
                reused_passwords[entry.password] = [entry.website]
        
        # Calculate overall health score
        total_score = sum([self.analyzer.analyze_password(e.password, include_ml=False)['rule_based']['score'] for e in entries])
        avg_score = total_score / len(entries) if entries else 0
        
        reuse_penalty = len([pwd for pwd, sites in reused_passwords.items() if len(sites) > 1]) * 10
        health_score = max(0, avg_score - reuse_penalty)
        
        # Display results
        print("="*70)
        print("  AUDIT RESULTS")
        print("="*70)
        
        print(f"\n📊 Overall Health Score: {health_score:.1f}/100")
        
        if health_score >= 80:
            print("✅ Excellent password hygiene!")
        elif health_score >= 60:
            print("💡 Good, but room for improvement")
        elif health_score >= 40:
            print("⚠️  Needs attention")
        else:
            print("❌ Critical - Immediate action needed!")
        
        # Weak passwords
        if weak_passwords:
            print(f"\n⚠️  {len(weak_passwords)} WEAK PASSWORD(S):")
            for wp in weak_passwords:
                print(f"\n  • {wp['entry'].website}")
                print(f"    Strength: {wp['strength']} ({wp['score']:.1f}/100)")
                if wp['issues']:
                    print(f"    Issues: {wp['issues'][0]}")
        else:
            print("\n✅ No weak passwords found")
        
        # Reused passwords
        reused = [(pwd, sites) for pwd, sites in reused_passwords.items() if len(sites) > 1]
        if reused:
            print(f"\n⚠️  {len(reused)} REUSED PASSWORD(S):")
            for pwd, sites in reused:
                print(f"\n  Password used for: {', '.join(sites)}")
        else:
            print("\n✅ No password reuse detected")
        
        # Recommendations
        print("\n💡 RECOMMENDATIONS:")
        if weak_passwords:
            print("  • Update weak passwords immediately")
        if reused:
            print("  • Use unique passwords for each service")
        if health_score < 80:
            print("  • Aim for passwords with 80+ strength score")
            print("  • Use the password generator for new passwords")
        
        print()
    
    def lock_vault_menu(self):
        """Lock the vault."""
        print("\n🔒 Locking vault...")
        self.vault.lock_vault()
        print("✅ Vault locked securely")
    
    # ==================== PASSWORD TOOLS ====================
    
    def generate_password_menu(self):
        """Generate a secure password."""
        print("\n" + "="*70)
        print("  GENERATE SECURE PASSWORD")
        print("="*70)
        
        print("\nPassword Type:")
        print("1. Random Password (high security)")
        print("2. Passphrase (memorable)")
        
        choice = self.get_user_choice("Choice [1]: ") or "1"
        
        if choice == '2':
            # Generate passphrase
            word_count = int(self.get_user_choice("Number of words [4]: ") or "4")
            separator = self.get_user_choice("Separator ['-']: ") or "-"
            capitalize = self.get_user_choice("Capitalize? [Y/n]: ").lower() != 'n'
            add_number = self.get_user_choice("Add number? [Y/n]: ").lower() != 'n'
            
            try:
                passphrase = self.analyzer.generate_passphrase(
                    word_count=word_count,
                    separator=separator,
                    capitalize=capitalize,
                    add_number=add_number
                )
                
                print("\n" + "="*70)
                print(f"Generated Passphrase: {passphrase}")
                print("="*70)
                
                # Analyze
                analysis = self.analyzer.analyze_password(passphrase, include_ml=False)
                print(f"\nStrength: {analysis['combined_strength']} ({analysis['rule_based']['score']:.1f}/100)")
                print(f"Entropy: {analysis['rule_based']['entropy_bits']:.1f} bits")
                
            except Exception as e:
                print(f"\n❌ Error: {e}")
        
        else:
            # Generate random password
            length = int(self.get_user_choice("\nLength [16]: ") or "16")
            
            print("\nInclude:")
            include_upper = self.get_user_choice("Uppercase? [Y/n]: ").lower() != 'n'
            include_lower = self.get_user_choice("Lowercase? [Y/n]: ").lower() != 'n'
            include_digits = self.get_user_choice("Digits? [Y/n]: ").lower() != 'n'
            include_symbols = self.get_user_choice("Symbols? [Y/n]: ").lower() != 'n'
            exclude_similar = self.get_user_choice("Exclude similar (0,O,1,l,I)? [y/N]: ").lower() == 'y'
            
            try:
                req = PasswordRequirements(
                    length=length,
                    include_uppercase=include_upper,
                    include_lowercase=include_lower,
                    include_digits=include_digits,
                    include_symbols=include_symbols,
                    exclude_similar=exclude_similar,
                    require_all_types=True
                )
                
                password = self.analyzer.generate_secure_password(req)
                
                print("\n" + "="*70)
                print(f"Generated Password: {password}")
                print("="*70)
                
                # Analyze
                analysis = self.analyzer.analyze_password(password, include_ml=False)
                print(f"\nStrength: {analysis['combined_strength']} ({analysis['rule_based']['score']:.1f}/100)")
                print(f"Entropy: {analysis['rule_based']['entropy_bits']:.1f} bits")
                
            except ValueError as e:
                print(f"\n❌ Error: {e}")
    
    def analyze_password_menu(self):
        """Analyze password strength."""
        print("\n" + "="*70)
        print("  ANALYZE PASSWORD STRENGTH")
        print("="*70)
        
        password = getpass("\nEnter password (hidden): ")
        
        if not password:
            print("❌ Password cannot be empty")
            return
        
        # Analyze
        analysis = self.analyzer.analyze_password(
            password,
            include_ml=self.analyzer.ml_classifier.is_trained
        )
        
        # Display results
        print("\n" + "="*70)
        print("  ANALYSIS RESULTS")
        print("="*70)
        
        print(f"\n{analysis['summary']}")
        
        rule = analysis['rule_based']
        print(f"\n📊 Rule-Based Analysis:")
        print(f"   Strength: {rule['strength'].replace('_', ' ')}")
        print(f"   Score: {rule['score']:.1f}/100")
        print(f"   Entropy: {rule['entropy_bits']:.1f} bits")
        print(f"   Diversity: {rule['character_diversity']} unique chars")
        
        if analysis['ml_based']:
            ml = analysis['ml_based']
            print(f"\n🤖 ML Prediction:")
            print(f"   {ml['prediction']} ({ml['confidence']:.0%} confidence)")
        
        if rule['issues']:
            print(f"\n❌ Critical Issues:")
            for issue in rule['issues']:
                print(f"   • {issue}")
        
        if rule['warnings']:
            print(f"\n⚠️  Warnings:")
            for warning in rule['warnings'][:5]:
                print(f"   • {warning}")
        
        if rule['recommendations']:
            print(f"\n💡 Recommendations:")
            for rec in rule['recommendations'][:5]:
                print(f"   • {rec}")
        
        print()
    
    def get_suggestions_menu(self):
        """Get password suggestions."""
        print("\n" + "="*70)
        print("  PASSWORD SUGGESTIONS")
        print("="*70)
        
        current = getpass("\nCurrent password (hidden): ")
        count = int(self.get_user_choice("Number of suggestions [3]: ") or "3")
        
        suggestions = self.analyzer.get_password_suggestions(current, count=count)
        
        print("\n" + "="*70)
        print("  SUGGESTED STRONGER PASSWORDS")
        print("="*70)
        
        for i, pwd in enumerate(suggestions, 1):
            print(f"\n{i}. {pwd}")
            
            analysis = self.analyzer.analyze_password(pwd, include_ml=False)
            strength = analysis['combined_strength'].replace('_', ' ')
            score = analysis['rule_based']['score']
            print(f"   {strength} ({score:.1f}/100)")
        
        print()
    
    def compare_passwords_menu(self):
        """Compare two passwords."""
        print("\n" + "="*70)
        print("  COMPARE PASSWORDS")
        print("="*70)
        
        pwd1 = getpass("\nFirst password (hidden): ")
        pwd2 = getpass("Second password (hidden): ")
        
        if not pwd1 or not pwd2:
            print("❌ Both passwords required")
            return
        
        comparison = self.analyzer.compare_passwords(pwd1, pwd2)
        
        print("\n" + "="*70)
        print("  COMPARISON RESULTS")
        print("="*70)
        
        print(f"\nPassword 1: {comparison['password1_score']:.1f}/100")
        print(f"Password 2: {comparison['password2_score']:.1f}/100")
        print(f"\n{comparison['explanation']}")
        
        if self.get_user_choice("\nShow detailed analysis? [y/N]: ").lower() == 'y':
            print("\n📊 PASSWORD 1:")
            self._show_brief_analysis(comparison['password1_analysis'])
            
            print("\n📊 PASSWORD 2:")
            self._show_brief_analysis(comparison['password2_analysis'])
        
        print()
    
    def _show_brief_analysis(self, analysis: dict):
        """Show brief analysis summary."""
        rule = analysis['rule_based']
        print(f"  Strength: {rule['strength']}")
        print(f"  Score: {rule['score']:.1f}/100")
        print(f"  Entropy: {rule['entropy_bits']:.1f} bits")
        if rule['issues']:
            print(f"  Issues: {rule['issues'][0]}")
    
    # ==================== SYSTEM ====================
    
    def train_ml_model_menu(self):
        """Train ML classifier."""
        print("\n" + "="*70)
        print("  TRAIN ML MODEL")
        print("="*70)
        
        print("\nThis trains the ML classifier using the RockYou dataset.")
        print("Ensure rockyou.txt is in the current directory.")
        print("\n⏱️  This may take a few minutes...")
        
        if self.get_user_choice("\nProceed? [y/N]: ").lower() != 'y':
            return
        
        try:
            self.analyzer.train_ml_model()
        except Exception as e:
            print(f"\n❌ Training failed: {e}")
    
    def show_help(self):
        """Display help."""
        print("\n" + "="*70)
        print("  PASSMETRIC HELP")
        print("="*70)
        
        print("""
PassMetric is a complete password manager with advanced security features.

VAULT FEATURES:
• Encrypted storage using AES-256-GCM + Argon2id
• Zero-knowledge architecture (passwords never leave your device)
• Create, read, update, delete password entries
• Search functionality
• Password health auditing

ANALYSIS FEATURES:
• Rule-based strength evaluation (transparent feedback)
• ML-powered classification (trained on real leaked passwords)
• Entropy calculation
• Pattern detection (keyboard patterns, sequences, l33t speak)
• Common password detection

GENERATION FEATURES:
• Cryptographically secure random passwords (CSPRNG)
• Memorable passphrases (EFF word list)
• Customizable requirements
• Instant strength analysis

SECURITY:
• Master password protects all data
• Argon2id key derivation (OWASP recommended)
• AES-256-GCM authenticated encryption
• Local storage only
• No cloud, no internet required

ML CLASSIFIER:
• Train with RockYou dataset (14.3M leaked passwords)
• Learns patterns from real password breaches
• Provides confidence scores

For more information, see the documentation.
        """)
        
        print("="*70)
    
    def run(self):
        """Run the main CLI loop."""
        self.clear_screen()
        self.print_header()
        self.print_status()
        
        while self.running:
            self.print_main_menu()
            choice = self.get_user_choice()
            
            # Different menus based on vault state
            if not self.vault.vault_exists():
                # No vault - limited options
                if choice == '1':
                    self.create_vault_menu()
                elif choice == '2':
                    self.analyze_password_menu()
                elif choice == '3':
                    self.train_ml_model_menu()
                elif choice == '4':
                    self.show_help()
                elif choice == '5':
                    print("\n👋 Goodbye!")
                    self.running = False
                else:
                    print("\n❌ Invalid choice")
            
            elif not self.vault.is_unlocked:
                # Vault exists but locked
                if choice == '1':
                    self.unlock_vault_menu()
                elif choice == '2':
                    self.analyze_password_menu()
                elif choice == '3':
                    self.train_ml_model_menu()
                elif choice == '4':
                    self.show_help()
                elif choice == '5':
                    print("\n👋 Goodbye!")
                    self.running = False
                else:
                    print("\n❌ Invalid choice")
            
            else:
                # Vault unlocked - full access
                if choice == '1':
                    self.view_all_passwords_menu()
                elif choice == '2':
                    self.add_password_menu()
                elif choice == '3':
                    self.search_passwords_menu()
                elif choice == '4':
                    self.update_password_menu()
                elif choice == '5':
                    self.delete_password_menu()
                elif choice == '6':
                    self.password_health_audit_menu()
                elif choice == '7':
                    self.lock_vault_menu()
                elif choice == '8':
                    self.generate_password_menu()
                elif choice == '9':
                    self.analyze_password_menu()
                elif choice == '10':
                    self.get_suggestions_menu()
                elif choice == '11':
                    self.compare_passwords_menu()
                elif choice == '12':
                    self.train_ml_model_menu()
                elif choice == '13':
                    self.show_help()
                elif choice == '14':
                    print("\n👋 Goodbye!")
                    self.running = False
                else:
                    print("\n❌ Invalid choice")
            
            if self.running and choice not in ['4', '7', '13', '14']:
                input("\nPress Enter to continue...")


# Entry point
if __name__ == "__main__":
    try:
        cli = PassMetricCompleteCLI()
        cli.run()
    except KeyboardInterrupt:
        print("\n\n👋 Goodbye!")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)