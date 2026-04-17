import secrets
import string
from typing import Optional, Set
from dataclasses import dataclass
import os

@dataclass
class PasswordRequirements:
    length: int = 16
    include_uppercase: bool = True
    include_lowercase: bool = True
    include_digits: bool = True
    include_symbols: bool = True
    exclude_similar: bool = False # Exclude characters like 'l', '1', 'I', 'O', '0' to avoid confusion
    require_all_types: bool = True # Ensure at least one character from each selected type is included
    custom_symbols: Optional[str] = None
    exclude_chars: Optional[str] = None

    def validate(self) -> tuple[bool, Optional[str]]: # Validate the password requirements and return a tuple of (is_valid, error_message)
        if self.length < 4:
            return False, "Password length must be at least 4 characters."
        
        if not (self.include_uppercase or self.include_lowercase or self.include_digits or self.include_symbols):
            return False, "At least one character type must be included."
        
        if self.require_all_types and sum([self.include_uppercase, self.include_lowercase, self.include_digits, self.include_symbols]) > self.length:
            return False, "Password length must be at least equal to the number of required character types."   

        return True, None
    
class PasswordGenerator:
        LOWERCASE = string.ascii_lowercase
        UPPERCASE = string.ascii_uppercase
        DIGITS = string.digits
        SYMBOL = string.punctuation

        SIMILAR_CHARACTERS = 'l1I0O'
        BASIC_SYMBOLS = '!@#$%^&*'
        EXTENDED_SYMBOLS = '!@#$%^&*()-_=+[]{}|;:,.<>?/~`'
        ALL_SYMBOLS = string.punctuation

        def __init__(self):
            self.wordlist = self._load_wordlist()
    
        def _load_wordlist(self) -> list[str]:
            wordlist_path = os.path.join(os.path.dirname(__file__), 'eff_large_wordlist.txt')
        
            if not os.path.exists(wordlist_path):
                raise FileNotFoundError(f"Wordlist not found at {wordlist_path}. Please download from https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt")
        
            with open(wordlist_path, 'r') as f:
                words = [line.strip().split('\t')[1] for line in f if line.strip()]
        
            return words

        def generate_password(self, requirements: Optional[PasswordRequirements] = None) -> str:
            if requirements is None:
                requirements = PasswordRequirements()

            is_valid, error_message = requirements.validate()
            if not is_valid:
                raise ValueError(f"Invalid password requirements: {error_message}")
            
            charset = self._build_charset(requirements) 

            if not charset:
                raise ValueError("No characters available to generate password based on the specified requirements.")
            
            if requirements.require_all_types:
                return self._generate_with_requirements(requirements, charset)
            else:
                return self._generate_random_password(requirements.length, charset)
            
        def _build_charset(self, requirements: PasswordRequirements) -> str:
            charset = ''
            if requirements.include_uppercase:
                charset += self.UPPERCASE
            if requirements.include_lowercase:
                charset += self.LOWERCASE
            if requirements.include_digits:
                charset += self.DIGITS
            if requirements.include_symbols:
                if requirements.custom_symbols:
                    charset += requirements.custom_symbols
                else:
                    charset += self.EXTENDED_SYMBOLS
            
            if requirements.exclude_similar:
                charset = ''.join(c for c in charset if c not in self.SIMILAR_CHARACTERS)
            
            if requirements.exclude_chars:
                charset = ''.join(c for c in charset if c not in requirements.exclude_chars)
            
            return charset
        
        def _generate_simple(self, length: int, charset: str) -> str:
            return ''.join(secrets.choice(charset) for _ in range(length))
        
        def _generate_with_requirements(self, requirements: PasswordRequirements, full_charset: str) -> str:
            password_chars = []
            remaining_length = requirements.length

            if requirements.include_lowercase:
                char_pool = self.LOWERCASE
                if requirements.exclude_similar:
                    char_pool = ''.join(c for c in char_pool if c not in self.SIMILAR_CHARACTERS)
                password_chars.append(secrets.choice(char_pool))
                remaining_length -= 1

            if requirements.include_uppercase:
                char_pool = self.UPPERCASE
                if requirements.exclude_similar:
                    char_pool = ''.join(c for c in char_pool if c not in self.SIMILAR_CHARACTERS)
                password_chars.append(secrets.choice(char_pool))
                remaining_length -= 1
            
            if requirements.include_digits:
                char_pool = self.DIGITS
                if requirements.exclude_similar:
                    char_pool = ''.join(c for c in char_pool if c not in self.SIMILAR_CHARACTERS)
                password_chars.append(secrets.choice(char_pool))
                remaining_length -= 1

            if requirements.include_symbols:
                if requirements.custom_symbols is not None:
                    char_pool = requirements.custom_symbols
                else:
                    char_pool = self.EXTENDED_SYMBOLS

                if requirements.exclude_similar:
                    char_pool = ''.join(c for c in char_pool if c not in self.SIMILAR_CHARACTERS)
                password_chars.append(secrets.choice(char_pool))
                remaining_length -= 1

            # Fill the rest of the password with random characters from the FULL available charset
            if remaining_length > 0:
                password_chars.extend(secrets.choice(full_charset) for _ in range(remaining_length))

            # Shuffle the list so it doesn't always start with lower -> upper -> digit -> special
            rng = secrets.SystemRandom()
            rng.shuffle(password_chars)

            return ''.join(password_chars)
        
        def generate_passphrase(self, word_count: int = 4, separator: str = "-", capitalize: bool = True, add_number: bool = True) -> str:
            if not self.wordlist:
                raise ValueError("Wordlist is empty. Cannot generate passphrase.")
         
            words = [secrets.choice(self.wordlist) for _ in range(word_count)]

            if capitalize:
                words = [word.capitalize() for word in words]

            passphrase = separator.join(words)

            if add_number:
                passphrase += str(secrets.randbelow(10000)) #

            return passphrase
    
        def generate_pin(self, length: int = 6) -> str:
            if length < 4:
                raise ValueError("PIN length must be at least 4 digits.")
        
        #ensure the first digit is not zero
            first_digit = secrets.choice(string.digits[1:])
            remaining_digits = ''.join(secrets.choice(string.digits) for _ in range(length - 1))
            return first_digit + remaining_digits
    
   