
import re
import math
from typing import Dict, List, Any
from rapidfuzz import fuzz


class PasswordChecker:
    # Character set sizes for entropy calculation
    LOWERCASE = 26
    UPPERCASE = 26
    DIGITS = 10
    SPECIAL = 32  # Common special characters
    
    # Time to crack calculation (assumes 1 billion guesses per second)
    GUESSES_PER_SECOND = 1_000_000_000
    SECONDS_PER_YEAR = 31_536_000
    
    def __init__(self, common_passwords_file: str = "data/common_passwords.txt"):
        # Initialize checker with common passwords list
        self.common_passwords = self._load_common_passwords(common_passwords_file)
    
    def _load_common_passwords(self, filepath: str) -> set:
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return set(line.strip().lower() for line in f)
        except FileNotFoundError:
            print(f"Warning: {filepath} not found. Common password check disabled.")
            return set()
    
    def check_password(self, password: str) -> Dict[str, Any]:
        if not password:
            return self._weak_result("Password cannot be empty")
        
        # Calculate all criteria
        length_score = self._check_length(password)
        diversity_score = self._check_character_diversity(password)
        entropy = self._calculate_entropy(password)
        pattern_score = self._check_patterns(password)
        dictionary_score = self._check_dictionary(password)
        
        # Calculate weighted overall score (out of 100)
        overall_score = (
            length_score * 0.25 +
            diversity_score * 0.25 +
            pattern_score * 0.20 +
            dictionary_score * 0.20 +
            self._entropy_to_score(entropy) * 0.10
        )
        
        # Determine strength level
        if overall_score >= 80:
            strength = "STRONG"
        elif overall_score >= 60:
            strength = "MEDIUM"
        elif overall_score >= 40:
            strength = "WEAK"
        else:
            strength = "VERY WEAK"
        
        # Calculate time to crack
        time_to_crack = self._calculate_time_to_crack(entropy)
        
        # Generate feedback
        feedback = self._generate_feedback(password, length_score, diversity_score, 
                                          pattern_score, dictionary_score)
        
        return {
            "password": "***" if len(password) > 0 else "",
            "overall_strength": strength,
            "score": round(overall_score),
            "entropy_bits": round(entropy, 2),
            "time_to_crack": time_to_crack,
            "feedback": feedback,
            "criteria": {
                "length": {"status": "PASS" if self._length_check(password) else "FAIL"},
                "uppercase": {"status": "PASS" if self._has_uppercase(password) else "FAIL"},
                "lowercase": {"status": "PASS" if self._has_lowercase(password) else "FAIL"},
                "numbers": {"status": "PASS" if self._has_numbers(password) else "FAIL"},
                "special_chars": {"status": "PASS" if self._has_special_chars(password) else "FAIL"},
                "no_dictionary_words": {"status": "PASS" if dictionary_score > 50 else "FAIL"},
                "no_keyboard_patterns": {"status": "PASS" if pattern_score > 70 else "FAIL"},
                "no_sequential_chars": {"status": "PASS" if not self._has_sequential_chars(password) else "FAIL"},
            }
        }
    
    # ==================== LENGTH CHECKS ====================
    
    def _length_check(self, password: str) -> bool:
        # Meet minimum length requirement of 12 chars recommended 
        return len(password) >= 12
    
    def _check_length(self, password: str) -> float:
        # Score based on password length (0-100)
        length = len(password)
        if length < 6:
            return 0
        elif length < 8:
            return 20
        elif length < 12:
            return 50
        elif length < 16:
            return 75
        else:
            return 100
    
    # ==================== CHARACTER DIVERSITY ====================
    
    def _has_uppercase(self, password: str) -> bool:
        # Check for uppercase letters
        return any(c.isupper() for c in password)
    
    def _has_lowercase(self, password: str) -> bool:
        # Check for lowercase letters
        return any(c.islower() for c in password)
    
    def _has_numbers(self, password: str) -> bool:
        # Check for digits
        return any(c.isdigit() for c in password)
    
    def _has_special_chars(self, password: str) -> bool:
        # Check for special characters
        special = re.compile(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]')
        return bool(special.search(password))
    
    def _check_character_diversity(self, password: str) -> float:
        # Score based on character variety (0-100)
        diversity_count = 0
        
        if self._has_uppercase(password):
            diversity_count += 1
        if self._has_lowercase(password):
            diversity_count += 1
        if self._has_numbers(password):
            diversity_count += 1
        if self._has_special_chars(password):
            diversity_count += 1
        
        # Score: 1 type = 25, 2 types = 50, 3 types = 75, 4 types = 100
        return (diversity_count / 4) * 100
    
    # ==================== PATTERN DETECTION ====================
    
    def _has_keyboard_pattern(self, password: str) -> bool:
        # Detect keyboard walks like 'qwerty', 'asdf', '12345'
        patterns = [
            r'qwert|werty|ertyu|rtyui|tyuio|yuiop',  # QWERTY row
            r'asdfg|sdfgh|dfghj|fghjk|ghjkl',        # ASDF row
            r'zxcvb|xcvbn|cvbnm',                     # ZXCV row
            r'12345|23456|34567|45678|56789|67890',  # Number sequence
            r'!@#\$%|\$%\^&',                         # Special char sequence
        ]
        
        pwd_lower = password.lower()
        for pattern in patterns:
            if re.search(pattern, pwd_lower):
                return True
        return False
    
    def _has_sequential_chars(self, password: str) -> bool:
        # Detect sequential characters like 'abc', 'xyz', '012'
        for i in range(len(password) - 2):
            if ord(password[i+1]) == ord(password[i]) + 1 and \
               ord(password[i+2]) == ord(password[i+1]) + 1:
                return True
        return False
    
    def _has_repeated_chars(self, password: str) -> bool:
        # Detect repeated characters like 'aaa', '1111'
        return any(password.count(c) >= 3 for c in set(password))
    
    def _is_common_pattern(self, password: str) -> bool:
        # Detect common substitution patterns
        common_patterns = [
            r'[Pp]ass(word)?',
            r'[Pp]\@ssw0rd',
            r'[Qq]werty',
            r'[Aa]dmin',
            r'[Ll]etme[Ii]n',
            r'[Ww]elcome',
            r'[Ss]ecure',
        ]
        
        for pattern in common_patterns:
            if re.search(pattern, password):
                return True
        return False
    
    def _check_patterns(self, password: str) -> float:
        # Score based on pattern detection (0-100). Higher is better.
        score = 100
        
        if self._has_keyboard_pattern(password):
            score -= 25
        if self._has_sequential_chars(password):
            score -= 15
        if self._has_repeated_chars(password):
            score -= 10
        if self._is_common_pattern(password):
            score -= 20
        
        return max(0, score)
    
    # ==================== DICTIONARY CHECK ====================
    
    def _check_dictionary(self, password: str) -> float:
        # Enhanced dictionary check using fuzzy matching with RapidFuzz
        # Catches exact matches, variations, leet speak, typos, and phonetic similarities
        # Returns 0-100 score (higher = better, not in list)
        pwd_lower = password.lower()
        
        # Normalize leet speak variations (p@ssw0rd → password)
        normalized_pwd = self._normalize_leet_speak(pwd_lower)
        
        # Exact match in known password list
        if pwd_lower in self.common_passwords or normalized_pwd in self.common_passwords:
            return 0  # FAIL - Password is directly in breach database
        
        # Fuzzy match
        # Check for very similar passwords (85%+ similarity)
        for common in self.common_passwords:
            # Use token_set_ratio for order-independent comparison
            similarity = fuzz.token_set_ratio(normalized_pwd, common)
            
            if similarity >= 85:  # 85%+ means very similar
                # Return score inversely proportional to similarity
                # 85% similar → 30 points, 90% similar → 10 points
                return max(0, 50 - (similarity - 85) * 4)
        
        # Common weak password patterns
        common_words = [
            'password', 'admin', 'user', 'welcome', 'letmein', 'monkey',
            'dragon', 'master', 'shadow', 'sunshine', 'starlight', 'trustno1',
            'qwerty', 'admin123', 'pass123', 'password123'
        ]
        
        for word in common_words:
            similarity = fuzz.token_set_ratio(normalized_pwd, word)
            
            if similarity >= 80:  # 80%+ means contains dictionary word
                # Higher similarity = worse score
                # 80% match → 40 points, 95% match → 5 points
                return max(10, 60 - (similarity - 80) * 2.5)
        
        # Check if password contains common words as substrings
        for word in common_words:
            if len(word) >= 4:  # Only check substantial words
                if word in normalized_pwd:
                    return 25  # Contains common word
        
        # No match found
        return 100
    
    def _normalize_leet_speak(self, password: str) -> str:
        
        leet_map = {
            # Numbers and symbols to letters
            '@': 'a', '4': 'a', '^': 'a',      # @ and 4 = a
            '3': 'e', '€': 'e',                # 3 = e
            '8': 'b',                          # 8 = b
            '9': 'g',                          # 9 = g
            '1': 'i', '|': 'i', '!': 'i',    # 1, |, ! = i
            '0': 'o', '()': 'o',               # 0 = o
            '5': 's', '$': 's',                # 5, $ = s
            '7': 't', '+': 't',                # 7, + = t
            '2': 'z',                          # 2 = z
            '6': 'g',                          # 6 = g
            '.': '', '-': '', '_': '', ' ': '', # Remove spacing
        }
        
        normalized = password
        for leet_char, letter in leet_map.items():
            normalized = normalized.replace(leet_char, letter)
        
        return normalized
    
    # ==================== ENTROPY CALCULATION ====================
    
    def _calculate_entropy(self, password: str) -> float:
        # Calculate Shannon entropy of password
        # Formula: log2(possible_characters ^ password_length)
        # Industry standard: 50+ bits acceptable, 70+ bits strong
        charset_size = 0
        
        if re.search(r'[a-z]', password):
            charset_size += self.LOWERCASE
        if re.search(r'[A-Z]', password):
            charset_size += self.UPPERCASE
        if re.search(r'[0-9]', password):
            charset_size += self.DIGITS
        if re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password):
            charset_size += self.SPECIAL
        
        if charset_size == 0:
            return 0
        
        entropy = len(password) * math.log2(charset_size)
        return entropy
    
    def _entropy_to_score(self, entropy: float) -> float:
        # Convert entropy bits to score (0-100)
        if entropy < 30:
            return 10
        elif entropy < 50:
            return 50
        elif entropy < 70:
            return 75
        else:
            return 100
    
    # ==================== TIME TO CRACK ====================
    
    def _calculate_time_to_crack(self, entropy: float) -> str:
        # Calculate approximate time to crack (assuming 1 billion guesses/sec)
        total_possibilities = 2 ** entropy
        average_guesses = total_possibilities / 2  # On average, takes half the guesses
        seconds = average_guesses / self.GUESSES_PER_SECOND
        
        if seconds < 1:
            return "Less than 1 second"
        elif seconds < 60:
            return f"{seconds:.1f} seconds"
        elif seconds < 3600:
            return f"{seconds/60:.1f} minutes"
        elif seconds < 86400:
            return f"{seconds/3600:.1f} hours"
        elif seconds < self.SECONDS_PER_YEAR:
            return f"{seconds/86400:.1f} days"
        else:
            years = seconds / self.SECONDS_PER_YEAR
            if years > 1_000_000:
                return f"~{years/1_000_000:.1f} million years"
            else:
                return f"~{years:.1f} years"
    
    # ==================== FEEDBACK GENERATION ====================
    
    def _generate_feedback(self, password: str, length_score: float, 
                          diversity_score: float, pattern_score: float,
                          dictionary_score: float) -> Dict[str, List[str]]:
        # Generate actionable feedback for the user
        positive = []
        negative = []
        suggestions = []
        
        # Positive feedback
        if len(password) >= 16:
            positive.append("Excellent length (16+ characters)")
        elif len(password) >= 12:
            positive.append("Good length (12+ characters)")
        
        if diversity_score == 100:
            positive.append("Excellent character diversity (all types present)")
        elif diversity_score >= 75:
            positive.append("Good character variety")
        
        if pattern_score == 100:
            positive.append("No predictable patterns detected")
        
        if dictionary_score == 100:
            positive.append("Not a common password")
        
        # Negative feedback
        if len(password) < 12:
            negative.append("Password too short (use 12+ characters)")
            suggestions.append("Increase password length to at least 12 characters")
        
        if not self._has_uppercase(password):
            negative.append("Missing uppercase letters")
            suggestions.append("Add uppercase letters (A-Z)")
        
        if not self._has_lowercase(password):
            negative.append("Missing lowercase letters")
            suggestions.append("Add lowercase letters (a-z)")
        
        if not self._has_numbers(password):
            negative.append("Missing numbers")
            suggestions.append("Add numbers (0-9)")
        
        if not self._has_special_chars(password):
            negative.append("Missing special characters")
            suggestions.append("Add special characters (!@#$%^&*)")
        
        if self._has_keyboard_pattern(password):
            negative.append("Contains keyboard walk pattern")
            suggestions.append("Avoid keyboard patterns like qwerty or 12345")
        
        if dictionary_score < 100:
            negative.append("Password contains common words")
            suggestions.append("Use random, uncommon words or phrases")
        
        if len(positive) == 0:
            suggestions.append("Consider using a password generator for a strong password")
        
        return {
            "positive": positive,
            "negative": negative,
            "suggestions": suggestions
        }
    
    def _weak_result(self, reason: str) -> Dict[str, Any]:
        # Return a weak result for invalid passwords
        return {
            "password": "***",
            "overall_strength": "VERY WEAK",
            "score": 0,
            "entropy_bits": 0,
            "time_to_crack": "Less than 1 second",
            "feedback": {
                "positive": [],
                "negative": [reason],
                "suggestions": ["Create a proper password with minimum 12 characters"]
            },
            "criteria": {k: {"status": "FAIL"} for k in [
                "length", "uppercase", "lowercase", "numbers", 
                "special_chars", "no_dictionary_words", 
                "no_keyboard_patterns", "no_sequential_chars"
            ]}
        }


