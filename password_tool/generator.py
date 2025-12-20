import secrets
import string
from typing import List, Tuple
from enum import Enum


class PasswordStrength(Enum):
    # Password strength levels
    WEAK = "WEAK"
    MEDIUM = "MEDIUM"
    STRONG = "STRONG"
    VERY_STRONG = "VERY_STRONG"


class PasswordGenerator:
    # Cryptographically secure password generator
    
    # Character sets - using standard ASCII ranges
    LOWERCASE = string.ascii_lowercase          # a-z
    UPPERCASE = string.ascii_uppercase          # A-Z
    DIGITS = string.digits                      # 0-9
    SPECIAL = "!@#$%^&*()_+-=[]{}|;:',<>?/.~"  # Common special chars
    
    # Ambiguous characters to exclude (optional)
    AMBIGUOUS = "0O1lI|`"  # Often confused: zero/O, one/l/I
    
    def __init__(self):
        # Initialize the generator
        pass
    
    # ==================== STRENGTH LEVEL GENERATORS ====================
    
    def generate_password(self, length: int = 16, 
                         strength: PasswordStrength = PasswordStrength.STRONG,
                         include_special: bool = True,
                         exclude_ambiguous: bool = True,
                         readable: bool = False) -> str:
        """        
        Args:
        1.    length: Password length (default 16 chars)
        2.    strength: Strength level (WEAK, MEDIUM, STRONG, VERY_STRONG)
        3.    include_special: Include special characters
        4.    exclude_ambiguous: Exclude easily confused characters
        5.    readable: Generate more readable password (alternating consonants/vowels)
        
        Returns:
            Generated password string
        """
        # Validate length
        if length < 8:
            raise ValueError("Password length must be at least 8 characters")
        
        if readable:
            return self._generate_readable_password(length, include_special)
        
        # Map strength to actual strategy
        if strength == PasswordStrength.WEAK:
            return self._generate_weak(length)
        elif strength == PasswordStrength.MEDIUM:
            return self._generate_medium(length, include_special, exclude_ambiguous)
        elif strength == PasswordStrength.STRONG:
            return self._generate_strong(length, include_special, exclude_ambiguous)
        else:  # VERY_STRONG
            return self._generate_very_strong(length, exclude_ambiguous)
    
    def _generate_weak(self, length: int) -> str:
        # Generate WEAK password: letters and numbers only
        charset = self.LOWERCASE + self.UPPERCASE + self.DIGITS
        password = ''.join(secrets.choice(charset) for _ in range(length))
        return password
    
    def _generate_medium(self, length: int, include_special: bool, 
                        exclude_ambiguous: bool) -> str:
        #Generate MEDIUM password: guaranteed 1 uppercase, 1 lowercase, 1 digit
        charset = self.LOWERCASE + self.UPPERCASE + self.DIGITS
        if include_special:
            charset += self.SPECIAL
        
        if exclude_ambiguous:
            charset = self._remove_ambiguous(charset)
        
        # Guarantee minimum requirements
        required = [
            secrets.choice(self.UPPERCASE),
            secrets.choice(self.LOWERCASE),
            secrets.choice(self.DIGITS),
        ]
        
        if include_special and len(self.SPECIAL) > 0:
            required.append(secrets.choice(self.SPECIAL))
        
        # Fill remaining length with random characters
        remaining = length - len(required)
        password_chars = required + [secrets.choice(charset) for _ in range(remaining)]
        
        # Shuffle to avoid predictable patterns
        password_chars = self._shuffle_list(password_chars)
        
        return ''.join(password_chars)
    
    def _generate_strong(self, length: int, include_special: bool,
                        exclude_ambiguous: bool) -> str:
        # Generate STRONG password: guaranteed uppercase, lowercase, digit, and special char
        
        charset = self.LOWERCASE + self.UPPERCASE + self.DIGITS + self.SPECIAL
        
        if exclude_ambiguous:
            charset = self._remove_ambiguous(charset)
        
        # Guarantee all 4 character types
        required = [
            secrets.choice(self.UPPERCASE),
            secrets.choice(self.LOWERCASE),
            secrets.choice(self.DIGITS),
            secrets.choice(self.SPECIAL),
        ]
        
        # Fill remaining length
        remaining = length - len(required)
        password_chars = required + [secrets.choice(charset) for _ in range(remaining)]
        
        # Shuffle
        password_chars = self._shuffle_list(password_chars)
        
        return ''.join(password_chars)
    
    def _generate_very_strong(self, length: int, exclude_ambiguous: bool) -> str:
        # Generate VERY_STRONG password: maximum character diversity
        # Includes uppercase, lowercase, digits, and special characters

        charset = self.LOWERCASE + self.UPPERCASE + self.DIGITS + self.SPECIAL
        
        if exclude_ambiguous:
            charset = self._remove_ambiguous(charset)
        
        # Guarantee at least 2 of each character type for maximum diversity
        required = [
            secrets.choice(self.UPPERCASE),
            secrets.choice(self.UPPERCASE),
            secrets.choice(self.LOWERCASE),
            secrets.choice(self.LOWERCASE),
            secrets.choice(self.DIGITS),
            secrets.choice(self.DIGITS),
            secrets.choice(self.SPECIAL),
            secrets.choice(self.SPECIAL),
        ]
        
        # Fill remaining length
        remaining = length - len(required)
        password_chars = required + [secrets.choice(charset) for _ in range(remaining)]
        
        # Shuffle
        password_chars = self._shuffle_list(password_chars)
        
        return ''.join(password_chars)
    
    def _generate_readable_password(self, length: int, include_special: bool) -> str:
        
        consonants = "bcdfghjklmnprstvwxyz"
        vowels = "aeiou"
        
        password_chars = []
        is_consonant = True
        
        for i in range(length):
            if is_consonant:
                char = secrets.choice(consonants.upper() if i % 5 == 0 else consonants)
            else:
                char = secrets.choice(vowels)
            
            password_chars.append(char)
            is_consonant = not is_consonant
        
        # Add some digits and special chars if needed
        if include_special and length >= 12:
            # Replace some characters with digits/special chars
            idx1 = secrets.randbelow(length - 2)
            idx2 = secrets.randbelow(length - 2)
            
            password_chars[idx1] = secrets.choice(self.DIGITS)
            password_chars[idx2] = secrets.choice(self.SPECIAL)
        
        return ''.join(password_chars)
    
    # ==================== UTILITY METHODS ====================
    
    def _remove_ambiguous(self, charset: str) -> str:
        # Remove ambiguous characters from charset
        return ''.join(c for c in charset if c not in self.AMBIGUOUS)
    
    def _shuffle_list(self, items: List[str]) -> List[str]:
        # Shuffle a list using cryptographic randomness
        shuffled = items.copy()
        n = len(shuffled)
        for i in range(n - 1, 0, -1):
            j = secrets.randbelow(i + 1)
            shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
        return shuffled
    
    # ==================== BATCH OPERATIONS ====================
    
    def generate_multiple(self, count: int, length: int = 16,
                         strength: PasswordStrength = PasswordStrength.STRONG) -> List[str]:
        """        
        Args:
        1.    count: Number of passwords to generate
        2.    length: Length of each password
        3.    strength: Strength level for all passwords
        
        Returns:
            List of generated passwords
        """
        return [self.generate_password(length, strength) for _ in range(count)]
    
    # ==================== PASSWORD STRENGTH RECOMMENDATION ====================
    
    @staticmethod
    def get_recommended_length(strength: PasswordStrength) -> int:
        # Get recommended password length for each strength level
        recommendations = {
            PasswordStrength.WEAK: 8,
            PasswordStrength.MEDIUM: 12,
            PasswordStrength.STRONG: 16,
            PasswordStrength.VERY_STRONG: 20,
        }
        return recommendations[strength]
    
    @staticmethod
    def get_strength_description(strength: PasswordStrength) -> Tuple[str, str]:
        # Get description of a strength level
        descriptions = {
            PasswordStrength.WEAK: (
                "Basic security",
                "Letters and numbers only (8+ chars)"
            ),
            PasswordStrength.MEDIUM: (
                "Standard security",
                "Uppercase, lowercase, numbers (12+ chars)"
            ),
            PasswordStrength.STRONG: (
                "Good security",
                "All character types including special chars (16+ chars)"
            ),
            PasswordStrength.VERY_STRONG: (
                "Maximum security",
                "Maximum diversity, recommended for critical accounts (20+ chars)"
            ),
        }
        return descriptions[strength]
    
    # ==================== ENTROPY CALCULATION ====================
    
    @staticmethod
    def calculate_entropy(password_length: int, charset_size: int) -> float:
        """
        Calculate entropy of a generated password
        Formula: log2(charset_size ^ password_length)
        """
        import math
        if charset_size <= 1 or password_length <= 0:
            return 0
        return password_length * math.log2(charset_size)
    
    @staticmethod
    def get_charset_size(include_uppercase: bool = True,
                        include_lowercase: bool = True,
                        include_digits: bool = True,
                        include_special: bool = True,
                        exclude_ambiguous: bool = False) -> int:
        
        size = 0
        if include_uppercase:
            size += 26
        if include_lowercase:
            size += 26
        if include_digits:
            size += 10
        if include_special:
            size += len("!@#$%^&*()_+-=[]{}|;:',<>?/.~")
        
        if exclude_ambiguous:
            size -= len("0O1lI|`")  # Approximate
        
        return size


# ==================== EXAMPLE USAGE ====================

if __name__ == "__main__":
    generator = PasswordGenerator()
    
    print("=" * 60)
    print("PASSWORD GENERATOR - REFERENCE IMPLEMENTATION")
    print("=" * 60)
    
    # Generate passwords at different strength levels
    strengths = [
        PasswordStrength.WEAK,
        PasswordStrength.MEDIUM,
        PasswordStrength.STRONG,
        PasswordStrength.VERY_STRONG,
    ]
    
    for strength in strengths:
        print(f"\n{strength.value} Password:")
        print("-" * 40)
        
        # Get description
        title, description = generator.get_strength_description(strength)
        recommended_length = generator.get_recommended_length(strength)
        
        print(f"  Description: {description}")
        print(f"  Recommended length: {recommended_length}+ characters")
        
        # Generate 3 examples
        print(f"  Examples:")
        for i in range(3):
            pwd = generator.generate_password(
                length=recommended_length,
                strength=strength
            )
            charset_size = generator.get_charset_size(
                include_special=(strength != PasswordStrength.WEAK)
            )
            entropy = generator.calculate_entropy(recommended_length, charset_size)
            print(f"    {i+1}. {pwd} (entropy: {entropy:.1f} bits)")
    
    # Generate readable passwords
    print(f"\n{'READABLE' if 'READABLE' else 'READABLE'} Passwords (MEDIUM - Readable):")
    print("-" * 40)
    for i in range(3):
        pwd = generator.generate_password(
            length=14,
            strength=PasswordStrength.MEDIUM,
            readable=True
        )
        print(f"  {i+1}. {pwd}")
    
    # Generate multiple passwords at once
    print(f"\n{'BATCH GENERATION'} (5 STRONG passwords):")
    print("-" * 40)
    batch = generator.generate_multiple(5, length=16, strength=PasswordStrength.STRONG)
    for i, pwd in enumerate(batch, 1):
        print(f"  {i}. {pwd}")
