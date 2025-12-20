"""
Reference Tests for Password Generator
Shows best practices for testing cryptographic password generation
"""

import pytest
import re
from password_tool.generator import PasswordGenerator, PasswordStrength


class TestPasswordGenerator:
    """Test suite for PasswordGenerator"""
    
    @pytest.fixture
    def generator(self):
        """Create a PasswordGenerator instance for testing"""
        return PasswordGenerator()
    
    # ==================== INITIALIZATION ====================
    
    def test_generator_initialization(self, generator):
        """Test that generator initializes correctly"""
        assert generator is not None
        assert hasattr(generator, 'LOWERCASE')
        assert hasattr(generator, 'UPPERCASE')
        assert hasattr(generator, 'DIGITS')
        assert hasattr(generator, 'SPECIAL')
    
    # ==================== BASIC GENERATION ====================
    
    def test_generate_password_returns_string(self, generator):
        """Test that generate_password returns a string"""
        pwd = generator.generate_password()
        assert isinstance(pwd, str)
        assert len(pwd) > 0
    
    def test_generate_password_respects_length(self, generator):
        """Test that generated password has correct length"""
        for length in [8, 12, 16, 20, 32]:
            pwd = generator.generate_password(length=length)
            assert len(pwd) == length
    
    def test_minimum_length_validation(self, generator):
        """Test that minimum length is enforced"""
        with pytest.raises(ValueError):
            generator.generate_password(length=7)
    
    def test_generates_different_passwords(self, generator):
        """Test that generator produces different passwords each time"""
        pwds = [generator.generate_password() for _ in range(10)]
        # All passwords should be unique (extremely unlikely to have duplicates)
        assert len(set(pwds)) == len(pwds)
    
    # ==================== STRENGTH LEVELS ====================
    
    def test_weak_password_generation(self, generator):
        """Test WEAK strength password generation"""
        pwd = generator.generate_password(length=12, strength=PasswordStrength.WEAK)
        
        # Should only have letters and numbers
        assert re.match(r'^[a-zA-Z0-9]+$', pwd)
        assert len(pwd) == 12
        
        # Should have both upper and lower case
        assert any(c.isupper() for c in pwd)
        assert any(c.islower() for c in pwd)
        assert any(c.isdigit() for c in pwd)
    
    def test_medium_password_generation(self, generator):
        """Test MEDIUM strength password generation"""
        pwd = generator.generate_password(length=12, strength=PasswordStrength.MEDIUM)
        
        # Should have all basic character types
        assert any(c.isupper() for c in pwd)
        assert any(c.islower() for c in pwd)
        assert any(c.isdigit() for c in pwd)
    
    def test_strong_password_generation(self, generator):
        """Test STRONG strength password generation"""
        pwd = generator.generate_password(length=16, strength=PasswordStrength.STRONG)
        
        # Should have all character types including special
        assert len(pwd) == 16
        assert any(c.isupper() for c in pwd)
        assert any(c.islower() for c in pwd)
        assert any(c.isdigit() for c in pwd)
        # Check for special characters
        has_special = any(c in PasswordGenerator.SPECIAL for c in pwd)
        assert has_special
    
    def test_very_strong_password_generation(self, generator):
        """Test VERY_STRONG password generation"""
        pwd = generator.generate_password(length=20, strength=PasswordStrength.VERY_STRONG)
        
        # Should have maximum diversity
        assert len(pwd) == 20
        assert any(c.isupper() for c in pwd)
        assert any(c.islower() for c in pwd)
        assert any(c.isdigit() for c in pwd)
        has_special = any(c in PasswordGenerator.SPECIAL for c in pwd)
        assert has_special
    
    # ==================== CHARACTER DIVERSITY ====================
    
    def test_includes_uppercase_when_required(self, generator):
        """Test that uppercase is included in appropriate strength levels"""
        for strength in [PasswordStrength.MEDIUM, PasswordStrength.STRONG, 
                        PasswordStrength.VERY_STRONG]:
            pwd = generator.generate_password(length=16, strength=strength)
            assert any(c.isupper() for c in pwd)
    
    def test_includes_lowercase_when_required(self, generator):
        """Test that lowercase is included"""
        for strength in [PasswordStrength.WEAK, PasswordStrength.MEDIUM, 
                        PasswordStrength.STRONG, PasswordStrength.VERY_STRONG]:
            pwd = generator.generate_password(length=16, strength=strength)
            assert any(c.islower() for c in pwd)
    
    def test_includes_numbers_when_required(self, generator):
        """Test that numbers are included"""
        for strength in [PasswordStrength.WEAK, PasswordStrength.MEDIUM, 
                        PasswordStrength.STRONG, PasswordStrength.VERY_STRONG]:
            pwd = generator.generate_password(length=16, strength=strength)
            assert any(c.isdigit() for c in pwd)
    
    def test_includes_special_chars_when_requested(self, generator):
        """Test that special characters are included when requested"""
        pwd = generator.generate_password(
            length=16,
            strength=PasswordStrength.STRONG,
            include_special=True
        )
        has_special = any(c in PasswordGenerator.SPECIAL for c in pwd)
        assert has_special
    
    def test_excludes_special_chars_when_not_requested(self, generator):
        """Test that special characters are excluded when not requested"""
        pwd = generator.generate_password(
            length=16,
            strength=PasswordStrength.WEAK,
            include_special=False
        )
        has_special = any(c in PasswordGenerator.SPECIAL for c in pwd)
        assert not has_special
    
    # ==================== AMBIGUOUS CHARACTER HANDLING ====================
    
    def test_can_exclude_ambiguous_characters(self, generator):
        """Test that ambiguous characters can be excluded"""
        pwd = generator.generate_password(
            length=20,
            strength=PasswordStrength.STRONG,
            exclude_ambiguous=True
        )
        
        # Should not contain ambiguous characters
        for char in pwd:
            assert char not in PasswordGenerator.AMBIGUOUS
    
    def test_ambiguous_exclusion_maintains_strength(self, generator):
        """Test that excluding ambiguous chars doesn't weaken the password"""
        pwd = generator.generate_password(
            length=20,
            strength=PasswordStrength.STRONG,
            exclude_ambiguous=True
        )
        
        # Should still have all character types (or almost all)
        assert any(c.isupper() for c in pwd)
        assert any(c.islower() for c in pwd)
        assert any(c.isdigit() for c in pwd)
    
    # ==================== READABLE PASSWORDS ====================
    
    def test_readable_password_generation(self, generator):
        """Test generation of readable passwords"""
        pwd = generator.generate_password(length=14, readable=True)
        
        # Should be a valid string of the right length
        assert isinstance(pwd, str)
        assert len(pwd) == 14
    
    def test_readable_passwords_are_different(self, generator):
        """Test that readable passwords are still unique"""
        pwds = [generator.generate_password(length=14, readable=True) for _ in range(5)]
        assert len(set(pwds)) == len(pwds)
    
    # ==================== BATCH OPERATIONS ====================
    
    def test_generate_multiple_passwords(self, generator):
        """Test generating multiple passwords at once"""
        count = 5
        pwds = generator.generate_multiple(count=count, length=16)
        
        assert isinstance(pwds, list)
        assert len(pwds) == count
        assert all(isinstance(pwd, str) for pwd in pwds)
        assert all(len(pwd) == 16 for pwd in pwds)
    
    def test_multiple_passwords_are_unique(self, generator):
        """Test that batch-generated passwords are unique"""
        pwds = generator.generate_multiple(count=10, length=16)
        assert len(set(pwds)) == len(pwds)
    
    def test_multiple_respects_strength(self, generator):
        """Test that batch generation respects strength level"""
        pwds = generator.generate_multiple(
            count=5,
            length=16,
            strength=PasswordStrength.STRONG
        )
        
        # All should have special characters (STRONG requirement)
        for pwd in pwds:
            assert any(c in PasswordGenerator.SPECIAL for pwd in pwds)
    
    # ==================== UTILITY FUNCTIONS ====================
    
    def test_remove_ambiguous_characters(self, generator):
        """Test removal of ambiguous characters"""
        charset = generator._remove_ambiguous("abc0O1lI|")
        
        for char in PasswordGenerator.AMBIGUOUS:
            assert char not in charset
    
    def test_shuffle_list_changes_order(self, generator):
        """Test that shuffle actually changes the order"""
        items = list("abcdefghij")
        original = items.copy()
        shuffled = generator._shuffle_list(items)
        
        # Should have same items but different order (very likely)
        assert sorted(shuffled) == sorted(original)
        assert shuffled != original  # Extremely unlikely to be in same order
    
    def test_shuffle_preserves_items(self, generator):
        """Test that shuffle preserves all items"""
        items = ['a', 'b', 'c', '1', '2', '3', '!', '@']
        shuffled = generator._shuffle_list(items)
        
        assert sorted(shuffled) == sorted(items)
        assert len(shuffled) == len(items)
    
    # ==================== STRENGTH RECOMMENDATIONS ====================
    
    def test_get_recommended_length(self, generator):
        """Test recommended length for each strength"""
        assert generator.get_recommended_length(PasswordStrength.WEAK) == 8
        assert generator.get_recommended_length(PasswordStrength.MEDIUM) == 12
        assert generator.get_recommended_length(PasswordStrength.STRONG) == 16
        assert generator.get_recommended_length(PasswordStrength.VERY_STRONG) == 20
    
    def test_get_strength_description(self, generator):
        """Test getting strength descriptions"""
        for strength in PasswordStrength:
            title, desc = generator.get_strength_description(strength)
            assert isinstance(title, str)
            assert isinstance(desc, str)
            assert len(title) > 0
            assert len(desc) > 0
    
    # ==================== ENTROPY CALCULATION ====================
    
    def test_entropy_calculation(self, generator):
        """Test entropy calculation"""
        # 8 chars from 94-char charset (lowercase + uppercase + digits + special)
        entropy = generator.calculate_entropy(password_length=8, charset_size=94)
        assert entropy > 0
        
        # 16 chars should have higher entropy than 8 chars
        entropy2 = generator.calculate_entropy(password_length=16, charset_size=94)
        assert entropy2 > entropy
    
    def test_entropy_zero_for_invalid_input(self, generator):
        """Test entropy is zero for invalid inputs"""
        assert generator.calculate_entropy(password_length=0, charset_size=94) == 0
        assert generator.calculate_entropy(password_length=10, charset_size=0) == 0
        assert generator.calculate_entropy(password_length=0, charset_size=0) == 0
    
    def test_charset_size_calculation(self, generator):
        """Test charset size calculation"""
        # Only lowercase
        size1 = generator.get_charset_size(
            include_uppercase=False,
            include_lowercase=True,
            include_digits=False,
            include_special=False
        )
        assert size1 == 26
        
        # All types
        size2 = generator.get_charset_size(
            include_uppercase=True,
            include_lowercase=True,
            include_digits=True,
            include_special=True
        )
        assert size2 > 50
    
    # ==================== INTEGRATION TESTS ====================
    
    def test_generated_password_quality(self, generator):
        """Test that generated passwords meet quality standards"""
        for strength in PasswordStrength:
            length = generator.get_recommended_length(strength)
            pwd = generator.generate_password(length=length, strength=strength)
            
            # Should be correct length
            assert len(pwd) == length
            
            # Should not be empty
            assert len(pwd) > 0
            
            # Should only contain valid characters
            valid_chars = (PasswordGenerator.LOWERCASE + 
                          PasswordGenerator.UPPERCASE + 
                          PasswordGenerator.DIGITS + 
                          PasswordGenerator.SPECIAL)
            assert all(c in valid_chars for c in pwd)
    
    def test_password_generation_consistency(self, generator):
        """Test that password generation doesn't fail after multiple calls"""
        for _ in range(50):
            pwd = generator.generate_password(length=16, strength=PasswordStrength.STRONG)
            assert isinstance(pwd, str)
            assert len(pwd) == 16
    
    def test_all_strength_levels_work(self, generator):
        """Test that all strength levels work correctly"""
        for strength in PasswordStrength:
            length = generator.get_recommended_length(strength)
            try:
                pwd = generator.generate_password(length=length, strength=strength)
                assert len(pwd) == length
                assert isinstance(pwd, str)
            except Exception as e:
                pytest.fail(f"Generation failed for {strength}: {e}")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
