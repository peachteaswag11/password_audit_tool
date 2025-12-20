
import pytest
from password_tool.checker import PasswordChecker


class TestPasswordChecker:
    
    @pytest.fixture
    def checker(self):
        """Create a PasswordChecker instance for testing"""
        return PasswordChecker()
    
    # ==================== BASIC FUNCTIONALITY ====================
    
    def test_checker_initialization(self, checker):
        """Test that checker initializes correctly"""
        assert checker is not None
        assert hasattr(checker, 'common_passwords')
    
    def test_check_password_returns_dict(self, checker):
        """Test that check_password returns a dictionary"""
        result = checker.check_password("TestPassword123!")
        assert isinstance(result, dict)
        assert 'overall_strength' in result
        assert 'score' in result
        assert 'entropy_bits' in result
        assert 'feedback' in result
    
    # ==================== STRENGTH LEVELS ====================
    
    def test_very_weak_password(self, checker):
        """Test detection of very weak passwords"""
        result = checker.check_password("")
        assert result['overall_strength'] == "VERY WEAK"
        assert result['score'] == 0
    
    def test_weak_password_detection(self, checker):
        """Test detection of weak passwords"""
        weak_passwords = [
            "123456",      # Only numbers
            "password",    # Dictionary word
            "abc",         # Too short
            "qwerty",      # Keyboard pattern
        ]
        for pwd in weak_passwords:
            result = checker.check_password(pwd)
            assert result['overall_strength'] in ["WEAK", "VERY WEAK"]
            assert result['score'] < 60
    
    def test_medium_password_detection(self, checker):
        """Test detection of medium strength passwords"""
        result = checker.check_password("Password123")
        assert result['overall_strength'] in ["MEDIUM", "WEAK", "STRONG"]
        # Score should be in reasonable range
        assert 40 <= result['score'] <= 90
    
    def test_strong_password_detection(self, checker):
        """Test detection of strong passwords"""
        strong_passwords = [
            "MySecure@Pass123",
            "Tr0pic@lThund3rstorm!",
            "C0mpl3x!P@ssw0rd#2024",
        ]
        for pwd in strong_passwords:
            result = checker.check_password(pwd)
            assert result['overall_strength'] in ["STRONG", "MEDIUM"]
            assert result['score'] >= 60
    
    # ==================== CHARACTER CHECKS ====================
    
    def test_uppercase_detection(self, checker):
        """Test uppercase letter detection"""
        result_with_upper = checker.check_password("ABCdef123")
        result_without_upper = checker.check_password("abcdef123")
        
        assert checker._has_uppercase("ABCdef") is True
        assert checker._has_uppercase("abcdef") is False
        
        assert result_with_upper['criteria']['uppercase']['status'] == "PASS"
        assert result_without_upper['criteria']['uppercase']['status'] == "FAIL"
    
    def test_lowercase_detection(self, checker):
        """Test lowercase letter detection"""
        assert checker._has_lowercase("abcdef") is True
        assert checker._has_lowercase("ABCDEF") is False
    
    def test_number_detection(self, checker):
        """Test number detection"""
        assert checker._has_numbers("abc123") is True
        assert checker._has_numbers("abcdef") is False
    
    def test_special_char_detection(self, checker):
        """Test special character detection"""
        assert checker._has_special_chars("abc!def") is True
        assert checker._has_special_chars("abc@def") is True
        assert checker._has_special_chars("abcdef") is False
    
    def test_character_diversity_score(self, checker):
        """Test character diversity scoring"""
        # No character type
        score1 = checker._check_character_diversity("aaaa")
        assert score1 < 50
        
        # All character types
        score2 = checker._check_character_diversity("Aa1!")
        assert score2 == 100
    
    # ==================== PATTERN DETECTION ====================
    
    def test_keyboard_pattern_detection(self, checker):
        """Test detection of keyboard walk patterns"""
        keyboard_patterns = [
            "qwerty",
            "asdf",
            "12345",
            "!@#$%",
        ]
        for pattern in keyboard_patterns:
            # Pad to meet minimum length
            pwd = pattern + "AAaa1!"
            result = checker.check_password(pwd)
            assert result['criteria']['no_keyboard_patterns']['status'] == "FAIL"
    
    def test_sequential_char_detection(self, checker):
        """Test detection of sequential characters"""
        result = checker.check_password("abc123!@#AAA")
        assert checker._has_sequential_chars("abc") is True
        assert checker._has_sequential_chars("xyz") is True
        assert checker._has_sequential_chars("abd") is False
    
    def test_repeated_char_detection(self, checker):
        """Test detection of repeated characters"""
        assert checker._has_repeated_chars("aaa") is True
        assert checker._has_repeated_chars("aa") is False
        assert checker._has_repeated_chars("abcdef") is False
    
    def test_common_pattern_detection(self, checker):
        """Test detection of common patterns"""
        assert checker._is_common_pattern("password") is True
        assert checker._is_common_pattern("admin") is True
        assert checker._is_common_pattern("rAndomstring") is False
    
    # ==================== LENGTH CHECKS ====================
    
    def test_length_scoring(self, checker):
        """Test length-based scoring"""
        # Short password
        score1 = checker._check_length("abc")
        assert score1 == 0
        
        # 8 characters
        score2 = checker._check_length("abcdefgh")
        assert score2 < 50
        
        # 12 characters (NIST minimum)
        score3 = checker._check_length("abcdefghijkl")
        assert 40 <= score3 < 80
        
        # 16+ characters (recommended)
        score4 = checker._check_length("abcdefghijklmnop")
        assert score4 >= 75
    
    def test_length_requirement(self, checker):
        """Test minimum length requirement"""
        assert checker._length_check("Aa1!abcdefgh") is True  # 12 chars
        assert checker._length_check("Aa1!abcdef") is False   # 10 chars
    
    # ==================== ENTROPY CALCULATION ====================
    
    def test_entropy_calculation(self, checker):
        """Test entropy calculation"""
        # Low entropy (lowercase only, 8 chars)
        entropy1 = checker._calculate_entropy("abcdefgh")
        assert 0 < entropy1 < 50
        
        # Medium entropy
        entropy2 = checker._calculate_entropy("Aa1!aBc9")
        assert 40 < entropy2 < 70
        
        # High entropy (mixed types, long)
        entropy3 = checker._calculate_entropy("Tr0pic@lThund3rstorm!")
        assert entropy3 > 70
    
    def test_entropy_to_score_conversion(self, checker):
        """Test conversion of entropy to score"""
        assert checker._entropy_to_score(20) == 10   # Very low
        assert checker._entropy_to_score(40) == 50   # Low
        assert checker._entropy_to_score(60) == 75   # Medium
        assert checker._entropy_to_score(80) == 100  # High
    
    # ==================== TIME TO CRACK ====================
    
    def test_time_to_crack_calculation(self, checker):
        """Test time to crack estimation"""
        # Low entropy
        time1 = checker._calculate_time_to_crack(20)
        assert "second" in time1.lower() or "minute" in time1.lower()
        
        # High entropy
        time2 = checker._calculate_time_to_crack(70)
        assert "year" in time2.lower() or "million" in time2.lower()
    
    # ==================== FEEDBACK GENERATION ====================
    
    def test_feedback_structure(self, checker):
        """Test that feedback is properly structured"""
        result = checker.check_password("TestPassword123!")
        feedback = result['feedback']
        
        assert 'positive' in feedback
        assert 'negative' in feedback
        assert 'suggestions' in feedback
        
        assert isinstance(feedback['positive'], list)
        assert isinstance(feedback['negative'], list)
        assert isinstance(feedback['suggestions'], list)
    
    def test_positive_feedback_generation(self, checker):
        """Test positive feedback generation"""
        result = checker.check_password("MySecure@Pass123ABC")
        feedback = result['feedback']
        
        # Strong password should have positive feedback
        assert len(feedback['positive']) > 0
    
    def test_negative_feedback_generation(self, checker):
        """Test negative feedback for weak passwords"""
        result = checker.check_password("weak")
        feedback = result['feedback']
        
        # Weak password should have negative feedback
        assert len(feedback['negative']) > 0 or len(feedback['suggestions']) > 0
    
    # ==================== INTEGRATION TESTS ====================
    
    def test_full_password_analysis(self, checker):
        """Test complete password analysis workflow"""
        result = checker.check_password("Tr0pic@lThund3rstorm!")
        
        # Verify all components are present
        assert result['password'] == "***"
        assert result['overall_strength'] is not None
        assert 0 <= result['score'] <= 100
        assert result['entropy_bits'] > 0
        assert len(result['time_to_crack']) > 0
        assert len(result['criteria']) == 8
        assert len(result['feedback']) == 3
    
    def test_password_comparison(self, checker):
        """Test comparing strength of multiple passwords"""
        weak = checker.check_password("password")
        strong = checker.check_password("Tr0pic@lThund3rstorm!")
        
        assert strong['score'] > weak['score']
        assert strong['entropy_bits'] > weak['entropy_bits']
    
    def test_edge_cases(self, checker):
        """Test edge cases"""
        # Very long password
        result1 = checker.check_password("A" * 100 + "a1!")
        assert result1['score'] >= 80
        
        # Only special characters (not recommended but valid)
        result2 = checker.check_password("!@#$%^&*()_+-=")
        assert result2['overall_strength'] in ["WEAK", "MEDIUM"]
        
        # Single character (should be very weak)
        result3 = checker.check_password("a")
        assert result3['overall_strength'] == "VERY WEAK"


class TestPasswordCheckerDictionary:
    """Test dictionary checking functionality"""
    
    @pytest.fixture
    def checker(self):
        return PasswordChecker()
    
    def test_dictionary_check_returns_score(self, checker):
        """Test that dictionary check returns a valid score"""
        score = checker._check_dictionary("testpassword")
        assert 0 <= score <= 100
    
    def test_non_dictionary_words_score_high(self, checker):
        """Test that non-dictionary words score higher"""
        result = checker._check_dictionary("Xyzzyx123")
        assert result > 80


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
