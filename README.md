# 🔐 Password Audit Tool

An intensive password strength checker and generator with advanced fuzzy matching, entropy analysis, and pattern detection. Built with Streamlit for interactive analysis and secure password generation. 

## Try It Online (click the link!)

https://passwordaudittool-ct9ulveusu8hqqttlnqq6h.streamlit.app/

## Features

### 🔍 Password Checker
- **Advanced Strength Analysis**: Entropy calculation, pattern detection, fuzzy dictionary checking
- **Fuzzy Matching**: Catches leet speak variations (`p@ssw0rd`), typos, and phonetic similarities
- **Detailed Feedback**: Positive points, areas to improve, and actionable suggestions
- **Time to Crack**: Estimates how long it takes to crack the password
- **Multi-Layer Detection**: 
  - Exact match against breach database
  - Fuzzy match for similar passwords
  - Dictionary word detection with fuzzy matching
  - Partial word matching
- **NIST Compliance**: Follows industry-standard security recommendations

### ⚡ Password Generator
- **Cryptographically Secure**: Uses Python's `secrets` module (not `random`)
- **4 Strength Levels**: WEAK, MEDIUM, STRONG, VERY_STRONG
- **Batch Generation**: Generate multiple passwords at once
- **Customizable**: Control length, character types, and readability

### 📊 Batch Audit
- Audit multiple passwords simultaneously
- Export results to CSV
- See summary statistics across all passwords

## Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Setup

1. **Clone or download this repository**
   ```bash
   git clone https://github.com/yourusername/password_audit_tool.git
   cd password_audit_tool
   ```

2. **Create a virtual environment** (recommended)
   ```bash
   # Windows
   python -m venv venv
   venv\Scripts\activate
   
   # macOS/Linux
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Running the Streamlit App

```bash
streamlit run app.py
```

The app will open in your browser at `http://localhost:8501`

### Using the Reference Implementations Directly

#### Check a Password
```python
from password_tool.checker import PasswordChecker

checker = PasswordChecker()
result = checker.check_password("MySecure@Pass123")

print(result['overall_strength'])    # STRONG
print(result['score'])               # 87/100
print(result['entropy_bits'])        # 68 bits
print(result['feedback'])            # Detailed feedback
```

#### Generate a Password
```python
from password_tool.generator import PasswordGenerator, PasswordStrength

generator = PasswordGenerator()

# Single password
pwd = generator.generate_password(
    length=16,
    strength=PasswordStrength.STRONG
)
print(pwd)  # Example: "Ky7@mN2zQp#Lr4St"

# Multiple passwords
batch = generator.generate_multiple(count=5, length=16)
for pwd in batch:
    print(pwd)
```

## Understanding Password Strength

### Strength Levels

| Level | Description | Min Chars | Entropy | Best For |
|-------|-------------|-----------|---------|----------|
| WEAK | Letters + Numbers only | 8+ | ~40 bits | Throwaway accounts |
| MEDIUM | Mixed types | 12+ | ~60 bits | Regular accounts |
| STRONG | All types + special chars | 16+ | ~70 bits | Email, Banking |
| VERY_STRONG | Maximum diversity | 20+ | ~80+ bits | Critical accounts |

### How Strength is Calculated

```
Overall Score = 
  (Character Diversity × 0.25) +
  (Length Score × 0.25) +
  (Pattern Analysis × 0.20) +
  (Dictionary Check × 0.20) +
  (Entropy × 0.10)
```

### Criteria Evaluated

- ✅ **Length**: Minimum 12 characters (NIST recommendation)
- ✅ **Uppercase**: At least one A-Z
- ✅ **Lowercase**: At least one a-z
- ✅ **Numbers**: At least one 0-9
- ✅ **Special Characters**: !@#$%^&* etc.
- ✅ **No Dictionary Words**: Not in common password lists (fuzzy matched)
- ✅ **No Keyboard Patterns**: Avoids qwerty, asdf, 12345
- ✅ **No Sequential Chars**: Avoids abc, xyz, 012

## Advanced Features

### Fuzzy Matching Dictionary Check

The password checker now uses **RapidFuzz** for advanced dictionary checking that catches variations most tools miss:

#### What It Catches

| Variation | Old Tool | New Tool |
|-----------|----------|----------|
| `password` | ✅ | ✅ |
| `p@ssw0rd` (leet speak) | ❌ | ✅ |
| `p4ssw0rd` (leet speak) | ❌ | ✅ |
| `PASSWORD` (case) | ❌ | ✅ |
| `passwerd` (typo) | ❌ | ✅ |
| `passwords` (plural) | ❌ | ✅ |
| `passw0rd123` (extension) | ❌ | ✅ |

#### How It Works

1. **Leet Speak Normalization**: Converts `p@ssw0rd` → `password`
2. **Fuzzy Matching**: Uses token_set_ratio for similarity detection (85%+ threshold)
3. **Multi-Layer Detection**: Checks exact match, fuzzy match, and dictionary words
4. **Graduated Scoring**: Returns 0-100 based on similarity, not binary pass/fail

#### Examples

```python
# Exact match (direct from breach database)
checker._check_dictionary("password")      # 0/100 (FAIL)

# Leet speak variation
checker._check_dictionary("p@ssw0rd")       # 0/100 (FAIL - caught!)

# Typo of common password
checker._check_dictionary("passwerd")       # 38/100 (WEAK - caught!)

# Legitimate strong password
checker._check_dictionary("Tr0pic@l!")      # 100/100 (PASS)
```

## Project Structure

```
password_audit_tool/
├── app.py                          # Streamlit web application
├── requirements.txt                # Python dependencies
├── README.md                       # Documentation
├── LICENSE                         # MIT License
├── data/
│   └── common_passwords.txt        # 10k most common passwords database
├── password_tool/
│   ├── checker.py                 # Password strength analysis engine
│   ├── generator.py               # Cryptographic password generation
│   └── __init__.py
├── tests/
│   ├── test_checker.py            # Checker test suite
│   └── test_generator.py          # Generator test suite
└── .gitignore
```

## Testing

Run the test suite:

```bash
pytest tests/ -v
```

With coverage:

```bash
pytest tests/ --cov=password_tool --cov-report=html
```


## Key Concepts

### Entropy
Password entropy is a measure of unpredictability. Higher entropy = harder to crack.

Formula: `entropy = password_length × log₂(charset_size)`

Example:
- "password" (8 chars, lowercase only) = 37 bits (WEAK)
- "MyP@ss123!" (10 chars, mixed types) = 66 bits (STRONG)

Industry standard: 50+ bits acceptable, 70+ bits strong

### Pattern Detection
The tool identifies common weaknesses:
- Keyboard walks: "qwerty", "asdf", "12345"
- Sequential characters: "abc", "xyz"
- Repeated characters: "aaaa", "1111"
- Common substitutions: "p@ssw0rd"

### Time to Crack
Estimated using: `(2^entropy / 2) / 1,000,000,000 guesses per second`

Example:
- 40 bits entropy = ~6 minutes
- 70 bits entropy = ~3 million years

### Fuzzy Matching (RapidFuzz)
Uses token_set_ratio algorithm to find similar strings:
- **100%**: Exact match
- **85-99%**: Nearly identical (dangerous!)
- **80-84%**: Contains dictionary word
- **< 80%**: Acceptable difference

## Security Best Practices

1. **Use minimum 12-16 characters** - Longer = exponentially harder to crack
2. **Mix character types** - Uppercase, lowercase, numbers, special chars
3. **Avoid personal information** - Names, birthdates, phone numbers
4. **No dictionary words** - Especially common ones (fuzzy matched)
5. **Use unique passwords** - Different password for each account
6. **Use a password manager** - Store passwords securely
7. **Enable MFA** - Two-factor authentication adds extra security
8. **Change compromised passwords** - Check haveibeenpwned.com


## Dependencies

- **streamlit**: Web UI framework
- **pandas**: Data processing
- **rapidfuzz**: Fuzzy string matching
- **pytest**: Testing framework
- **requests**: HTTP library (for optional HIBP integration)

See `requirements.txt` for full list.

## Resources

- **NIST Password Guidelines**: https://pages.nist.gov/800-63-3/sp800-63b.html
- **SecLists**: https://github.com/danielmiessler/SecLists
- **RapidFuzz Documentation**: https://maxbachmann.github.io/RapidFuzz/
- **Streamlit Documentation**: https://docs.streamlit.io/

## License

This project is open source and available under the MIT License.

## Contributing

Contributions are welcome! Feel free to:
- Report bugs
- Suggest improvements
- Submit pull requests

## Support

For issues, questions, or suggestions, please open an issue on GitHub.

---


