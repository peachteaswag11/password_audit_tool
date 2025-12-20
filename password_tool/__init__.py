"""
Password Audit Tool Package
Professional-grade password strength checker and generator
"""

from password_tool.checker import PasswordChecker
from password_tool.generator import PasswordGenerator, PasswordStrength

__version__ = "1.0.0"
__author__ = "Your Name"
__description__ = "Professional password strength checker and generator"

__all__ = [
    'PasswordChecker',
    'PasswordGenerator',
    'PasswordStrength',
]
