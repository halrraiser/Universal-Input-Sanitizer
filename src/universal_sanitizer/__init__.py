"""
Universal Input Sanitizer - package entry.
Keep the public API small and simple.
"""

# Core functions
from .sanitizer import sanitize_value, detect_type, language_escape
from .cli import main

# Convenience functions for easy use
from .sanitizer import mask_email, mask_phone

def sanitize(text: str) -> str:
    """
    Sanitize a text value, auto-detecting type.
    Returns a cleaned/masked version of the input.
    """
    _, result = sanitize_value(text)
    return result

def escape_for(text: str, target: str) -> str:
    """
    Return a string literal safe for the given language.
    Example: escape_for('Hello "world"', 'python') -> '"Hello \"world\""' 
    """
    return language_escape(text, target)
