import unittest
from universal_sanitizer.sanitizer import mask_email, mask_phone, strip_url_query, detect_type, sanitize_value, language_escape

class TestSanitizer(unittest.TestCase):
    def test_mask_email(self):
        self.assertTrue(mask_email("alice@example.com").startswith("a"))
        self.assertIn("@", mask_email("bob@example.com"))

    def test_mask_phone(self):
        m = mask_phone("+1 (555) 123-4567")
        self.assertIn("*", m)

    def test_strip_url(self):
        self.assertEqual(strip_url_query("https://example.com/path?token=abc"), "https://example.com/path")

    def test_detect(self):
        self.assertEqual(detect_type("user@example.com"), "email")
        self.assertEqual(detect_type("http://a.b"), "url")

    def test_sanitize_json(self):
        kind, s = sanitize_value('{"email":"user@example.com"}')
        self.assertEqual(kind, "json")
        self.assertNotIn("user@example.com", s)

    def test_language_escape(self):
        lit = language_escape('He said "hi"', 'javascript')
        self.assertTrue(lit.startswith('"') and lit.endswith('"'))

if __name__ == "__main__":
    unittest.main()
