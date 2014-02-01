from .utils import TestCase
from dynsupdate import client


PSEUDO_KEY = """
key "keyname" {
    algorithm hmac-sha256;
    secret "keyhere";
};
"""

PSEUDO_KEY_MIXED_CASE = """
keY "keyname" {
    alGorithm hMaC-sHa256;
    sEcrEt "keyhere";
};
"""

PSEUDO_KEY2 = """
key "keyname" {
    secret "keyhere";
    algorithm hmac-sha256;
};
"""

PSEUDO_KEYS = """
key "one" {
    secret "keyhere";
    algorithm hmac-md5;
};

key "two" {
    algorithm hmac-sha512;
    secret "keyhere";
};

key "three" {secret "keyhere"; algorithm hmac-sha384;};
key "four" { algorithm hmac-sha224; secret "keyhere"; };
"""


class KeyConfigTests(TestCase):

    def test_tokenize(self):
        tokens = []
        for m, token_id in client.KeyConfig.tokenize(PSEUDO_KEY):
            tokens.append((m.group(), token_id))

        TOKENS_ENUM = client.KeyConfig.Tokens

        VALID_TOKENS = (
            TOKENS_ENUM.SPACE,
            (TOKENS_ENUM.KEYWORD, "key"),
            TOKENS_ENUM.SPACE,
            (TOKENS_ENUM.STRING, '"keyname"'),
            TOKENS_ENUM.SPACE,
            TOKENS_ENUM.BLOCK_BEGIN,
            TOKENS_ENUM.SPACE,
            (TOKENS_ENUM.KEYWORD, "algorithm"),
            TOKENS_ENUM.SPACE,
            (TOKENS_ENUM.KEYWORD, "hmac-sha256"),
            TOKENS_ENUM.END_COMMAND,
            TOKENS_ENUM.SPACE,
            (TOKENS_ENUM.KEYWORD, "secret"),
            TOKENS_ENUM.SPACE,
            (TOKENS_ENUM.STRING, '"keyhere"'),
            TOKENS_ENUM.END_COMMAND,
            TOKENS_ENUM.SPACE,
            TOKENS_ENUM.BLOCK_END,
            TOKENS_ENUM.END_COMMAND,
        )

        for (g_text, g_token_id), valid in zip(tokens, VALID_TOKENS):
            if isinstance(valid, tuple):
                s_token_id, text = valid
                self.assertEqual(g_text, text)
            else:
                s_token_id = valid

            self.assertEqual(g_token_id, s_token_id)

    def test_parse(self):
        def check(parser):
            self.assertTupleEqual(tuple(parser.keys.keys()), ("keyname",))
            key = parser.get_key()
            self.assertEqual(key.algorithm, "hmac-sha256")
            self.assertEqual(key.key, "keyhere")

        parser = client.KeyConfigParser.parse_keys(PSEUDO_KEY)
        check(parser)

        parser = client.KeyConfigParser.parse_keys(PSEUDO_KEY2)
        check(parser)

        parser = client.KeyConfigParser.parse_keys(PSEUDO_KEY_MIXED_CASE)
        check(parser)

    def test_parse_multiple(self):
        parser = client.KeyConfigParser.parse_keys(PSEUDO_KEYS)
        self.assertTupleEqual(
            tuple(parser.keys_names),
            ("one", "two", "three", "four",)
        )

        key = parser.keys['one']
        self.assertTupleEqual(
            (key.algorithm, key.key),
            ("hmac-md5", "keyhere")
        )

        key = parser.keys['two']
        self.assertTupleEqual(
            (key.algorithm, key.key),
            ("hmac-sha512", "keyhere")
        )

        key = parser.keys['three']
        self.assertTupleEqual(
            (key.algorithm, key.key),
            ("hmac-sha384", "keyhere")
        )

        key = parser.keys['four']
        self.assertTupleEqual(
            (key.algorithm, key.key),
            ("hmac-sha224", "keyhere")
        )
