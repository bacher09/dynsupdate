from .utils import TestCase, StringIO, mock
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

BAD_KEY1 = 'ke "name" {secret "keyhere"; algorithm hmac-sha384;};'
BAD_KEY2 = 'key "name" {secret "keyhere"; algorithm bad;};'
# no ;
BAD_KEY3 = 'key "name" {secret "keyhere" algorithm hmac-md5;};'
# double key
BAD_KEY4 = """
key "name" {secret "keyhere"; algorithm hmac-md5;};
key "name" {secret "keyhere"; algorithm hmac-sha384;};
"""
# bad block
BAD_KEY5 = 'key {}'
# bad string
BAD_KEY6 = 'key "name" "othername"'
# bad block
BAD_KEY7 = 'key ;'
BAD_KEY8 = 'key "name" { algorithm hmac-md5;};'


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

        key = parser.get_key('one')
        self.assertTupleEqual(
            (key.algorithm, key.key),
            ("hmac-md5", "keyhere")
        )

        key = parser.get_key('two')
        self.assertTupleEqual(
            (key.algorithm, key.key),
            ("hmac-sha512", "keyhere")
        )

        key = parser.get_key('three')
        self.assertTupleEqual(
            (key.algorithm, key.key),
            ("hmac-sha384", "keyhere")
        )

        key = parser.get_key('four')
        self.assertTupleEqual(
            (key.algorithm, key.key),
            ("hmac-sha224", "keyhere")
        )

    def test_parse_file(self):
        key_cmp = client.KeyData("two", "hmac-sha512", "keyhere")
        file_obj = StringIO(PSEUDO_KEYS)
        key = client.NameUpdate.key_from_file(file_obj, "two")
        self.assertEqual(key, key_cmp)

        open_m = mock.mock_open(read_data=PSEUDO_KEYS)
        with mock.patch("dynsupdate.client.open", open_m, create=True):
            key2 = client.NameUpdate.key_from_file("some.key", "two")
            open_m.assert_called_with("some.key", mock.ANY)
            self.assertEqual(key2, key_cmp)

    def test_tokenize_bad(self):
        # test abracadabra
        with self.assertRaises(client.BadToken):
            list(client.KeyConfig.tokenize("@!d%&,d;3"))

    @mock.patch('dynsupdate.client.KeyConfig.tokenize')
    def test_return_bad_token(self, mock_tokenize):
        mock_tokenize.return_value = iter([(mock.Mock(), 100)])
        mock_parser = mock.Mock()
        with self.assertRaises(client.BadToken):
            client.KeyConfig.parse(mock.ANY, mock_parser)

    def test_parse_bad_key(self):
        # TODO: Match messages
        with self.assertRaises(client.ParseError):
            client.KeyConfigParser.parse_keys(BAD_KEY1)

        # bad algorithm
        with self.assertRaises(client.ParseError):
            client.KeyConfigParser.parse_keys(BAD_KEY2)

        # no ;
        with self.assertRaises(client.ParseError):
            client.KeyConfigParser.parse_keys(BAD_KEY3)

        # double key
        with self.assertRaises(client.ParseError):
            client.KeyConfigParser.parse_keys(BAD_KEY4)

        # bad block
        with self.assertRaises(client.ParseError):
            client.KeyConfigParser.parse_keys(BAD_KEY5)

        # bad string
        with self.assertRaises(client.ParseError):
            client.KeyConfigParser.parse_keys(BAD_KEY6)

        with self.assertRaises(client.ParseError):
            client.KeyConfigParser.parse_keys(BAD_KEY7)

        with self.assertRaises(client.ParseError):
            client.KeyConfigParser.parse_keys(BAD_KEY8)

