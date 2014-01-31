from .utils import TestCase
from dynsupdate import client


PSEUDO_KEY = """
key "keyname" {
    algorithm hmac-sha256;
    secret "keyhere";
};
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
