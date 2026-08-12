# Tokenizers

Optional. `context_budget.estimate_tokens` uses a real tokenizer when
`DOCKET_TOKENIZER_PATH` points at one, and falls back to `CHARS_PER_TOKEN` otherwise.

`deepseek-v3.json` is DeepSeek's published V3 tokenizer. Measured against the live
**V4 Pro** endpoint it is accurate to ~1-2% on prose, code, JSON and HTTP, with a
constant 4-token chat-template overhead — so it is the right encoder for V4 too. The
`chars/4` fallback undercounts JSON by ~38% and raw HTTP by ~40%, which is exactly the
content an agent conversation is made of.

    export DOCKET_TOKENIZER_PATH=engine/docket/llm/tokenizers/deepseek-v3.json

Needs `pip install tokenizers` (small, Rust-backed — NOT the much heavier
`transformers`, which DeepSeek's own snippet uses). Without the package the loader
returns None and the character estimate is used, so nothing breaks.

Using a different model? Drop its `tokenizer.json` here and repoint the variable.
Verify before trusting it: tokenize a sample, compare with `usage.prompt_tokens` from
a one-token completion, and check the delta is small and constant.
