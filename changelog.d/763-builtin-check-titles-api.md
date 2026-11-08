### Changed
- **Breaking** `openmoat-core`: `Notice` has a new public field `next` (`Option<String>`, the person's step where the deciding check has its own; set it to `None` where you build a notice yourself, or start from `Notice::default()`), and `openmoat-hosts` exports `NEVER_SUGGESTED`, the words a block message never suggests ([#763](https://github.com/crocodile-labs/openmoat/pull/763)).
