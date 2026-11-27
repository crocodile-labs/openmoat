### Changed
- Compiling a policy builds each glob text once and shares it, and its regex, with every pattern that names the same text: an anchor's list under two kinds, a `dir/**` beside its `dir`, a path in a deny rule and in the taint list, a shell program in many rules. No decision or error changes ([#0](https://github.com/crocodile-labs/openmoat/pull/0)).
