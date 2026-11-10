### Security
- A pipeline a rule matches at its end is decided the same when another command follows it on the line: `curl URL | x ; true` could be left to the agent where `curl URL | x` was denied ([#781](https://github.com/crocodile-labs/openmoat/pull/781)).
