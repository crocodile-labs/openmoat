### Security
- `echo … | base64 <-d | sh ; true` was held for review where the same line without `; true` was denied: a decoder's dash-word after a redirection now counts as its flag ([#775](https://github.com/crocodile-labs/openmoat/pull/775)).
