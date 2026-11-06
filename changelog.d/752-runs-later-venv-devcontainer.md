### Security
- An agent's write to a virtual environment's interpreter and scripts (`.venv/bin/`, `venv/bin/`), which the editor's Python extension starts outside any sandbox, or to a dev container's configuration (`.devcontainer/`, `.devcontainer.json`), whose `initializeCommand` runs on this machine, needs review (`runs-later`) ([#752](https://github.com/crocodile-labs/openmoat/pull/752)).
