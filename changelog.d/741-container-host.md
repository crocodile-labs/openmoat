### Security
- `docker`, `podman` and `nerdctl` commands that give a container the host (`--privileged`, a host namespace, `--cap-add`, `--device`, `--security-opt`, the host's root or the Docker socket mounted in) need review (`container-host`); other container runs still defer ([#741](https://github.com/crocodile-labs/openmoat/pull/741)).
