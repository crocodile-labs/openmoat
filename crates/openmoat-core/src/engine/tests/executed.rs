//! `CompiledPolicy::executed`: the files a call runs as code, resolved like
//! the paths of reads and writes (ADR-039).

use std::collections::BTreeMap;

use super::{ctx, policy, shell};
use crate::realpath::MapPathResolver;
use crate::{Action, CompiledPolicy, NoResolver};

fn executed(command: &str, paths: &MapPathResolver) -> Vec<String> {
    let p = policy("version: 1\n");
    let compiled = CompiledPolicy::compile(&p, &ctx()).unwrap();
    compiled.executed(&shell(command), paths)
}

#[test]
fn a_script_is_found_under_its_literal_and_its_real_path() {
    let paths = MapPathResolver {
        links: BTreeMap::from([("/p/tools".to_owned(), "/p/.cache/t".to_owned())]),
        ..MapPathResolver::default()
    };
    assert_eq!(
        executed("python3 tools/x.py", &paths),
        ["/p/.cache/t/x.py", "/p/tools/x.py"]
    );
    // a `..` is followed where the OS goes, up from where the link points, as
    // well as collapsed as written, as the read of it is
    assert_eq!(
        executed("bash tools/../x.sh", &paths),
        ["/p/.cache/x.sh", "/p/x.sh"]
    );
}

#[test]
fn a_glob_operand_is_the_files_it_names() {
    let paths = MapPathResolver {
        files: vec![
            "/p/a.sh".to_owned(),
            "/p/b.sh".to_owned(),
            "/p/c.txt".to_owned(),
        ],
        ..MapPathResolver::default()
    };
    assert_eq!(
        executed("bash *.sh", &paths),
        ["/p/*.sh", "/p/a.sh", "/p/b.sh"]
    );
}

#[test]
fn only_shell_commands_run_files() {
    let p = policy("version: 1\n");
    let compiled = CompiledPolicy::compile(&p, &ctx()).unwrap();
    let read = Action::FsRead {
        path: "/p/x.py".to_owned(),
    };
    assert!(compiled.executed(&read, &NoResolver).is_empty());
    assert!(compiled.executed(&shell("ls -la"), &NoResolver).is_empty());
    assert_eq!(compiled.executed(&shell("./x"), &NoResolver), ["/p/x"]);
}
