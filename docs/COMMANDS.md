# LeakLens Commands

A quick copy-paste guide for the most useful LeakLens commands.

## Beginner

```powershell
cd F:\dev\cv_output\leaklens
cargo run -p leaklens-cli -- scan .\some-folder
```

Scans a normal directory recursively.

```powershell
cd F:\dev\cv_output\leaklens
cargo run -p leaklens-cli -- scan .\some-repo --history
```

Scans a git repo working tree and its commit history.

```powershell
cd F:\dev\cv_output\leaklens
cargo run -p leaklens-cli -- scan .\some-repo --history --summary-only
```

Prints the console summary only and skips JSON, HTML, and SARIF outputs.

## Practical

```powershell
cd F:\dev\cv_output\leaklens
cargo run -p leaklens-cli -- scan .\some-folder --json .\reports\scan.json --html .\reports\scan.html
```

Scans a normal folder and writes JSON and HTML reports.

```powershell
cd F:\dev\cv_output\leaklens
cargo run -p leaklens-cli -- scan .\some-git-repo --history --sarif .\reports\scan.sarif
```

Scans a git repo with history and writes SARIF output for CI or code-scanning tools.

```powershell
cd F:\dev\cv_output\leaklens
cargo run -p leaklens-cli -- scan .\some-git-repo --baseline .\reports\previous.json
```

Suppresses findings already present in a previous LeakLens JSON report.

```powershell
cd F:\dev\cv_output\leaklens
cargo run -p leaklens-cli -- scan .\some-folder --ignore-file .\docs\leaklensignore.example
```

Skips files matching wildcard patterns from an ignore file.

## Scope Control

```powershell
cd F:\dev\cv_output\leaklens
cargo run -p leaklens-cli -- scan .\some-folder --no-recursive
```

Only scans files directly inside the target path.

```powershell
cd F:\dev\cv_output\leaklens
cargo run -p leaklens-cli -- scan .\some-folder --max-depth 2
```

Scans recursively, but only two levels below the target root.

```powershell
cd F:\dev\cv_output\leaklens
cargo run -p leaklens-cli -- scan .\some-folder --include *.env --include *.tfvars
```

Only scans files whose relative paths match those wildcard patterns.

```powershell
cd F:\dev\cv_output\leaklens
cargo run -p leaklens-cli -- scan .\some-folder --exclude */logs/* --exclude *.pem
```

Skips files matching those wildcard patterns.

## Git-Focused Examples

```powershell
cd F:\dev\cv_output\leaklens
cargo run -p leaklens-cli -- scan .\some-repo
```

Scans only the current working tree of a repo.

```powershell
cd F:\dev\cv_output\leaklens
cargo run -p leaklens-cli -- scan .\some-repo --history-only
```

Scans only commit history to find secrets removed from the live repo.

```powershell
cd F:\dev\cv_output\leaklens
cargo run -p leaklens-cli -- scan .\some-repo --history --summary-only
```

Useful for fast triage without writing artifacts.

## Public Test Repos

```powershell
cd F:\labs
git clone https://github.com/Yelp/detect-secrets.git
git clone https://github.com/awslabs/git-secrets.git
git clone https://github.com/gitleaks/fake-leaks.git
```

Then scan them with:

```powershell
cd F:\dev\cv_output\leaklens
cargo run -p leaklens-cli -- scan F:\labs\detect-secrets\test_data
cargo run -p leaklens-cli -- scan F:\labs\git-secrets\test
cargo run -p leaklens-cli -- scan F:\labs\fake-leaks --history --summary-only
```

## What The Main Flags Do

- `--history`: include git commit history
- `--history-only`: scan only git history, not the live working tree
- `--summary-only`: print CLI output only, no report files
- `--json <path>`: write a JSON report
- `--html <path>`: write an HTML report
- `--sarif <path>`: write a SARIF report
- `--ignore-file <path>`: load wildcard ignore rules from a file
- `--baseline <path>`: suppress findings already present in a previous report
- `--no-recursive`: scan only the top level of the target path
- `--max-depth <n>`: limit recursive depth
- `--include <pattern>`: only scan matching paths
- `--exclude <pattern>`: skip matching paths

## Suggested First 3 Runs

```powershell
cd F:\dev\cv_output\leaklens
cargo run -p leaklens-cli -- scan .
cargo run -p leaklens-cli -- scan .\some-repo --history
cargo run -p leaklens-cli -- scan F:\labs\detect-secrets\test_data --summary-only
```
