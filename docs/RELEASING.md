# Publishing a release

Push a version tag matching `[workspace.package].version` in `Cargo.toml`:

```text
git tag v0.1.1
git push origin v0.1.1
```

The release workflow tests and builds Windows x64 MSVC binaries, packages their
licence notices, generates SHA-256 checksums and build provenance, then publishes
a GitHub release marked **Latest**. The Windows ZIP uses the same asset name in
every release, so the README's direct download link always works. No Apple driver,
download cache or device journal goes into the release. Ordinary pushes and pull
requests run checks only.

The build job has read-only repository access. A separate publish job receives
only the packaged artifacts and the access needed to create the release. Actions
are pinned by full commit hash; Dependabot proposes dependency updates.

The workflow rejects tags that do not match the package version. Do not move a
published tag or replace assets silently: fix the source, increment the version
and release a new tag.

To create the same package locally after a release build:

```powershell
.\scripts\package.ps1 -Version 0.1.1 -BinaryDirectory target\release
```

Files appear in `dist/release`. The script refuses to overwrite an existing
package folder. Use `docs/TESTING.md` for hardware validation and record the results
in `docs/VALIDATION.md`.
