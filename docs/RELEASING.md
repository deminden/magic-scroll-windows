# Publishing a release

Push a version tag matching `[workspace.package].version` in `Cargo.toml`:

```text
git tag v0.1.0
git push origin v0.1.0
```

The release workflow tests and builds Windows x64 MSVC binaries, packages their
licence notices, generates SHA-256 checksums and build provenance, then publishes
an experimental GitHub prerelease. No Apple driver, download cache or device
journal goes into the release. Ordinary pushes and pull requests run checks only.

The build job has read-only repository access. A separate publish job receives
only the packaged artifacts and the access needed to create the release. Actions
are pinned by full commit hash; Dependabot proposes dependency updates.

The workflow rejects tags that do not match the package version. Do not move a
published tag or replace assets silently: fix the source, increment the version
and release a new tag. This workflow does not provide Authenticode signing.

To create the same package locally after a release build:

```powershell
.\scripts\package.ps1 -Version 0.1.0 -BinaryDirectory target\release
```

Files appear in `dist/release`. The script refuses to overwrite an existing
package folder. Check `docs/TESTING.md` and update `docs/VALIDATION.md` honestly
before changing experimental status or expanding compatibility claims.
