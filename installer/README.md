# MNDe Desktop Release Downloads

Desktop installer binaries are distributed through GitHub Releases, not committed to this repository.

Download the current release artifact from:

```text
https://github.com/mndesystems-ship-it/mnde-public-test/releases
```

Verify the downloaded file before running it:

```bash
sha256sum <downloaded-file>
```

On Windows PowerShell:

```powershell
Get-FileHash <downloaded-file> -Algorithm SHA256
```

Compare the output with the SHA-256 value published in the release notes.

The command-line reviewer proof does not require the desktop app:

```bash
npm run reviewer-kit
```

Optional desktop smoke testing can be run after downloading a release executable:

```bash
MNDE_DESKTOP_EXE=/path/to/MNDe-Execution-Control.exe npm run desktop-smoke
```
