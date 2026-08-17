# MNDe installation

No MSI, NSIS, EXE, DMG, PKG, or AppImage is available. No downloadable npm
tarball is currently published. The current evaluation path is a source
checkout with Node.js 24 or later:

```bash
git clone https://github.com/mndesystems-ship-it/mnde-public-test.git
cd mnde-public-test
npm install
npm run reviewer-kit
```

Start MNDe directly from the checkout with:

```bash
npm run sidecar
```

`npm run release` creates local release-candidate artifacts for release
verification and maintainer publication preparation. Those local artifacts are
not public downloads and are not desktop installers.

See [`docs/RELEASE.md`](../docs/RELEASE.md) for the build and packaged-install
contract.
