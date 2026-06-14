# Changesets

This directory is managed by [Changesets](https://github.com/changesets/changesets).

To record a change for the next release:

```bash
npm run changeset
```

Select the affected package(s), the semver bump type, and write a human-readable
summary. The CI release workflow consumes these files to version and publish.
