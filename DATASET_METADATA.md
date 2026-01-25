# Dataset Metadata


## Versioning Policy

- **Current Version**: 1.0.0
- **Schema Version**: 1.1 (frozen)
- **Scenario Version**: 1.0 (frozen)

**Versioning Rules**:
- **Major version** (X.0.0): Schema changes, breaking changes to scenario structure, or addition/removal of scenarios
- **Minor version** (x.Y.0): Addition of new scenarios, non-breaking schema extensions, or significant metadata updates
- **Patch version** (x.y.Z): Bug fixes, documentation updates, or manifest corrections

**Frozen Components** (require major version bump for changes):
- `schema/session_schema.json` - Frozen at version 1.1
- All scenario JSON files in `examples/` - Frozen at version 1.0
- Deterministic generation logic (UUID, timestamp, hash algorithms)

## Usage Notes

- The published dataset contains **30** scenarios under `examples/`, indexed by `dataset_manifest.json`
- All scenario files are deterministic (seed: 1234 is recorded in `session_metadata.determinism.random_seed`)
- Each scenario includes machine-checkable `success_criteria` and `failure_conditions` in the manifest
- Validation requires AJV v8.x with the provided preprocessing logic
- See `README.md` for detailed usage instructions and `REVIEWER_CHECKLIST.md` for evaluation procedures
