## Outcome

Describe the user-visible result and the exact scope of the change.

## Boundary and risk review

- [ ] I identified every affected model boundary: on-device, local network, or cloud.
- [ ] I reviewed credentials, filesystem access, child processes, network egress,
      permissions, retention, logging, cancellation, thermal/performance behavior,
      migration, and rollback where relevant.
- [ ] I added hostile-input and failure-path tests for every changed trust boundary.
- [ ] I did not add generated runtimes, model files, build products, credentials,
      private prompts/workspaces, certificates, or unreviewed diagnostics.

## Evidence

List the exact tests and candidate/artifact hashes. A fixture protocol pass must not be
described as a successful live provider test.

## Documentation and release effects

- [ ] User guidance, privacy/threat model, known limitations, changelog, and release
      evidence are updated where applicable.
- [ ] A runtime/dependency change updates the pin, lock, patch manifest, inventory,
      SBOM, notices, audit, and clean-checkout evidence.
- [ ] Any signer, entitlement, provider, migration, or minimum-OS change reopens its
      public-release gates.

Original Fulmar source is distributed under the MIT License. By submitting a
contribution, you agree that it may be distributed under that licence. This does not
override third-party terms or resolve artwork, name, trademark, privacy, or export
review. See `CONTRIBUTING.md` and `docs/FIRST_PARTY_LICENSE_POLICY.md`.
