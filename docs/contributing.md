# Contributing

We welcome contributions to ClosedSSPM! Whether you are fixing a bug, adding a new platform connector, or improving documentation, your help is appreciated.

## Contribution Guidelines

Follow these steps:

1. **Open an Issue**: Before starting work on a significant change, please open an issue to discuss your proposal with the maintainers. This helps avoid duplicate work and ensures the change aligns with the project's goals.
2. **Fork and Branch**: Fork the repository and create a new branch from `main` for your changes.
3. **Follow Existing Patterns**: Maintain the architectural style of the project. If you are adding a new connector, use the existing ones as a template.
4. **Add Tests**: All new features and bug fixes must include corresponding tests.
5. **CI Checks**: Ensure that all continuous integration checks pass, including:
    - Unit tests
    - `go vet`
    - CodeQL analysis
    - Trivy vulnerability scans
6. **One PR Per Change**: Keep your pull requests focused on a single logical change. This makes it easier to review and merge your contribution.

## Testing Your Changes

Before submitting your pull request, run the following commands to verify your changes:

- Run all unit tests:
  ```bash
  make test
  ```
  Or using the Go CLI:
  ```bash
  go test ./...
  ```
- Run static analysis:
  ```bash
  make vet
  ```
  Or using the Go CLI:
  ```bash
  go vet ./...
  ```

## Reporting Issues

If you find a bug or have a feature request, please use the GitHub Issues page. When reporting an issue, include as much information as possible:

- The version of ClosedSSPM you are using.
- Your operating system.
- Clear steps to reproduce the issue.
- What you expected to happen vs. what actually happened.
- Any relevant error messages or output.

!!! note
    If you discover a security vulnerability, please follow the process outlined on our [Security](security.md) page.

## License

By contributing to ClosedSSPM, you agree that your contributions will be licensed under its Apache 2.0 License.
