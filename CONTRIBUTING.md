# Contributing to IFRIT

We welcome contributions! This document explains how to contribute effectively.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/ifrit.git`
3. Create a feature branch: `git checkout -b feature/your-feature develop`
4. Make your changes
5. Push to your fork
6. Create a Pull Request to `develop` branch

## Development Setup
```bash
# Clone repository
git clone https://github.com/0tSystemsPublicRepos/ifrit.git
cd ifrit

# Switch to develop branch
git checkout develop

# Install dependencies
go mod download

# Build the project
go build -o ifrit ./cmd/ifrit

# Run tests
go test ./...
```

## Branch Strategy

- **main**: Stable releases only (tagged with versions)
- **develop**: Development branch for next release
- **feature/xxx**: Create from `develop`, PR back to `develop`
- **release/vX.Y.Z**: Release candidates, merge to `main` and back to `develop`
- **hotfix/xxx**: Critical fixes, branch from `main`

## Code Standards

- Follow Go conventions: https://golang.org/doc/effective_go
- Run `go fmt ./...` before committing
- Run `go vet ./...` to check for issues
- Write tests for new features
- Keep commits atomic and well-described

## Commit Messages

Use descriptive commit messages:
```
feat: Add new feature
fix: Fix bug in module
docs: Update documentation
test: Add tests for feature
refactor: Refactor module
chore: Update dependencies
```

## Pull Request Process

1. Update CHANGELOG.md with your changes
2. Ensure all tests pass: `go test ./...`
3. Add description of changes in PR
4. Link related issues if applicable
5. Wait for review and address feedback
6. Maintainer will merge when approved

## Reporting Issues

- Use GitHub Issues for bug reports
- Include steps to reproduce
- Include your environment details
- Include error messages and logs

## Security Issues

For security vulnerabilities, email ifrit@0t.systems instead of using public issues.

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.

