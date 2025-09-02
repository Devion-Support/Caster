# Contributing

We welcome contributions to Caster! This document provides guidelines for contributing to the project.

## Code of Conduct

Please read and follow our [Code of Conduct](code-of-conduct.md) to ensure a welcoming environment for all contributors.

## How to Contribute

### Reporting Issues

If you find a bug or have a feature request, please [open an issue](https://github.com/yoganataa/caster/issues) on GitHub. Before creating a new issue, please check if one already exists.

When reporting bugs, please include:

- A clear description of the issue
- Steps to reproduce the problem
- Expected vs. actual behavior
- Device and Android version information
- Caster version being used

### Suggesting Enhancements

Feature requests are welcome! Please [open an issue](https://github.com/yoganataa/caster/issues) describing:

- The problem the feature would solve
- A clear description of the proposed solution
- Any alternative solutions considered
- How the feature would benefit users

## Development Setup

### Prerequisites

- Android Studio or compatible IDE
- Android SDK API level 27 or higher
- Kotlin 1.5+ (recommended)
- Gradle 7.0+
- Android NDK for native code development

### Building the Project

1. Clone the repository:

   ```bash
   git clone https://github.com/yoganataa/caster.git
   ```

2. Open the project in Android Studio

3. Sync the project with Gradle files

4. Build the project:

   ```bash
   ./gradlew build
   ```

### Running Tests

Run unit tests:

```bash
./gradlew test
```

Run instrumentation tests:

```bash
./gradlew connectedAndroidTest
```

Generate code coverage reports:

```bash
./gradlew jacocoTestReport
```

## Code Style and Quality

### Coding Standards

- Follow Kotlin coding conventions
- Use descriptive variable and function names
- Write clear, concise comments for complex logic
- Maintain consistent code formatting

### Code Quality Tools

The project uses several tools to ensure code quality:

- **Detekt**: Static code analysis for Kotlin
- **Lint**: Android lint checks
- **Ktlint**: Kotlin code formatting

Run code quality checks:

```bash
./gradlew detekt
./gradlew lint
```

### Documentation

- Update documentation when adding or modifying features
- Write clear, concise documentation
- Include examples where appropriate
- Keep documentation up to date with code changes

## Making Changes

### Branching Strategy

1. Fork the repository
2. Create a feature branch from `main`:

   ```bash
   git checkout -b feature/your-feature-name
   ```

3. Make your changes
4. Commit your changes with clear, descriptive messages
5. Push to your fork
6. Create a pull request

### Commit Messages

Follow conventional commit messages:

- `feat:` for new features
- `fix:` for bug fixes
- `docs:` for documentation changes
- `style:` for formatting changes
- `refactor:` for code refactoring
- `test:` for adding or modifying tests
- `chore:` for maintenance tasks

Example:

```txt
feat: Add new root detection method

- Implement additional binary check locations
- Update confidence scoring algorithm
- Add unit tests for new detection method
```

### Pull Request Process

1. Ensure your code follows the project's coding standards
2. Write clear, descriptive pull request titles and descriptions
3. Include information about what changes were made and why
4. Reference any related issues
5. Ensure all tests pass
6. Request review from maintainers

## Native Code Development

### C++ Coding Standards

- Follow modern C++ best practices
- Use RAII for resource management
- Prefer const-correctness
- Use safe string handling functions
- Avoid raw pointers when possible

### Security Considerations

- Validate all inputs from Kotlin layer
- Prevent buffer overflows
- Use secure memory handling
- Avoid information leakage through error messages

### Testing Native Code

- Write unit tests for C++ functions
- Test edge cases and error conditions
- Validate memory safety
- Benchmark performance-critical functions

## Testing Guidelines

### Unit Tests

- Write unit tests for new functionality
- Test edge cases and error conditions
- Maintain high test coverage
- Use descriptive test names

### Integration Tests

- Test integration between Kotlin and native layers
- Verify correct data exchange
- Test error handling across layers

### Performance Tests

- Benchmark performance-critical operations
- Test on various device configurations
- Monitor memory usage
- Validate timeout behavior

## Documentation Guidelines

### API Documentation

- Document all public APIs
- Include parameter and return value descriptions
- Provide usage examples
- Keep documentation synchronized with code changes

### User Documentation

- Write clear, concise documentation
- Include practical examples
- Organize content logically
- Keep documentation up to date

## Security Considerations

### Code Review

All contributions undergo security review:

- Validate input handling
- Check for potential vulnerabilities
- Review native code security
- Ensure proper error handling

### Vulnerability Reporting

If you discover a security vulnerability, please report it responsibly:

1. Do not create a public issue
2. Contact the maintainers directly
3. Provide detailed information about the vulnerability
4. Allow time for a fix before public disclosure

## Community

### Communication

- Join our community discussions
- Participate in code reviews
- Help other contributors
- Share knowledge and best practices

### Recognition

Contributors are recognized in:

- Release notes
- Contributor list
- Documentation credits

## License

By contributing to Caster, you agree that your contributions will be licensed under the MIT License.

## Getting Help

If you need help with contributing:

- Check the documentation
- Review existing issues and pull requests
- Ask questions in issues or discussions
- Contact the maintainers directly

Thank you for contributing to Caster!
