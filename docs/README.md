# Caster Documentation

Welcome to the official documentation for Caster, a comprehensive Android security library designed to provide robust device security analysis and threat detection.

## What is Caster?

Caster is an advanced Android security library that offers enhanced security features implemented in native C++ code for maximum protection against reverse engineering and tampering. It provides a modular, lightweight solution for detecting rooted devices, emulators, malicious applications, and various security threats.

## Key Features

- **Root Detection**: Comprehensive detection of rooted devices including Magisk, SuperSU, and KernelSU
- **Emulator Detection**: Advanced detection of Android emulators and virtualized environments
- **Anti-Tampering**: Protection against debugging, hooking frameworks (Frida/Xposed), and code injection
- **Integrity Checks**: Verification of application signatures, APK integrity, and system partition status
- **Malicious App Detection**: Scanning for known malicious applications and suspicious behaviors
- **Flag Secure Detection**: Protection against screen recording and screenshot bypasses
- **Native Implementation**: Core security logic implemented in C++ for enhanced protection
- **Modular Design**: Easy integration as a separate library module
- **Privacy Protection**: Minimal data collection with local processing

## Documentation Structure

This documentation is organized into the following sections:

- [Getting Started](getting-started/README.md) - Installation and basic usage
- [Core Concepts](core-concepts/README.md) - Understanding how Caster works
- [API Reference](api/README.md) - Detailed API documentation
- [Security Features](security-features/README.md) - In-depth look at each security feature
- [Native Implementation](native-implementation/README.md) - Details about the C++ native code
- [Configuration](configuration/README.md) - Customizing Caster behavior
- [Best Practices](best-practices/README.md) - Security best practices and recommendations
- [Contributing](contributing/README.md) - How to contribute to the project

## Quick Links

- [GitHub Repository](https://github.com/yoganataa/caster)
- [Release Notes](changelog/README.md)
- [License](license/README.md)

## Support

If you encounter any issues or have questions about Caster, please [open an issue](https://github.com/yoganataa/caster/issues) on GitHub.
