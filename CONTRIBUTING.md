# Contributing to NanOS

Thank you for your interest in contributing to NanOS! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Process](#development-process)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Submitting Changes](#submitting-changes)
- [Documentation](#documentation)

## Code of Conduct

This project adheres to a Code of Conduct that all contributors are expected to follow. Please be respectful, inclusive, and constructive in all interactions.

## Getting Started

### Prerequisites

Before contributing, ensure you have the following installed:

**For x86 Development:**
- GCC cross-compiler (i686-elf-gcc)
- GNU Make
- QEMU (for testing)
- GRUB tools (grub-mkrescue, xorriso)

**For ARM Development:**
- arm-none-eabi-gcc toolchain
- QEMU with ARM support

**For ESP32 Development:**
- ESP-IDF v5.0+
- PlatformIO (optional)

### Setting Up Your Development Environment

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/nanOs.git
   cd nanOs
   ```

3. Add the upstream repository:
   ```bash
   git remote add upstream https://github.com/sotomayorlucas/nanOs.git
   ```

4. Build the project:
   ```bash
   make        # x86 version
   make arm    # ARM version
   ```

5. Test your build:
   ```bash
   make run    # Single x86 node
   make swarm  # 3-node x86 swarm
   ```

## Development Process

### Branching Strategy

- `main` - Stable production-ready code
- `develop` - Integration branch for features
- `feature/*` - New features
- `bugfix/*` - Bug fixes
- `docs/*` - Documentation improvements

### Workflow

1. Create a new branch from `develop`:
   ```bash
   git checkout develop
   git pull upstream develop
   git checkout -b feature/your-feature-name
   ```

2. Make your changes, following the coding standards

3. Test your changes thoroughly:
   ```bash
   make clean
   make
   make test  # If tests exist
   ```

4. Commit your changes with descriptive messages:
   ```bash
   git add .
   git commit -m "feat: add new feature description"
   ```

5. Push to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

6. Create a Pull Request on GitHub

## Coding Standards

### General Principles

- **Minimalism**: Keep code simple and focused
- **Readability**: Write code that others can understand
- **Safety**: Always validate inputs and handle errors
- **Performance**: Be mindful of resource constraints (RAM, CPU)

### C Code Style

```c
// Use K&R style bracing
void function_name(int param) {
    if (condition) {
        // code
    } else {
        // code
    }
}

// Use descriptive variable names
uint32_t packet_count = 0;  // Good
uint32_t pc = 0;             // Avoid

// Document complex logic
// Calculate HMAC for packet authentication using SHA256
hmac_sha256(key, key_len, data, data_len, output);

// Use const where appropriate
const char* get_role_name(uint8_t role);

// Prefer fixed-size types
uint8_t  byte_value;   // Not: char, unsigned char
uint32_t counter;      // Not: int, unsigned int
```

### Naming Conventions

- **Functions**: `lowercase_with_underscores`
- **Variables**: `lowercase_with_underscores`
- **Constants**: `UPPERCASE_WITH_UNDERSCORES`
- **Types**: `lowercase_with_underscores_t`
- **Macros**: `UPPERCASE_WITH_UNDERSCORES`

### File Organization

```
nanOs/
├── arch/           # Architecture-specific code
│   ├── x86/
│   ├── arm-qemu/
│   └── esp32/
├── kernel/         # Core kernel functionality
├── drivers/        # Hardware drivers
├── include/        # Public header files
├── lib/            # Utility libraries
└── docs/           # Documentation
```

### Header Files

- Use include guards:
  ```c
  #ifndef NANOS_MODULE_H
  #define NANOS_MODULE_H
  
  // declarations
  
  #endif // NANOS_MODULE_H
  ```

- Include order: system headers, then project headers
- Document all public functions in headers

### Memory Management

- Always check malloc/heap_alloc return values
- Free allocated memory when done
- Be aware of the apoptosis threshold (90% heap usage)
- Prefer stack allocation for small, short-lived data

### Security Considerations

- Validate all network input
- Use constant-time comparisons for cryptographic operations
- Zero sensitive data after use
- Check HMAC on authenticated packets
- Implement rate limiting for command handlers

## Testing Guidelines

### Manual Testing

Before submitting a PR, test:

1. **Single Node**: `make run`
   - Verify boot sequence
   - Check heartbeat transmission
   - Monitor memory usage

2. **Multi-Node Swarm**: `make swarm`
   - Verify node discovery
   - Test message propagation
   - Check gossip deduplication

3. **Dashboard**: `make dashboard`
   - Test control commands
   - Verify visualization updates
   - Check API endpoints

### Platform-Specific Testing

- **x86**: Test with QEMU e1000 networking
- **ARM**: Test with Stellaris Ethernet
- **ESP32**: Test with actual hardware if available

### Test Coverage Areas

- [ ] Packet parsing and validation
- [ ] HMAC verification
- [ ] Role assignment
- [ ] Gossip protocol
- [ ] Apoptosis/rebirth
- [ ] Command authentication
- [ ] Memory leak detection

## Submitting Changes

### Pull Request Guidelines

1. **Title**: Use conventional commits format:
   - `feat: add new feature`
   - `fix: resolve bug`
   - `docs: update documentation`
   - `refactor: improve code structure`
   - `test: add tests`

2. **Description**: Include:
   - What changes were made
   - Why the changes were necessary
   - How to test the changes
   - Any breaking changes

3. **Checklist**:
   - [ ] Code builds without warnings
   - [ ] Code follows project style guidelines
   - [ ] Changes tested on target platform(s)
   - [ ] Documentation updated if needed
   - [ ] No unnecessary files added (build artifacts, etc.)

### Review Process

1. Maintainers will review your PR
2. Address any feedback or requested changes
3. Once approved, your PR will be merged

## Documentation

### Code Documentation

- Document all public functions:
  ```c
  /**
   * Calculates HMAC-SHA256 for packet authentication.
   * 
   * @param key Shared secret key
   * @param key_len Length of key in bytes
   * @param data Data to authenticate
   * @param data_len Length of data
   * @param output Buffer for 32-byte HMAC output
   */
  void hmac_sha256(const uint8_t* key, size_t key_len,
                   const uint8_t* data, size_t data_len,
                   uint8_t* output);
  ```

- Use inline comments for complex algorithms
- Keep comments up-to-date with code changes

### README and Guides

When updating documentation:

- Use clear, concise language
- Include code examples where helpful
- Update table of contents if adding sections
- Test all commands and code snippets
- Add diagrams for complex concepts

### LaTeX Manual

The technical manual is in `docs/manual/`:

- Follow existing structure and style
- Build with `make` in the manual directory
- Include TikZ diagrams for visualizations
- Cross-reference sections with `\cref{}`

## Areas for Contribution

### High Priority

- Cross-platform HAL improvements
- Power management for embedded platforms
- Additional exploration algorithms
- Enhanced security features
- Performance optimizations

### Medium Priority

- More visualization modes in dashboard
- Additional hardware platform support
- Network protocol extensions
- Improved logging and debugging

### Documentation

- Tutorial videos
- Architecture deep-dives
- Porting guides for new platforms
- Benchmark results and comparisons

## Questions?

If you have questions or need help:

1. Check existing documentation in `docs/`
2. Open an issue on GitHub
3. Review closed issues and PRs for similar topics

## License

By contributing to NanOS, you agree that your contributions will be licensed under the same license as the project (see LICENSE file).

---

Thank you for contributing to NanOS! Every contribution, no matter how small, helps make the swarm stronger.

*"In the swarm, no cell is special. Every cell is essential."*
