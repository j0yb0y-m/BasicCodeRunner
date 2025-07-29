# BasicCodeRunner
A secure, multi-language code execution tool that compiles and runs source files in 16+ programming languages with resource constraints and safety features.

## Features

- **Multi-language Support**: Execute code in C, C++, Rust, Python, Java, Go, JavaScript, TypeScript, C#, Ruby, PHP, Swift, Kotlin, Scala, Lua, Perl, and Bash
- **Resource Management**:
  - 50MB maximum file size
  - 60-second compilation timeout
  - 30-second execution timeout
- **Security Measures**:
  - Temporary directory isolation
  - Command injection prevention
  - File permission restrictions (non-Windows)
  - Secure temporary directory naming
- **Automatic Cleanup**: Temporary directory removal after execution (configurable)
- **Concurrency Safe**: Limits maximum concurrent temporary directories (100 max)

## Supported Languages

| Language        | File Extensions                |
|-----------------|--------------------------------|
| C              | `.c`                           |
| C++            | `.cpp`, `.cc`, `.cxx`, `.c++`  |
| Rust           | `.rs`                          |
| Python         | `.py`, `.py3`                  |
| Java           | `.java`                        |
| Go             | `.go`                          |
| JavaScript     | `.js`, `.mjs`                  |
| TypeScript     | `.ts`                          |
| C#             | `.cs`                          |
| Ruby           | `.rb`                          |
| PHP            | `.php`                         |
| Swift          | `.swift`                       |
| Kotlin         | `.kt`, `.kts`                  |
| Scala          | `.scala`                       |
| Lua            | `.lua`                         |
| Perl           | `.pl`, `.pm`                   |
| Bash/Shell     | `.sh`, `.bash`                 |

## Requirements

- C++17 compatible compiler
- CMake (build system)
- Target language runtimes/compilers (e.g., GCC for C/C++, JDK for Java, etc.)

## Building

```bash
# Clone repository
git clone https://github.com/yourusername/code-runner.git
cd code-runner

# Create build directory
mkdir build && cd build

# Configure and build
cmake ..
cmake --build .
```

## Usage

```bash
./code_runner <source_file>
```

### Examples
```bash
./code_runner hello.c
./code_runner app.py
./code_runner Main.java
```

### Environment Variables
- `KEEP_TEMP=1`: Preserve temporary directories after execution (useful for debugging)
  ```bash
  KEEP_TEMP=1 ./code_runner myapp.rs
  ```

## Configuration

Constants can be modified in the source code (`config` namespace):
```cpp
namespace config {
    constexpr size_t MAX_FILE_SIZE = 50 * 1024 * 1024; // 50MB
    constexpr int COMPILE_TIMEOUT = 60;  // 60 seconds
    constexpr int EXECUTION_TIMEOUT = 30; // 30 seconds
    constexpr size_t MAX_PATH_LENGTH = 4096;
    constexpr size_t MAX_TEMP_DIRS = 100;
}
```

## Security Features

1. **Input Validation**:
   - Checks for dangerous command characters (`;`, `&&`, `|`, etc.)
   - Validates file paths and extensions
2. **Resource Limiting**:
   - File size restrictions
   - Timeouts for compilation and execution
3. **Isolation**:
   - Process-level isolation for executions
   - Unique temporary directories per execution
4. **File System Security**:
   - Restrictive permissions on temporary directories (700 on Unix)
   - Secure random directory names
5. **Concurrency Controls**:
   - Thread-safe temporary directory counter
   - Maximum concurrent executions limit

## Limitations

- Windows support has limited permission controls
- No network access restrictions
- Limited sandboxing capabilities
- Resource limits are process-wide (not per-language)
- Some languages require specific compiler versions (e.g., C++17)

## Error Handling

The program provides detailed error messages for:
- Compilation failures
- Execution timeouts
- Missing dependencies
- File system errors
- Security violations

## Contributing

Contributions are welcome! Please follow these guidelines:
1. Add tests for new language support
2. Maintain consistent security practices
3. Document new features in README
4. Ensure cross-platform compatibility

## License

[MIT License](LICENSE)
