#include <iostream>
#include <filesystem>
#include <cstdlib>
#include <fstream>
#include <random>
#include <chrono>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>
#include <cctype>
#include <stdexcept>
#include <memory>
#include <mutex>

#if defined(_WIN32)
#include <windows.h>
#include <process.h>
#define PATH_SEPARATOR "\\"
#define getpid _getpid
#else
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#define PATH_SEPARATOR "/"
#endif

namespace fs = std::filesystem;

// Configuration constants
namespace config {
    constexpr size_t MAX_FILE_SIZE = 50 * 1024 * 1024; // 50MB
    constexpr int COMPILE_TIMEOUT = 60;  // 60 seconds
    constexpr int EXECUTION_TIMEOUT = 30; // 30 seconds
    constexpr size_t MAX_PATH_LENGTH = 4096;
    constexpr size_t MAX_TEMP_DIRS = 100; // Prevent temp dir exhaustion
}

// Custom exception classes
class CodeRunnerException : public std::exception {
public:
    explicit CodeRunnerException(const std::string& message) : msg_(message) {}
    const char* what() const noexcept override { return msg_.c_str(); }
private:
    std::string msg_;
};

class CompilationException : public CodeRunnerException {
public:
    explicit CompilationException(const std::string& message) 
        : CodeRunnerException("Compilation failed: " + message) {}
};

class ExecutionException : public CodeRunnerException {
public:
    explicit ExecutionException(const std::string& message)
        : CodeRunnerException("Execution failed: " + message) {}
};

// Thread-safe temporary directory counter
class TempDirManager {
public:
    static TempDirManager& instance() {
        static TempDirManager instance;
        return instance;
    }

    bool can_create_dir() {
        std::lock_guard<std::mutex> lock(mutex_);
        return active_dirs_ < config::MAX_TEMP_DIRS;
    }

    void increment() {
        std::lock_guard<std::mutex> lock(mutex_);
        ++active_dirs_;
    }

    void decrement() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (active_dirs_ > 0) --active_dirs_;
    }

private:
    std::mutex mutex_;
    size_t active_dirs_ = 0;
};

// RAII class for temporary directory management with improved security
class TempDir {
public:
    TempDir() {
        if (!TempDirManager::instance().can_create_dir()) {
            throw CodeRunnerException("Too many temporary directories in use");
        }
        create_temp_directory();
        TempDirManager::instance().increment();
    }

    ~TempDir() {
        TempDirManager::instance().decrement();
        if (!keep_temp_) {
            try {
                fs::remove_all(path_);
            } catch (const std::exception& e) {
                std::cerr << "Warning: Failed to clean up temporary directory: " 
                         << e.what() << std::endl;
            }
        }
    }

    // Delete copy constructor and assignment operator
    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;

    // Move constructor and assignment
    TempDir(TempDir&& other) noexcept 
        : path_(std::move(other.path_)), keep_temp_(other.keep_temp_) {
        other.path_.clear();
        other.keep_temp_ = false;
    }

    TempDir& operator=(TempDir&& other) noexcept {
        if (this != &other) {
            path_ = std::move(other.path_);
            keep_temp_ = other.keep_temp_;
            other.path_.clear();
            other.keep_temp_ = false;
        }
        return *this;
    }

    const fs::path& get_path() const { return path_; }
    void set_keep(bool keep) { keep_temp_ = keep; }

private:
    void create_temp_directory() {
        auto now = std::chrono::high_resolution_clock::now();
        auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
            now.time_since_epoch()).count();

        std::random_device rd;
        std::mt19937_64 gen(rd());
        std::uniform_int_distribution<uint64_t> dist;

        std::stringstream ss;
        ss << "secure_compile_run_" << getpid() << "_" << ns << "_" << dist(gen);
        
        fs::path temp_base = fs::temp_directory_path();
        path_ = temp_base / ss.str();

        // Validate path length
        if (path_.string().length() > config::MAX_PATH_LENGTH) {
            throw CodeRunnerException("Temporary path too long");
        }

        std::error_code ec;
        if (!fs::create_directory(path_, ec)) {
            throw CodeRunnerException("Failed to create temporary directory: " + ec.message());
        }

        // Set restrictive permissions (owner only)
        #ifndef _WIN32
        fs::permissions(path_, fs::perms::owner_all, ec);
        if (ec) {
            fs::remove_all(path_);
            throw CodeRunnerException("Failed to set directory permissions: " + ec.message());
        }
        #endif
    }

    fs::path path_;
    bool keep_temp_ = false;
};

// Secure command execution with timeout
class CommandExecutor {
public:
    static int execute_with_timeout(const std::string& cmd, int timeout_seconds = 30) {
        if (cmd.empty()) {
            throw ExecutionException("Empty command");
        }

        // Basic command injection prevention
        if (contains_dangerous_chars(cmd)) {
            throw ExecutionException("Command contains potentially dangerous characters");
        }

        #if defined(_WIN32)
        return execute_windows(cmd, timeout_seconds);
        #else
        return execute_unix(cmd, timeout_seconds);
        #endif
    }

private:
    static bool contains_dangerous_chars(const std::string& cmd) {
        // Check for basic command injection patterns
        const std::vector<std::string> dangerous = {
            ";", "&&", "||", "|", "`", "$", "$(", "${", 
            "<", ">", ">>", "&", "\n", "\r"
        };
        
        for (const auto& danger : dangerous) {
            if (cmd.find(danger) != std::string::npos) {
                return true;
            }
        }
        return false;
    }

    #if defined(_WIN32)
    static int execute_windows(const std::string& cmd, int timeout_seconds) {
        STARTUPINFOA si = {sizeof(si)};
        PROCESS_INFORMATION pi = {};
        
        // Create a mutable copy of the command string
        std::string mutable_cmd = cmd;
        
        if (!CreateProcessA(nullptr, &mutable_cmd[0], nullptr, nullptr, 
                           FALSE, 0, nullptr, nullptr, &si, &pi)) {
            throw ExecutionException("Failed to create process");
        }

        DWORD wait_result = WaitForSingleObject(pi.hProcess, timeout_seconds * 1000);
        DWORD exit_code = 0;

        if (wait_result == WAIT_TIMEOUT) {
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            throw ExecutionException("Process timeout");
        } else if (wait_result == WAIT_OBJECT_0) {
            GetExitCodeProcess(pi.hProcess, &exit_code);
        }

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return static_cast<int>(exit_code);
    }
    #else
    static int execute_unix(const std::string& cmd, int timeout_seconds) {
        pid_t pid = fork();
        if (pid == -1) {
            throw ExecutionException("Failed to fork process");
        }

        if (pid == 0) {
            // Child process
            execl("/bin/sh", "sh", "-c", cmd.c_str(), nullptr);
            exit(127); // execl failed
        }

        // Parent process - wait with timeout
        int status;
        pid_t result;
        
        // Set up alarm for timeout
        alarm(timeout_seconds);
        result = waitpid(pid, &status, 0);
        alarm(0); // Cancel alarm

        if (result == -1) {
            kill(pid, SIGKILL);
            waitpid(pid, nullptr, 0);
            throw ExecutionException("Process timeout or wait failed");
        }

        if (WIFEXITED(status)) {
            return WEXITSTATUS(status);
        } else if (WIFSIGNALED(status)) {
            throw ExecutionException("Process terminated by signal");
        }

        return -1;
    }
    #endif
};

// Utility functions
class Utils {
public:
    static std::string get_compiler_path(const std::string& compiler) {
        if (compiler.empty()) {
            throw CodeRunnerException("Empty compiler name");
        }

        const char* env_path = std::getenv("PATH");
        if (!env_path) {
            return compiler;
        }

        std::istringstream iss(env_path);
        std::string path_token;
        
        #if defined(_WIN32)
        const char path_delim = ';';
        const std::string exe_suffix = ".exe";
        #else
        const char path_delim = ':';
        const std::string exe_suffix = "";
        #endif

        while (std::getline(iss, path_token, path_delim)) {
            if (path_token.empty()) continue;
            
            try {
                fs::path candidate = fs::path(path_token) / (compiler + exe_suffix);
                if (fs::exists(candidate) && fs::is_regular_file(candidate)) {
                    return candidate.string();
                }
            } catch (const std::exception&) {
                // Skip invalid paths
                continue;
            }
        }
        return compiler;
    }

    static void validate_source_file(const fs::path& file_path) {
        std::error_code ec;
        
        if (!fs::exists(file_path, ec)) {
            throw CodeRunnerException("Source file does not exist");
        }

        if (!fs::is_regular_file(file_path, ec)) {
            throw CodeRunnerException("Path is not a regular file");
        }

        auto file_size = fs::file_size(file_path, ec);
        if (ec) {
            throw CodeRunnerException("Cannot determine file size: " + ec.message());
        }

        if (file_size > config::MAX_FILE_SIZE) {
            throw CodeRunnerException("File too large (max " + 
                std::to_string(config::MAX_FILE_SIZE) + " bytes)");
        }

        // Check if file is readable
        std::ifstream test_stream(file_path);
        if (!test_stream.is_open()) {
            throw CodeRunnerException("Cannot read source file");
        }
    }

    static std::string quote_path(const std::string& path) {
        return "\"" + path + "\"";
    }

    static std::string to_lower(const std::string& str) {
        std::string result = str;
        std::transform(result.begin(), result.end(), result.begin(),
            [](unsigned char c) { return std::tolower(c); });
        return result;
    }
};

// Language-specific runners
class LanguageRunner {
public:
    virtual ~LanguageRunner() = default;
    virtual int run(const fs::path& file) = 0;
    virtual std::string get_language_name() const = 0;

protected:
    void log_temp_dir_if_requested(const TempDir& temp_dir) {
        if (std::getenv("KEEP_TEMP")) {
            std::cerr << "Temporary directory for " << get_language_name() 
                     << ": " << temp_dir.get_path() << std::endl;
        }
    }
};

class CRunner : public LanguageRunner {
public:
    int run(const fs::path& file) override {
        TempDir temp_dir;
        if (std::getenv("KEEP_TEMP")) {
            temp_dir.set_keep(true);
            log_temp_dir_if_requested(temp_dir);
        }

        fs::path output = temp_dir.get_path() / "program";
        #if defined(_WIN32)
        output += ".exe";
        #endif

        std::string gcc_path = Utils::get_compiler_path("gcc");
        std::string cmd = Utils::quote_path(gcc_path) + " " + 
                         Utils::quote_path(file.string()) + " -o " + 
                         Utils::quote_path(output.string()) + 
                         " -std=c11 -Wall -Wextra -O2";

        try {
            int compile_status = CommandExecutor::execute_with_timeout(cmd, config::COMPILE_TIMEOUT);
            if (compile_status != 0) {
                throw CompilationException("gcc returned exit code " + std::to_string(compile_status));
            }

            return CommandExecutor::execute_with_timeout(
                Utils::quote_path(output.string()), config::EXECUTION_TIMEOUT);
        } catch (const ExecutionException& e) {
            throw CompilationException(e.what());
        }
    }

    std::string get_language_name() const override { return "C"; }
};

class CppRunner : public LanguageRunner {
public:
    int run(const fs::path& file) override {
        TempDir temp_dir;
        if (std::getenv("KEEP_TEMP")) {
            temp_dir.set_keep(true);
            log_temp_dir_if_requested(temp_dir);
        }

        fs::path output = temp_dir.get_path() / "program";
        #if defined(_WIN32)
        output += ".exe";
        #endif

        std::string gpp_path = Utils::get_compiler_path("g++");
        std::string cmd = Utils::quote_path(gpp_path) + " " + 
                         Utils::quote_path(file.string()) + " -o " + 
                         Utils::quote_path(output.string()) + 
                         " -std=c++17 -Wall -Wextra -O2";

        try {
            int compile_status = CommandExecutor::execute_with_timeout(cmd, config::COMPILE_TIMEOUT);
            if (compile_status != 0) {
                throw CompilationException("g++ returned exit code " + std::to_string(compile_status));
            }

            return CommandExecutor::execute_with_timeout(
                Utils::quote_path(output.string()), config::EXECUTION_TIMEOUT);
        } catch (const ExecutionException& e) {
            throw CompilationException(e.what());
        }
    }

    std::string get_language_name() const override { return "C++"; }
};

class RustRunner : public LanguageRunner {
public:
    int run(const fs::path& file) override {
        TempDir temp_dir;
        if (std::getenv("KEEP_TEMP")) {
            temp_dir.set_keep(true);
            log_temp_dir_if_requested(temp_dir);
        }

        fs::path temp_path = temp_dir.get_path();
        fs::path src_dir = temp_path / "src";
        
        std::error_code ec;
        fs::create_directories(src_dir, ec);
        if (ec) {
            throw CodeRunnerException("Failed to create src directory: " + ec.message());
        }

        // Create Cargo.toml with security considerations
        std::ofstream cargo_toml(temp_path / "Cargo.toml");
        if (!cargo_toml.is_open()) {
            throw CodeRunnerException("Failed to create Cargo.toml");
        }

        cargo_toml << "[package]\n"
                   << "name = \"temp_rust_bin\"\n"
                   << "version = \"0.1.0\"\n"
                   << "edition = \"2021\"\n\n"
                   << "[dependencies]\n"
                   << "\n[profile.dev]\n"
                   << "opt-level = 1\n"
                   << "\n[profile.release]\n"
                   << "opt-level = 2\n";
        cargo_toml.close();

        // Copy source file
        fs::path main_rs = src_dir / "main.rs";
        fs::copy_file(file, main_rs, fs::copy_options::overwrite_existing, ec);
        if (ec) {
            throw CodeRunnerException("Failed to copy source file: " + ec.message());
        }

        // Build and run with timeout
        std::string cargo_cmd = "cargo run --quiet --manifest-path " + 
                               Utils::quote_path((temp_path / "Cargo.toml").string()) +
                               " --release";

        return CommandExecutor::execute_with_timeout(cargo_cmd, config::COMPILE_TIMEOUT + config::EXECUTION_TIMEOUT);
    }

    std::string get_language_name() const override { return "Rust"; }
};

class PythonRunner : public LanguageRunner {
public:
    int run(const fs::path& file) override {
        log_temp_dir_if_requested(TempDir()); // For consistency, though Python doesn't need temp compilation
        
        std::string python_path = Utils::get_compiler_path("python3");
        if (python_path == "python3") {
            // Fallback to python if python3 not found
            python_path = Utils::get_compiler_path("python");
        }

        std::string cmd = Utils::quote_path(python_path) + " " + Utils::quote_path(file.string());
        return CommandExecutor::execute_with_timeout(cmd, config::EXECUTION_TIMEOUT);
    }

    std::string get_language_name() const override { return "Python"; }
};

class JavaRunner : public LanguageRunner {
public:
    int run(const fs::path& file) override {
        TempDir temp_dir;
        if (std::getenv("KEEP_TEMP")) {
            temp_dir.set_keep(true);
            log_temp_dir_if_requested(temp_dir);
        }

        std::string javac_path = Utils::get_compiler_path("javac");
        std::string java_path = Utils::get_compiler_path("java");

        // Extract class name from file
        std::string class_name = file.stem().string();
        
        // Compile
        std::string compile_cmd = Utils::quote_path(javac_path) + " -d " + 
                                 Utils::quote_path(temp_dir.get_path().string()) + " " +
                                 Utils::quote_path(file.string());

        try {
            int compile_status = CommandExecutor::execute_with_timeout(compile_cmd, config::COMPILE_TIMEOUT);
            if (compile_status != 0) {
                throw CompilationException("javac returned exit code " + std::to_string(compile_status));
            }

            // Run
            std::string run_cmd = Utils::quote_path(java_path) + " -cp " + 
                                 Utils::quote_path(temp_dir.get_path().string()) + " " + class_name;
            
            return CommandExecutor::execute_with_timeout(run_cmd, config::EXECUTION_TIMEOUT);
        } catch (const ExecutionException& e) {
            throw CompilationException(e.what());
        }
    }

    std::string get_language_name() const override { return "Java"; }
};

class GoRunner : public LanguageRunner {
public:
    int run(const fs::path& file) override {
        log_temp_dir_if_requested(TempDir()); // For consistency
        
        std::string go_path = Utils::get_compiler_path("go");
        std::string cmd = Utils::quote_path(go_path) + " run " + Utils::quote_path(file.string());
        
        return CommandExecutor::execute_with_timeout(cmd, config::COMPILE_TIMEOUT + config::EXECUTION_TIMEOUT);
    }

    std::string get_language_name() const override { return "Go"; }
};

class JavaScriptRunner : public LanguageRunner {
public:
    int run(const fs::path& file) override {
        log_temp_dir_if_requested(TempDir()); // For consistency
        
        std::string node_path = Utils::get_compiler_path("node");
        std::string cmd = Utils::quote_path(node_path) + " " + Utils::quote_path(file.string());
        
        return CommandExecutor::execute_with_timeout(cmd, config::EXECUTION_TIMEOUT);
    }

    std::string get_language_name() const override { return "JavaScript (Node.js)"; }
};

class TypeScriptRunner : public LanguageRunner {
public:
    int run(const fs::path& file) override {
        TempDir temp_dir;
        if (std::getenv("KEEP_TEMP")) {
            temp_dir.set_keep(true);
            log_temp_dir_if_requested(temp_dir);
        }

        std::string tsc_path = Utils::get_compiler_path("tsc");
        std::string node_path = Utils::get_compiler_path("node");

        // Compile TypeScript to JavaScript
        fs::path js_output = temp_dir.get_path() / (file.stem().string() + ".js");
        std::string compile_cmd = Utils::quote_path(tsc_path) + " " + 
                                 Utils::quote_path(file.string()) + " --outDir " +
                                 Utils::quote_path(temp_dir.get_path().string()) +
                                 " --target ES2020 --module commonjs";

        try {
            int compile_status = CommandExecutor::execute_with_timeout(compile_cmd, config::COMPILE_TIMEOUT);
            if (compile_status != 0) {
                throw CompilationException("tsc returned exit code " + std::to_string(compile_status));
            }

            // Run the compiled JavaScript
            std::string run_cmd = Utils::quote_path(node_path) + " " + Utils::quote_path(js_output.string());
            return CommandExecutor::execute_with_timeout(run_cmd, config::EXECUTION_TIMEOUT);
        } catch (const ExecutionException& e) {
            throw CompilationException(e.what());
        }
    }

    std::string get_language_name() const override { return "TypeScript"; }
};

class CSharpRunner : public LanguageRunner {
public:
    int run(const fs::path& file) override {
        TempDir temp_dir;
        if (std::getenv("KEEP_TEMP")) {
            temp_dir.set_keep(true);
            log_temp_dir_if_requested(temp_dir);
        }

        std::string csc_path = get_csharp_compiler();
        if (csc_path.empty()) {
            throw CodeRunnerException("C# compiler not found. Install .NET SDK or Mono");
        }

        fs::path exe_output = temp_dir.get_path() / (file.stem().string() + ".exe");
        
        std::string compile_cmd;
        if (csc_path.find("dotnet") != std::string::npos) {
            // Using .NET Core/5+
            compile_cmd = csc_path + " build " + Utils::quote_path(file.string()) + 
                         " -o " + Utils::quote_path(temp_dir.get_path().string());
        } else {
            // Using traditional csc or mcs
            compile_cmd = Utils::quote_path(csc_path) + " " + Utils::quote_path(file.string()) + 
                         " -out:" + Utils::quote_path(exe_output.string());
        }

        try {
            int compile_status = CommandExecutor::execute_with_timeout(compile_cmd, config::COMPILE_TIMEOUT);
            if (compile_status != 0) {
                throw CompilationException("C# compiler returned exit code " + std::to_string(compile_status));
            }

            // Run the executable
            std::string run_cmd;
            if (csc_path.find("dotnet") != std::string::npos) {
                run_cmd = "dotnet " + Utils::quote_path(exe_output.string());
            } else {
                #ifdef _WIN32
                run_cmd = Utils::quote_path(exe_output.string());
                #else
                run_cmd = "mono " + Utils::quote_path(exe_output.string());
                #endif
            }

            return CommandExecutor::execute_with_timeout(run_cmd, config::EXECUTION_TIMEOUT);
        } catch (const ExecutionException& e) {
            throw CompilationException(e.what());
        }
    }

    std::string get_language_name() const override { return "C#"; }

private:
    std::string get_csharp_compiler() {
        // Try .NET first
        std::string dotnet_path = Utils::get_compiler_path("dotnet");
        if (dotnet_path != "dotnet") {
            return dotnet_path;
        }

        // Try traditional compilers
        std::string csc_path = Utils::get_compiler_path("csc");
        if (csc_path != "csc") {
            return csc_path;
        }

        // Try Mono compiler
        std::string mcs_path = Utils::get_compiler_path("mcs");
        if (mcs_path != "mcs") {
            return mcs_path;
        }

        return "";
    }
};

class RubyRunner : public LanguageRunner {
public:
    int run(const fs::path& file) override {
        log_temp_dir_if_requested(TempDir()); // For consistency
        
        std::string ruby_path = Utils::get_compiler_path("ruby");
        std::string cmd = Utils::quote_path(ruby_path) + " " + Utils::quote_path(file.string());
        
        return CommandExecutor::execute_with_timeout(cmd, config::EXECUTION_TIMEOUT);
    }

    std::string get_language_name() const override { return "Ruby"; }
};

class PHPRunner : public LanguageRunner {
public:
    int run(const fs::path& file) override {
        log_temp_dir_if_requested(TempDir()); // For consistency
        
        std::string php_path = Utils::get_compiler_path("php");
        std::string cmd = Utils::quote_path(php_path) + " " + Utils::quote_path(file.string());
        
        return CommandExecutor::execute_with_timeout(cmd, config::EXECUTION_TIMEOUT);
    }

    std::string get_language_name() const override { return "PHP"; }
};

class SwiftRunner : public LanguageRunner {
public:
    int run(const fs::path& file) override {
        log_temp_dir_if_requested(TempDir()); // For consistency
        
        std::string swift_path = Utils::get_compiler_path("swift");
        std::string cmd = Utils::quote_path(swift_path) + " " + Utils::quote_path(file.string());
        
        return CommandExecutor::execute_with_timeout(cmd, config::COMPILE_TIMEOUT + config::EXECUTION_TIMEOUT);
    }

    std::string get_language_name() const override { return "Swift"; }
};

class KotlinRunner : public LanguageRunner {
public:
    int run(const fs::path& file) override {
        TempDir temp_dir;
        if (std::getenv("KEEP_TEMP")) {
            temp_dir.set_keep(true);
            log_temp_dir_if_requested(temp_dir);
        }

        std::string kotlinc_path = Utils::get_compiler_path("kotlinc");
        std::string kotlin_path = Utils::get_compiler_path("kotlin");

        // Compile Kotlin to JAR
        fs::path jar_output = temp_dir.get_path() / "program.jar";
        std::string compile_cmd = Utils::quote_path(kotlinc_path) + " " + 
                                 Utils::quote_path(file.string()) + " -include-runtime -d " +
                                 Utils::quote_path(jar_output.string());

        try {
            int compile_status = CommandExecutor::execute_with_timeout(compile_cmd, config::COMPILE_TIMEOUT);
            if (compile_status != 0) {
                throw CompilationException("kotlinc returned exit code " + std::to_string(compile_status));
            }

            // Run the JAR
            std::string run_cmd = Utils::quote_path(kotlin_path) + " " + Utils::quote_path(jar_output.string());
            return CommandExecutor::execute_with_timeout(run_cmd, config::EXECUTION_TIMEOUT);
        } catch (const ExecutionException& e) {
            throw CompilationException(e.what());
        }
    }

    std::string get_language_name() const override { return "Kotlin"; }
};

class ScalaRunner : public LanguageRunner {
public:
    int run(const fs::path& file) override {
        TempDir temp_dir;
        if (std::getenv("KEEP_TEMP")) {
            temp_dir.set_keep(true);
            log_temp_dir_if_requested(temp_dir);
        }

        std::string scalac_path = Utils::get_compiler_path("scalac");
        std::string scala_path = Utils::get_compiler_path("scala");

        // Extract class name (assuming it matches filename)
        std::string class_name = file.stem().string();

        // Compile Scala
        std::string compile_cmd = Utils::quote_path(scalac_path) + " -d " + 
                                 Utils::quote_path(temp_dir.get_path().string()) + " " +
                                 Utils::quote_path(file.string());

        try {
            int compile_status = CommandExecutor::execute_with_timeout(compile_cmd, config::COMPILE_TIMEOUT);
            if (compile_status != 0) {
                throw CompilationException("scalac returned exit code " + std::to_string(compile_status));
            }

            // Run
            std::string run_cmd = Utils::quote_path(scala_path) + " -cp " + 
                                 Utils::quote_path(temp_dir.get_path().string()) + " " + class_name;
            
            return CommandExecutor::execute_with_timeout(run_cmd, config::EXECUTION_TIMEOUT);
        } catch (const ExecutionException& e) {
            throw CompilationException(e.what());
        }
    }

    std::string get_language_name() const override { return "Scala"; }
};

class LuaRunner : public LanguageRunner {
public:
    int run(const fs::path& file) override {
        log_temp_dir_if_requested(TempDir()); // For consistency
        
        std::string lua_path = Utils::get_compiler_path("lua");
        if (lua_path == "lua") {
            // Try lua5.3, lua5.4, etc.
            std::vector<std::string> versions = {"lua5.4", "lua5.3", "lua5.2", "lua5.1"};
            for (const auto& version : versions) {
                std::string versioned_path = Utils::get_compiler_path(version);
                if (versioned_path != version) {
                    lua_path = versioned_path;
                    break;
                }
            }
        }

        std::string cmd = Utils::quote_path(lua_path) + " " + Utils::quote_path(file.string());
        return CommandExecutor::execute_with_timeout(cmd, config::EXECUTION_TIMEOUT);
    }

    std::string get_language_name() const override { return "Lua"; }
};

class PerlRunner : public LanguageRunner {
public:
    int run(const fs::path& file) override {
        log_temp_dir_if_requested(TempDir()); // For consistency
        
        std::string perl_path = Utils::get_compiler_path("perl");
        std::string cmd = Utils::quote_path(perl_path) + " " + Utils::quote_path(file.string());
        
        return CommandExecutor::execute_with_timeout(cmd, config::EXECUTION_TIMEOUT);
    }

    std::string get_language_name() const override { return "Perl"; }
};

class BashRunner : public LanguageRunner {
public:
    int run(const fs::path& file) override {
        log_temp_dir_if_requested(TempDir()); // For consistency
        
        std::string bash_path = Utils::get_compiler_path("bash");
        if (bash_path == "bash") {
            // Fallback to sh if bash not found
            bash_path = Utils::get_compiler_path("sh");
        }

        std::string cmd = Utils::quote_path(bash_path) + " " + Utils::quote_path(file.string());
        return CommandExecutor::execute_with_timeout(cmd, config::EXECUTION_TIMEOUT);
    }

    std::string get_language_name() const override { return "Bash/Shell"; }
};

// Factory for creating language runners
class RunnerFactory {
public:
    static std::unique_ptr<LanguageRunner> create_runner(const std::string& extension) {
        std::string ext = Utils::to_lower(extension);
        
        // C/C++ languages
        if (ext == ".c") {
            return std::make_unique<CRunner>();
        } else if (ext == ".cpp" || ext == ".cc" || ext == ".cxx" || ext == ".c++") {
            return std::make_unique<CppRunner>();
        }
        
        // Systems programming
        else if (ext == ".rs") {
            return std::make_unique<RustRunner>();
        } else if (ext == ".go") {
            return std::make_unique<GoRunner>();
        } else if (ext == ".swift") {
            return std::make_unique<SwiftRunner>();
        }
        
        // JVM languages
        else if (ext == ".java") {
            return std::make_unique<JavaRunner>();
        } else if (ext == ".kt" || ext == ".kts") {
            return std::make_unique<KotlinRunner>();
        } else if (ext == ".scala") {
            return std::make_unique<ScalaRunner>();
        }
        
        // .NET languages
        else if (ext == ".cs") {
            return std::make_unique<CSharpRunner>();
        }
        
        // Web/Scripting languages
        else if (ext == ".js" || ext == ".mjs") {
            return std::make_unique<JavaScriptRunner>();
        } else if (ext == ".ts") {
            return std::make_unique<TypeScriptRunner>();
        } else if (ext == ".py" || ext == ".py3") {
            return std::make_unique<PythonRunner>();
        } else if (ext == ".rb") {
            return std::make_unique<RubyRunner>();
        } else if (ext == ".php") {
            return std::make_unique<PHPRunner>();
        } else if (ext == ".lua") {
            return std::make_unique<LuaRunner>();
        } else if (ext == ".pl" || ext == ".pm") {
            return std::make_unique<PerlRunner>();
        }
        
        // Shell scripting
        else if (ext == ".sh" || ext == ".bash") {
            return std::make_unique<BashRunner>();
        }
        
        else {
            throw CodeRunnerException("Unsupported file extension: " + extension);
        }
    }

    static std::vector<std::string> get_supported_extensions() {
        return {
            // C/C++
            ".c", ".cpp", ".cc", ".cxx", ".c++",
            // Systems programming
            ".rs", ".go", ".swift",
            // JVM languages
            ".java", ".kt", ".kts", ".scala",
            // .NET
            ".cs",
            // Web/Scripting
            ".js", ".mjs", ".ts", ".py", ".py3", ".rb", ".php", ".lua", ".pl", ".pm",
            // Shell
            ".sh", ".bash"
        };
    }

    static void print_supported_languages() {
        std::cerr << "Supported languages and extensions:\n\n";
        
        std::cerr << "Compiled languages:\n";
        std::cerr << "  C:           .c\n";
        std::cerr << "  C++:         .cpp, .cc, .cxx, .c++\n";
        std::cerr << "  Rust:        .rs\n";
        std::cerr << "  Go:          .go\n";
        std::cerr << "  Swift:       .swift\n";
        std::cerr << "  Java:        .java\n";
        std::cerr << "  Kotlin:      .kt, .kts\n";
        std::cerr << "  Scala:       .scala\n";
        std::cerr << "  C#:          .cs\n";
        std::cerr << "  TypeScript:  .ts\n\n";
        
        std::cerr << "Interpreted languages:\n";
        std::cerr << "  Python:      .py, .py3\n";
        std::cerr << "  JavaScript:  .js, .mjs\n";
        std::cerr << "  Ruby:        .rb\n";
        std::cerr << "  PHP:         .php\n";
        std::cerr << "  Lua:         .lua\n";
        std::cerr << "  Perl:        .pl, .pm\n";
        std::cerr << "  Bash/Shell:  .sh, .bash\n";
    }
};

// Main application class
class CodeRunner {
public:
    int run(const std::string& file_path_str) {
        try {
            fs::path file_path(file_path_str);
            
            // Validate input file
            Utils::validate_source_file(file_path);
            
            // Get file extension
            std::string extension = file_path.extension().string();
            if (extension.empty()) {
                throw CodeRunnerException("File has no extension");
            }

            // Create appropriate runner
            auto runner = RunnerFactory::create_runner(extension);
            
            // Execute
            std::cerr << "Running " << runner->get_language_name() 
                     << " code from: " << file_path << std::endl;
            
            return runner->run(file_path);

        } catch (const CodeRunnerException& e) {
            std::cerr << "Error: " << e.what() << std::endl;
            return 1;
        } catch (const std::exception& e) {
            std::cerr << "Unexpected error: " << e.what() << std::endl;
            return 1;
        }
    }

    static void print_usage(const char* program_name) {
        std::cerr << "Usage: " << program_name << " <source_file>\n\n";
        RunnerFactory::print_supported_languages();
        std::cerr << "\nEnvironment variables:\n";
        std::cerr << "  KEEP_TEMP=1    Keep temporary directories for debugging\n\n";
        std::cerr << "Examples:\n";
        std::cerr << "  " << program_name << " hello.c\n";
        std::cerr << "  " << program_name << " main.py\n";
        std::cerr << "  " << program_name << " app.js\n";
        std::cerr << "  " << program_name << " HelloWorld.java\n";
    }
};

int main(int argc, char* argv[]) {
    if (argc != 2) {
        CodeRunner::print_usage(argv[0]);
        return 1;
    }

    CodeRunner runner;
    return runner.run(argv[1]);
}
