# Installation

ClosedSSPM supports multiple installation methods depending on your environment and operating system.

=== "Homebrew"

    For macOS and Linux users, Homebrew is the recommended way to install and manage ClosedSSPM.

    ```bash
    brew tap PiotrMackowski/closedsspm
    brew install closedsspm
    ```

=== "Binary"

    Pre-compiled binaries are available for major platforms on the GitHub Releases page.

    To download and install the latest Linux amd64 binary:

    ```bash
    curl -Lo closedsspm.tar.gz https://github.com/PiotrMackowski/ClosedSSPM/releases/latest/download/closedsspm_Linux_amd64.tar.gz
    tar xzf closedsspm.tar.gz
    sudo mv closedsspm closedsspm-mcp /usr/local/bin/
    ```

    For other architectures and operating systems, visit the [Releases page](https://github.com/PiotrMackowski/ClosedSSPM/releases).

=== "Debian / Ubuntu"

    Download the `.deb` package for your architecture from the Releases page.

    ```bash
    sudo dpkg -i closedsspm_*.deb
    ```

=== "Red Hat / Fedora"

    Download the `.rpm` package for your architecture from the Releases page.

    ```bash
    sudo rpm -i closedsspm_*.rpm
    ```

=== "Docker"

    Pull the latest image from the GitHub Container Registry.

    ```bash
    docker pull ghcr.io/piotrmackowski/closedsspm:latest
    ```

    Run a quick version check:

    ```bash
    docker run --rm ghcr.io/piotrmackowski/closedsspm:latest --version
    ```

=== "Build from Source"

    If you prefer to build the tool yourself, ensure you have Go 1.21 or later installed.

    ```bash
    git clone https://github.com/PiotrMackowski/ClosedSSPM.git
    cd ClosedSSPM
    make all
    ```

## Verification

After installation, verify that the CLI is correctly installed by checking the version.

```bash
closedsspm --version
```

!!! note
    If you installed via binary and the command is not found, ensure `/usr/local/bin` (or your chosen installation path) is in your system `PATH`.
