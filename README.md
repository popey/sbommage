# Sbommage

SBOM + Rummage = Sbommage.

*Pronounced (in my British English) as "ess-bomb-idge", or "SBOM Mage 🧙" if you prefer.*

Sbommage is an interactive terminal frontend for viewing Software Bill of Materials ([SBOM](https://anchore.com/sbom/)) files in various formats.

![A short video showing Sbommage](./sbommage.gif)

## Introduction

Software Bill of Materials ([SBOM](https://anchore.com/sbom/)) files are increasingly important in software supply chain security. However, they come in multiple formats (SPDX, CycloneDX, Syft's native format), each with their own structure and complexity. Sbommage aims to provide a consistent, user-friendly way to view and explore SBOM data, regardless of the underlying format.

## Installation

Sbommage is written in Python and requires Python 3.8 or later.

### From PyPI (Recommended)

The easiest way to install sbommage is from PyPI:

```shell
pip install sbommage
```

Or use the install script:

```shell
curl -sSL https://raw.githubusercontent.com/popey/sbommage/main/install.sh | bash
```

### From GitHub Releases

Download the latest release from the [GitHub releases page](https://github.com/popey/sbommage/releases).

### Using Homebrew (macOS/Linux)

```shell
brew tap popey/sbommage
brew install sbommage
```

### Using Docker

Note: `-it` is required for interaction with the application. Setting the `TERM` variable allows for better colour support.

```shell
docker run --rm -it -e TERM=xterm-256color -v $(pwd):/data ghcr.io/popey/sbommage:latest /data/your-sbom.json
```

### From Source

For development or if you prefer to install from source:

```shell
git clone https://github.com/popey/sbommage
cd sbommage
pip install -e .
```

### Using uv (Alternative)

If you use [uv](https://github.com/astral-sh/uv) for Python environment management:

```shell
git clone https://github.com/popey/sbommage
cd sbommage
uv venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
uv pip install -e .
```

## Usage

Point sbommage at an SBOM file:

```shell
./sbommage example_sboms/nextcloud-latest-syft-sbom.json
```

Sbommage will detect the SBOM format (SPDX, CycloneDX, GitHub, or Syft), and present the data in an interactive interface.
Use the cursor keys or mouse to navigate the tree on the left pane.
Click or press Enter on an item to see detailed information in the right pane.

### Keys:

Change view:

* `n` - View by package Name
* `t` - View by package Type
* `c` - View by License (Copyright/Code)
* `s` - View by Supplier

Navigation:

* `h` - Move left
* `j` - Move down
* `k` - Move up
* `l` - Move right

Misc:

* `/` - Search
* `q` - Quit

## Supported SBOM Formats

The goal is to support as many SBOM formats as possible. Patches welcome!

* SPDX
* CycloneDX (JSON)
* GitHub
* Syft

## Generating SBOMs

There are various tools available to generate SBOMs:

* [Syft](https://github.com/anchore/syft) - Generates comprehensive SBOMs in multiple formats
* [SPDX Tools](https://github.com/spdx/tools) - Official SPDX tools
* [CycloneDX Tools](https://github.com/CycloneDX) - Various tools for CycloneDX format

For example, to generate an SBOM with Syft:

```shell
syft alpine:latest -o json > alpine-syft.json
```

## Caveats

I am an open-source enthusiast and self-taught coder creating projects driven by curiosity and a love for problem-solving. The code may have bugs or sharp edges. Kindly let me know if you find one, via an [issue](https://github.com/popey/sbommage/issues). Thanks.
