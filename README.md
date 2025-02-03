# Sbommage

SBOM + Rummage = Sbommage.

*Pronounced (in my British English) as "ess-boomb-idge", or "SBOM Mage 🧙" if you prefer.*

Sbommage is an interactive terminal frontend for viewing Software Bill of Materials ([SBOM](https://anchore.com/sbom/)) files in various formats.

![A short video showing Sbommage](./sbommage.gif)

## Introduction

Software Bill of Materials ([SBOM](https://anchore.com/sbom/)) files are increasingly important in software supply chain security. However, they come in multiple formats (SPDX, CycloneDX, Syft's native format), each with their own structure and complexity. Sbommage aims to provide a consistent, user-friendly way to view and explore SBOM data, regardless of the underlying format.

## Installation

Sbommage is written in Python, and uses the [Textual](https://textual.textualize.io/) library for the UI.

### Pre-requisites

You just need Python and the Textual library installed.

I use [uv](https://github.com/astral-sh/uv) to manage Python virtual environments. It's good. You might like it too.

```shell
git clone https://github.com/popey/sbommage
cd sbommage
uv venv
source ./venv/bin/activate
uv pip install textual
```

## Usage

Point sbommage at an SBOM file:

```shell
./sbommage example_sboms/nextcloud-latest-syft-sbom.json
```

Sbommage will detect the SBOM format (SPDX, CycloneDX, or Syft), and present the data in an interactive interface.
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
* CycloneDX
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