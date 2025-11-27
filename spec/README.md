# DynaFed Specification

This directory contains the LaTeX source for the DynaFed specification document, which describes the dynamic federation management protocol for Botanix's Bitcoin custody system. It remains largely work-in-progress under its current form.

## Prerequisites

### Option 1: Using LaTeX Workshop (Recommended)

If you're using the [LaTeX Workshop](https://marketplace.visualstudio.com/items?itemName=James-Yu.latex-workshop) extension for VS Code, you only need to install the additional LaTeX packages:

```bash
sudo tlmgr install pgfplots sectsty quiver spath3 mathtools
```

### Option 2: Full TeXLive Installation

Alternatively, you can install the complete TeXLive distribution (warning: this is a large download):

```bash
sudo apt-get install -y texlive-full
```

## Building the Document

### Using LaTeX Workshop (VS Code)

1. Open `main.tex` in VS Code
2. The document will automatically build on save (if auto-build is enabled)
3. Or use the command palette: `Ctrl+Shift+P` -> "LaTeX Workshop: Build LaTeX project"

### Using Command Line

```bash
pdflatex main.tex
```

## License

Copyright © 2025 BotanixLabs
CC BY 4.0 (Creative Commons Attribution 4.0 International)
