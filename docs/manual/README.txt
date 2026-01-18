================================================================================
                    NanOS Technical Manual - LaTeX Source
================================================================================

CONTENTS
--------
  NanOS_Technical_Manual.tex   Main LaTeX source file
  Makefile                     Build automation

REQUIREMENTS
------------
To compile this manual, you need:

  1. TeX Distribution:
     - TeX Live (Linux/macOS): https://www.tug.org/texlive/
     - MiKTeX (Windows): https://miktex.org/

  2. Required LaTeX Packages:
     - tikz, pgfplots (diagrams and graphs)
     - booktabs, longtable (tables)
     - listings (code listings)
     - hyperref (links)
     - tcolorbox (boxes)
     - fancyhdr (headers)

     Most distributions include these by default.

COMPILATION
-----------

Using Make (Linux/macOS):

    make              # Full build (3 passes for TOC)
    make once         # Quick single pass
    make view         # Open resulting PDF
    make clean        # Remove build files

Using pdflatex directly:

    pdflatex NanOS_Technical_Manual.tex
    pdflatex NanOS_Technical_Manual.tex
    pdflatex NanOS_Technical_Manual.tex

    (Three passes needed for table of contents and references)

Using latexmk (auto-rebuild on changes):

    latexmk -pdf -pvc NanOS_Technical_Manual.tex

OUTPUT
------
The compiled PDF will be in:

    build/NanOS_Technical_Manual.pdf

MANUAL STRUCTURE
----------------

Part I: NanOS Core
  - Introduction and philosophy
  - System architecture
  - Role system (Queen, Worker, Explorer, Sentinel)
  - Pheromone protocol
  - Network mechanisms (Bloom filter, Gossip, Gradient routing)

Part II: NERT Protocol
  - Overview and motivation
  - Packet format
  - Cryptography (ChaCha8, Poly1305, Key rotation)
  - Reliability mechanisms (SACK, Retransmission)
  - Forward Error Correction
  - Multi-path transmission

Part III: Implementation Guide
  - Compilation for different platforms
  - Programming API
  - Debugging and monitoring

Appendices
  - Configuration constants
  - Glossary

DIAGRAMS INCLUDED
-----------------
The manual includes the following TikZ diagrams:

  - Biological analogy (cells <-> nodes)
  - Layer architecture
  - Node lifecycle state machine
  - Role system diagram
  - Election algorithm phases
  - Pheromone packet structure
  - HMAC generation process
  - Bloom filter visualization
  - Gossip probability decay graph
  - Gradient routing visualization
  - NERT reliability classes
  - NERT packet header structure
  - Key derivation process
  - Grace window timeline
  - Nonce structure
  - Connection state machine
  - Two-way handshake sequence
  - SACK example
  - RTO backoff graph
  - FEC XOR parity scheme
  - Multi-path transmission

================================================================================
NanOS Project - 2026
================================================================================
