# NanOS Technical Manual - LaTeX Build
#
# Requirements:
#   - pdflatex (TeX Live or MiKTeX)
#   - latexmk (optional, for auto-rebuild)

MAIN = NanOS_Technical_Manual
LATEX = pdflatex
LATEXFLAGS = -interaction=nonstopmode -halt-on-error

# Output directory
OUTDIR = build

.PHONY: all clean view once

# Default target: full build with references
all: $(OUTDIR)/$(MAIN).pdf

# Create output directory
$(OUTDIR):
	mkdir -p $(OUTDIR)

# Full build (3 passes for TOC and references)
$(OUTDIR)/$(MAIN).pdf: $(MAIN).tex | $(OUTDIR)
	$(LATEX) $(LATEXFLAGS) -output-directory=$(OUTDIR) $(MAIN).tex
	$(LATEX) $(LATEXFLAGS) -output-directory=$(OUTDIR) $(MAIN).tex
	$(LATEX) $(LATEXFLAGS) -output-directory=$(OUTDIR) $(MAIN).tex
	@echo "Build complete: $(OUTDIR)/$(MAIN).pdf"

# Single pass (for quick testing)
once: | $(OUTDIR)
	$(LATEX) $(LATEXFLAGS) -output-directory=$(OUTDIR) $(MAIN).tex

# Clean auxiliary files
clean:
	rm -rf $(OUTDIR)
	rm -f *.aux *.log *.toc *.out *.lof *.lot *.fls *.fdb_latexmk

# View PDF (Linux/macOS)
view: $(OUTDIR)/$(MAIN).pdf
ifeq ($(OS),Windows_NT)
	start $(OUTDIR)/$(MAIN).pdf
else
	xdg-open $(OUTDIR)/$(MAIN).pdf 2>/dev/null || open $(OUTDIR)/$(MAIN).pdf
endif

# Watch and rebuild (requires latexmk)
watch:
	latexmk -pdf -pvc -output-directory=$(OUTDIR) $(MAIN).tex

# Help
help:
	@echo "NanOS Technical Manual - Build Targets"
	@echo ""
	@echo "  make        - Full build (3 passes)"
	@echo "  make once   - Single pass (quick)"
	@echo "  make clean  - Remove build files"
	@echo "  make view   - Open PDF viewer"
	@echo "  make watch  - Auto-rebuild on changes (requires latexmk)"
	@echo ""
	@echo "Output: $(OUTDIR)/$(MAIN).pdf"
