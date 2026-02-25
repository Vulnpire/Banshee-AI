# Banshee

Banshee is an AI-assisted dorking and OSINT CLI for finding exposed documents, sensitive data, misconfigurations, and vulnerable surfaces using search engines, AI-generated queries, and built-in analysis pipelines.

It is designed for security researchers, bug bounty hunters, and defenders who want a repeatable workflow for search-based discovery without manually crafting every query.

This repository README is a practical getting-started guide.

It is not the full manual.

For the complete flag reference, workflow explanations, internal files/caches, outputs, FAQ, and more detailed examples, use the documentation page:

- `vulnpire.github.io/banshee-ai/web/docs.html`
- Local copy: `web/docs.html`

The docs interface also includes a simulated Banshee shell with a virtual `banshee` binary and a very basic CTF for learning/demo purposes.

## README Scope (Important)

This README intentionally focuses on:

- What Banshee is
- What you need to run it
- How to install it
- How to configure the basics
- Common usage patterns
- How to get help quickly

This README intentionally does not try to fully cover:

- Every flag and mode
- All edge-case behaviors
- Every cache and internal file format
- Every AI enhancement workflow
- Full troubleshooting matrix
- Full examples for every feature combination

For those, use the docs site:

- `https://vulnpire.github.io/Banshee-AI`
- `docs/index.html`

## What Banshee Does

At a high level, Banshee helps you:

- Generate dorks from natural-language prompts using AI
- Run dorks across supported search engines
- Deduplicate and organize findings
- Analyze discovered documents and responses for sensitive indicators
- Learn from previous successful scans to improve future dorks
- Use technology detection and CVE-aware logic for better targeting
- Scale to multiple targets using stdin and file-based workflows

Banshee is especially useful when you want to:

- Search for exposed documents across a target's indexed footprint
- Hunt for leaked configuration files and secrets
- Discover admin panels, API paths, backups, and debug endpoints
- Prioritize high-signal results instead of raw search noise
- Build repeatable recon workflows with output files and intelligence caches

## Why a Docs-First Approach

Banshee has grown into a broad toolkit.

A single README that tries to cover everything becomes hard to maintain and hard to read.

The web docs are a better place for:

- Interactive examples
- Rich outputs and annotated screenshots
- Full flag explanations
- Structured navigation
- FAQ and operational notes
- Demo shell and training content

Use this README to get moving.

Use the docs page as your main reference.

## Feature Overview (Short Version)

Banshee includes support for workflows such as:

- AI dork generation from prompts
- Random dork generation by category
- Multi-engine search execution
- SMART dork optimization and follow-ups
- Learning mode with per-target intelligence
- Multi-language dork support for non-English targets
- Document analysis and filtering
- Response analysis and code analysis
- Tech detection and technology-aware dorks
- CVE database workflows and related dork generation
- Wayback-assisted discovery and creative dorking
- Monitor-style recurring scans
- Output files with de-duplication
- Intelligence viewing/export utilities

This is only a summary.

For full feature coverage, use:

- `https://vulnpire.github.io/Banshee-AI`
- `docs/index.html`

## Requirements

### Runtime

- Go `1.20+` to build/install from source
- Network access for search APIs and target content retrieval (when used)
- Shell environment (`bash`/`zsh` etc.) for CLI usage

### Search Providers (Typical)

Banshee commonly uses:

- Google Custom Search (CSE)
- Brave Search API

### AI (Optional but Recommended for `-ai`)

For AI prompt-based dork generation, Banshee can use `gemini-cli`.

You will typically need:

- `gemini-cli` installed
- A valid Gemini API key or configured auth method (depending on your setup)

### Notes

- You can use Banshee without every feature enabled.
- Some modes require specific APIs or local configuration.
- The docs page explains each dependency path in detail.

## Installation

### Option 1: Install with Go

```bash
go install -v github.com/Vulnpire/Banshee-AI@latest
```

After install, make sure your Go bin path is in `PATH`.

Typical paths:

- `~/go/bin`
- `$GOBIN`

Check:

```bash
which banshee
banshee --help
```

### Option 2: Build from Source (Repository Clone)

If you prefer local builds from this repository:

```bash
go build -o banshee .
```

Or if your local setup requires building specific files directly (project/version dependent), use the method described in the docs or your existing workflow.

Then run:

```bash
./banshee --help
```

### Option 3: Use the Docs Interface First (No Install Yet)

If you are evaluating Banshee and do not want to install anything yet:

- Open `web/docs.html`
- Or visit `example.com`
- Use the simulated shell to learn the command style
- Try the basic demo/CTF in the virtual environment

This is useful for:

- New users
- Team onboarding
- Training sessions
- Quick demonstrations

## Basic Configuration (High Level)

Banshee typically needs configuration for API keys and related files.

The exact paths and formats may vary by feature and version.

Use the docs page for authoritative details:

- `https://vulnpire.github.io/Banshee-AI`
- `docs/index.html`

### Common Configuration Concepts

You will usually configure some or all of the following:

- Google API key(s)
- Google CSE / CX configuration
- Brave API key(s)
- Gemini API key or CLI auth
- Optional proxy settings
- Optional out-of-scope lists

### Typical Config Directory Pattern

Many setups use a config directory like:

```bash
~/.config/banshee/
```

Examples of files you may see there (depending on features used):

- `keys.txt`
- `brave-keys.txt`
- `gemini-api-key.txt`
- other feature-specific files/caches

Do not rely only on this README for exact file names and behavior.

Use the docs page for exact configuration instructions and current expectations.

## Quick Start Workflows

This section is intentionally practical.

Copy a command, replace the target, and run.

Then move to the docs page for deeper tuning.

### 1. Traditional Dork (Single Target)

```bash
echo example.com | banshee -q "inurl:admin" -v
```

What this does:

- Reads target from stdin
- Runs a custom dork/query
- Prints verbose logs (`-v`)

### 2. AI Prompt -> Dorks -> Scan

```bash
echo example.com | banshee -ai "find exposed dashboards and APIs" --smart --learn -quantity 5 -v
```

What this does:

- Generates dorks from a natural-language prompt
- Executes them on the target
- Uses SMART mode to analyze successful patterns
- Uses LEARN mode to reuse prior intelligence for the target

For prompt-writing tips and advanced AI tuning, use the docs page.

### 3. Document-Focused Hunting

```bash
echo example.com | banshee -e pdf,docx,xlsx --analyze-docs --filter-docs -o results.txt -v
```

What this does:

- Focuses on document extensions
- Analyzes documents for sensitive indicators
- Filters to more relevant document findings
- Writes output to `results.txt`

For analyzer behavior, file handling, and output specifics, see the docs page.

### 4. Random Dork Generation

```bash
echo example.com | banshee -random sqli --quantity 10 -v
```

What this does:

- Generates category-based dorks without an AI prompt
- Uses the requested quantity
- Runs a quick focused hunt

### 5. Tech Detection + Search

```bash
echo example.com | banshee --tech-detect -ai "find exposed admin or debug panels" -v
```

This is useful when you want technology context to influence how you search and prioritize.

Exact feature interplay varies by mode.

Use the docs page for the recommended workflow patterns.

### 6. Response Analysis Only

```bash
echo https://example.com/api/status | banshee --analyze-response-only -v
```

Use this when you already have a URL and want analysis without running dorks first.

### 7. Monitor-Style Workflow (Recurring)

```bash
cat domains.txt | banshee --monitor "sensitive pdf" --monitor-time 60 --filter-mon --analyze-mon
```

This runs recurring scans on a schedule-like interval (feature behavior depends on your selected flags and environment).

For safe operational usage and tuning, use the docs page.

## Input Patterns

Banshee supports several ways to define targets and search intent.

### stdin (Recommended for Pipelines)

Examples:

```bash
echo example.com | banshee -q "inurl:login"
cat domains.txt | banshee -ai "find exposed docs"
subfinder -d example.com -silent | banshee -q "inurl:admin"
```

Why stdin is useful:

- Easy integration with recon pipelines
- Batch processing from other tools
- Cleaner automation in shell scripts

### Direct Single Target (If Supported by Your Workflow)

Some examples in older usage patterns or docs may show direct target flags.

Prefer the docs page for the current recommended syntax and examples for your version.

### File-Based Inputs

Common patterns include:

- Domain lists
- Prompt lists
- Dork files
- Scope lists / exclusion lists

The exact flags for each file-based workflow are documented in the web docs.

## AI Dorking (Practical Summary)

AI dorking is one of Banshee's core strengths.

Instead of manually crafting every query, you can describe the goal.

Example prompts:

- `find admin panels`
- `find exposed invoices and customer docs`
- `find SQLi candidates`
- `find debug endpoints and test environments`
- `find PIIs in documents`

### Basic AI Usage Example

```bash
echo example.com | banshee -ai "find PIIs in documents" -quantity 5 -v
```

### AI + Learning + SMART Example

```bash
echo example.com | banshee -ai "find leaked config and secrets" --learn --smart -quantity 8 -v
```

### AI + Multi-language Example

```bash
echo example.com | banshee -ai "find sensitive HR documents" --multi-lang -quantity 6 -v
```

### AI Notes

- Prompt quality matters.
- Quantity influences breadth and runtime.
- SMART and LEARN are most useful over repeated scans.
- Multi-language mode can improve results for non-English targets.

For:

- prompt engineering tips
- quantity tuning
- AI model selection
- multi-language behavior
- edge cases and compatibility notes

Use the docs page.

## Document, Response, and Code Analysis

Banshee can do more than collect URLs.

It can analyze content and help prioritize results.

### Document Analysis

Document analysis is helpful for:

- PDF reports
- Office documents
- exported spreadsheets
- files likely to contain PII or internal data

Typical usage pattern:

```bash
echo example.com | banshee -e pdf,docx,xlsx --analyze-docs --filter-docs -v
```

### Response Analysis

Response analysis is helpful when:

- You already have a list of URLs
- You want to inspect returned content for secrets/indicators
- You want signal without broad dork generation

Typical usage pattern:

```bash
echo https://example.com/path | banshee --analyze-response-only -v
```

### Inline Code / Source-Oriented Analysis

Depending on the mode and target content, Banshee can analyze code-like responses or embedded data for high-signal indicators.

The docs page explains:

- analyzers
- filters
- output labels
- severity/sensitivity interpretation
- performance tradeoffs

## Output Files and De-duplication (Basic)

Banshee supports writing results to an output file (for example via `-o`, depending on your command).

Common reasons to use output files:

- Save findings for later analysis
- Track discoveries across runs
- Feed results into other tools
- Build target-specific result sets

General behavior (high level):

- Banshee de-duplicates results written to output files
- Existing entries can affect how repeated results are handled
- New results are appended when discovered

Exact behavior around:

- re-analysis skipping
- analyzer compatibility
- output formatting
- caching interactions

is documented in the web docs.

### Example

```bash
echo example.com | banshee -ai "find sensitive docs" --analyze-docs --filter-docs -o findings.txt -v
```

### Output Hygiene Tips

- Keep one output file per target/program when possible
- Use descriptive filenames
- Archive old runs before large experiments
- Review output with context before reporting findings

## Intelligence, Learning, and Caches (Overview)

Banshee can store and reuse information from previous runs.

This helps improve later scans through features like learning and smart optimization.

High-level concepts you may encounter:

- Target intelligence files
- AI cache(s)
- successful URL tracking
- research caches
- Wayback caches

Benefits:

- Faster repeat runs in some workflows
- Better dork quality over time
- Less repeated work across similar scans

For cache paths, formats, and maintenance, use the docs page.

## Tech Detection and CVE-Aware Workflows (Overview)

Banshee can perform technology detection and use that context to generate or prioritize better dorks.

This is especially useful for:

- exposed admin pages tied to specific stacks
- known technology-specific file patterns
- CVE-related recon hypotheses

Typical workflow idea:

1. Identify target(s)
2. Detect technologies
3. Generate technology-aware dorks
4. Run searches and analyze results
5. Refine using SMART/LEARN

The exact flags and advanced combinations are documented in the web interface.

For detailed setup and usage examples, use:

- `https://vulnpire.github.io/Banshee-AI`
- `docs/index.html`

## TLD-Scale and Multi-Target Scanning (High Level)

Banshee can be used in broader discovery workflows, including multi-target input patterns and TLD-oriented recon use cases (feature/mode dependent).

Because these workflows are more complex and easier to misuse, this README keeps the guidance high level.

Use the docs page for:

- mode compatibility notes
- performance tuning
- scope controls
- output management at scale
- safe usage patterns

If you are scanning multiple targets or broad scopes, make sure your authorization and program rules explicitly allow it.

## Search Strategy Tips (Beginner-Friendly)

These are practical tips that improve results without needing the full manual.

- Start narrow, then expand.
- Pick one goal per run (docs, configs, admin, debug, SQLi candidates, etc.).
- Use `-o` to preserve and review results.
- Add analysis flags when signal matters more than volume.
- Use `--learn` and `--smart` for repeat targets.
- Use `--multi-lang` when the target is non-English.
- Keep your prompts specific when using `-ai`.

### Prompt Examples (Good)

- `find exposed invoices and customer spreadsheets`
- `find admin panels and dashboard logins`
- `find SQLi candidates with id parameters`
- `find debug or staging endpoints`
- `find secrets in config files and logs`

### Prompt Examples (Too Vague)

- `hack site`
- `find bugs`
- `everything`

The docs page includes much better prompt-writing guidance and workflow-specific examples.

## Example Commands (More Practical Samples)

Use these as starting points.

Then tune in the docs.

### Sensitive Documents (AI)

```bash
echo target.com | banshee -v -ai "find PIIs in documents" --learn --smart --analyze-docs --filter-docs -o docs.txt
```

### Admin Panels (Traditional Query)

```bash
echo target.com | banshee -q "inurl:admin OR intitle:login" -v -o admin.txt
```

### Backup and Config File Hunt

```bash
echo target.com | banshee -ai "find backup files and exposed config files" -quantity 8 -v -o files.txt
```

### API / Debug Surface Discovery

```bash
echo target.com | banshee -ai "find debug endpoints, test environments, and APIs" --tech-detect --smart -v
```

### Random SQLi Candidate Sweep

```bash
echo target.com | banshee -random sqli --quantity 12 --learn -v
```

### Batch Domains from File

```bash
cat domains.txt | banshee -ai "find exposed dashboards" -quantity 3 -v -o batch.txt
```

### Response Analysis for Known URL List (Shell Loop Example)

```bash
while read -r url; do
  echo "$url" | banshee --analyze-response-only -v
done < urls.txt
```

### Quiet-ish Pipeline Logging (Adjust Flags)

```bash
cat scope.txt | banshee -ai "find sensitive docs" -quantity 4 -o results.txt
```

If a command fails or behaves unexpectedly, check the docs page before assuming the feature is broken.

Flag combinations can change output and behavior significantly.

## Web Documentation Interface (Primary Reference)

Banshee ships with a web documentation interface in the `web/` directory.

Open it locally:

```bash
xdg-open docs/index.html
```

Or use the hosted version:

- `https://vulnpire.github.io/Banshee-AI`

### What the Web Docs Include

- Quickstart walkthroughs
- Practical examples with sample output
- Feature overviews by category
- Analysis mode guidance
- Monitoring/intelligence notes
- Internal files and configuration notes
- Outputs and caches explanations
- Full flag reference
- FAQ
- Safety/EULA notes

### Simulated Shell + Demo/CTF

The docs include a simulated terminal (JavaScript-only).

It is useful for:

- learning Banshee command style
- demos in presentations
- onboarding new users
- basic CTF-like interaction practice

What it is:

- a virtual environment
- a fake/simulated shell
- a learning interface
- a docs feature

What it is not:

- a real shell
- a system terminal
- a replacement for local installation
- a live exploit environment

The simulated shell includes a virtual `banshee` binary and a very basic CTF flow.

## Suggested Learning Path (New Users)

1. Open `docs/index.html` or `https://vulnpire.github.io/Banshee-AI` and skim the Quickstart section.
2. Run `banshee --help` locally to confirm installation.
3. Try one traditional dork (`-q`) on a test target you are authorized to assess.
4. Try one AI prompt (`-ai`) with low quantity.
5. Add `--smart` and `--learn` on a repeated target.
6. Try a document-focused scan with `--analyze-docs --filter-docs`.
7. Start saving outputs with `-o`.
8. Move to the docs reference for advanced flag combinations.

This path gets you productive quickly without needing to memorize every flag upfront.

## Basic Troubleshooting (Quick Checks)

This is not the full troubleshooting guide.

Use the docs page for the detailed troubleshooting section.

### `banshee: command not found`

Check:

- `PATH` includes your Go bin directory
- `go install` completed successfully
- the binary exists (`which banshee`)

### `--help` Works but Searches Return No Results

Check:

- API keys are configured
- quotas are not exhausted
- target/query is too narrow
- network/proxy settings are correct
- your dork is syntactically reasonable

Try a simpler query first.

### AI Features Not Working

Check:

- `gemini-cli` is installed
- AI credentials/auth are configured correctly
- the prompt is specific enough
- the selected quantity is reasonable for testing

Test with a simple prompt first:

```bash
echo example.com | banshee -ai "find admin panels" -quantity 3 -v
```

### Too Much Noise in Results

Try:

- narrower prompts
- smaller quantity
- analysis/filter flags
- output files and manual review
- tech detection before broad searching

### Too Slow

Performance depends on:

- enabled features
- API limits
- target volume
- analysis modes
- network conditions

Use the docs page for tuning guidance and strategy recommendations.

## Security, Ethics, and Responsible Usage

Use Banshee only on systems and assets you own or are explicitly authorized to test.

Always respect:

- program scope
- rate limits
- terms of service
- local laws and regulations
- responsible disclosure practices

Banshee is a search and analysis tool.

Misuse is your responsibility.

If you are doing bug bounty hunting:

- read the program policy first
- confirm target scope before scanning
- avoid broad scans outside authorization
- verify findings before reporting
- redact sensitive data in reports when required

## Operational Tips for Bug Bounty Hunters

These are intentionally simple and practical.

- Keep separate output files per program.
- Re-scan high-value targets periodically.
- Use low quantities first, then expand.
- Save interesting prompts that worked well.
- Revisit targets with `--learn` and `--smart` after accumulating history.
- Use document analysis for programs with lots of PDFs and public docs.
- Review results manually before escalating any issue.

For advanced hunting playbooks, use the docs page.

## FAQ (Mini)

### Is this README the full documentation?

No.

This README is a practical getting-started guide.

Use `https://vulnpire.github.io/Banshee-AI` or `docs/index.html` for full documentation.

### Can I learn Banshee without installing it first?

Yes.

Open the docs interface and use the simulated shell.

It includes a virtual `banshee` binary and a very basic CTF-like flow.

### Is the docs shell a real terminal?

No.

It is a JavaScript simulation for learning and demos.

### Where do I find all flags?

Use the web docs reference section:

- `https://vulnpire.github.io/Banshee-AI`
- `docs/index.html`

### Where do I find output/cache/internal file explanations?

Use the web docs sections for:

- outputs
- caches
- internal files
- configuration

### Where do I report issues or ask for help?

See the Support section below.

## Versioning and Documentation Accuracy

Banshee evolves quickly.

Some flags, workflows, and defaults may change across versions.

The web docs should be treated as the primary source of usage guidance.

If you notice a mismatch between this README and the docs page:

- Prefer the docs page for detailed behavior
- Check `banshee --help` locally
- Open an issue or contact support

## Contributing

Contributions are welcome.

Useful contribution types include:

- bug fixes
- feature improvements
- documentation improvements
- examples and recipes
- UX improvements in the docs interface

Before making large changes:

- check existing issues/discussions
- describe the problem clearly
- explain expected behavior
- include reproduction steps where possible

If you are updating documentation:

- keep README concise and onboarding-focused
- put detailed reference material in the web docs
- keep examples realistic and safe

## Support

Support: `gorkem@cyberpars.com`

If you are reaching out for help, include:

- command used
- target type (sanitized if needed)
- relevant flags
- error/output snippet
- what you expected

This makes troubleshooting much faster.

## Final Notes

Banshee works best when used as a workflow, not just a single command.

Start simple.

Save outputs.

Let SMART/LEARN build context over time.

Use the web docs for the full picture.

Primary docs:

- `https://vulnpire.github.io/Banshee-AI`
- `docs/index.html`

Stay within scope.
