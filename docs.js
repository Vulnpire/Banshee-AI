const progressBar = document.querySelector('[data-progress] span');
const navLinks = Array.from(document.querySelectorAll('[data-nav]'));
const sections = Array.from(document.querySelectorAll('[data-section]'));
const revealNodes = document.querySelectorAll('.reveal');
const countNodes = document.querySelectorAll('[data-count]');
const filterInput = document.querySelector('[data-filter-input]');
const scrollTopLink = document.querySelector('[data-scroll-top]');
const particleCanvas = document.querySelector('[data-particles]');
const dock = document.querySelector('[data-dock]');
const dockToggle = document.querySelector('[data-dock-toggle]');
const dockShow = document.querySelector('[data-dock-show]');

const updateProgress = () => {
  if (!progressBar) return;
  const scrollable = document.documentElement.scrollHeight - window.innerHeight;
  const ratio = scrollable > 0 ? window.scrollY / scrollable : 0;
  progressBar.style.width = `${Math.min(100, Math.max(0, ratio * 100))}%`;
};

const setActiveNav = (id) => {
  navLinks.forEach((link) => {
    const isActive = link.getAttribute('href') === `#${id}`;
    link.classList.toggle('active', isActive);
  });
};

const initScrollSpy = () => {
  if (!sections.length || !navLinks.length) return;
  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          setActiveNav(entry.target.id);
        }
      });
    },
    { rootMargin: '-20% 0px -60% 0px', threshold: 0.1 }
  );

  sections.forEach((section) => observer.observe(section));
};

const initReveal = () => {
  if (!revealNodes.length) return;
  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add('is-visible');
          observer.unobserve(entry.target);
        }
      });
    },
    { threshold: 0.2 }
  );

  revealNodes.forEach((node) => observer.observe(node));
};

const animateCount = (node) => {
  const target = parseInt(node.dataset.count || '0', 10);
  const duration = 1200;
  const start = performance.now();

  const tick = (now) => {
    const progress = Math.min(1, (now - start) / duration);
    const value = Math.floor(target * progress);
    node.textContent = value.toString();
    if (progress < 1) {
      requestAnimationFrame(tick);
    } else {
      node.textContent = target.toString();
    }
  };

  requestAnimationFrame(tick);
};

const initCounters = () => {
  if (!countNodes.length) return;
  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          animateCount(entry.target);
          observer.unobserve(entry.target);
        }
      });
    },
    { threshold: 0.6 }
  );

  countNodes.forEach((node) => observer.observe(node));
};

const initTabs = () => {
  const tabs = document.querySelector('[data-tabs]');
  if (!tabs) return;

  const buttons = Array.from(tabs.querySelectorAll('[data-tab]'));
  const panels = Array.from(document.querySelectorAll('[data-panel]'));

  const activate = (name) => {
    buttons.forEach((btn) => btn.classList.toggle('active', btn.dataset.tab === name));
    panels.forEach((panel) => panel.classList.toggle('active', panel.dataset.panel === name));
  };

  buttons.forEach((btn) => {
    btn.addEventListener('click', () => activate(btn.dataset.tab));
  });
};

const initCopyButtons = () => {
  const buttons = document.querySelectorAll('[data-copy]');
  buttons.forEach((btn) => {
    btn.addEventListener('click', async () => {
      const container = btn.closest('.code-card, .example-card');
      const explicit = container?.querySelector('[data-copy-source] code');
      const fallback = container?.querySelector('code');
      const code = explicit || fallback;
      const text = code ? code.textContent.trim() : '';

      if (!text) return;

      try {
        await navigator.clipboard.writeText(text);
        const original = btn.textContent;
        btn.textContent = 'Copied';
        setTimeout(() => {
          btn.textContent = original;
        }, 1200);
      } catch (err) {
        btn.textContent = 'Copy failed';
        setTimeout(() => {
          btn.textContent = 'Copy';
        }, 1200);
      }
    });
  });
};

const initFilter = () => {
  if (!filterInput) return;
  const items = Array.from(document.querySelectorAll('[data-filter-item]'));

  filterInput.addEventListener('input', (event) => {
    const query = event.target.value.trim().toLowerCase();
    items.forEach((item) => {
      if (!query) {
        item.classList.remove('is-hidden');
        return;
      }
      const haystack = item.textContent.toLowerCase();
      item.classList.toggle('is-hidden', !haystack.includes(query));
    });
  });
};

const initFlagDetails = () => {
  const panel = document.querySelector('[data-flag-detail]');
  if (!panel) return;
  const titleNode = panel.querySelector('[data-flag-title]');
  const summaryNode = panel.querySelector('[data-flag-summary]');
  const usageNode = panel.querySelector('[data-flag-usage]');
  const detailsNode = panel.querySelector('[data-flag-details]');
  const closeButton = panel.querySelector('[data-flag-close]');
  const rows = Array.from(document.querySelectorAll('.flag-row'));
  const panelParent = panel.parentElement;
  if (panelParent && panelParent !== document.body) {
    panelParent.removeChild(panel);
    document.body.appendChild(panel);
  }

  const flagDetails = {
    '--help': {
      summary: 'Print the built-in help menu and exit.',
      usage: 'banshee --help',
      details: [
        'Shows every flag, default, and example in one place.',
        'Does not run any scans or make network requests.',
        'Use it to confirm required inputs and valid combinations.',
      ],
    },
    '--pages': {
      summary: 'Set the number of search result pages to query per dork.',
      usage: 'echo example.com | banshee -q "inurl:login" -p 3',
      details: [
        'Controls how deep Banshee paginates the search engine.',
        'Higher values increase coverage but add requests and time.',
        'Combine with --delay or --adaptive to avoid rate limits.',
      ],
    },
    '--delay': {
      summary: 'Seconds to sleep between search requests.',
      usage: 'echo example.com | banshee -q "inurl:admin" -d 2',
      details: [
        'Applies a fixed delay between each outgoing query.',
        'Useful for rate-limited engines or fragile proxies.',
        'Lower values speed scans but increase the risk of blocks.',
      ],
    },
    '--workers': {
      summary: 'Parallel worker count for analysis tasks.',
      usage: 'echo example.com | banshee --analyze-docs --workers 8',
      details: [
        'Controls concurrency for document and response analysis.',
        'Higher values use more CPU and memory.',
        'Recommended range is 3-10 depending on resources.',
      ],
    },
    '--verbose': {
      summary: 'Enable verbose logging.',
      usage: 'echo example.com | banshee -q "inurl:admin" -v',
      details: [
        'Prints additional status lines and intermediate steps.',
        'Helps verify filters, caches, and search operators.',
        'Produces larger output, so pipe to a file if needed.',
      ],
    },
    '--output': {
      summary: 'Write unique URLs to a file.',
      usage: 'echo example.com | banshee -q "inurl:admin" -o results.txt',
      details: [
        'Appends only new unique URLs (anew style).',
        'Skips analysis for URLs already present in the file.',
        'Creates the file if missing; combine with -v to log preloads.',
      ],
    },
    '--engine': {
      summary: 'Choose the search engine provider.',
      usage: 'echo example.com | banshee -q "inurl:admin" -engine brave',
      details: [
        'Supported values: both, google, brave.',
        'Controls which API keys and query syntax are used.',
        'Use both for broader coverage when keys are available.',
      ],
    },
    '--model': {
      summary: 'Override the AI model used for dork generation.',
      usage: 'echo example.com | banshee -ai "find admin panels" --model gemini-3-flash-preview',
      details: [
        'Passed to gemini-cli when generating AI dorks.',
        'Allows faster or higher-quality model selections.',
        'Only affects AI features such as -ai or --ai-dork-generation.',
      ],
    },
    '--query': {
      summary: 'Provide a custom dork query or a file of queries.',
      usage: 'echo example.com | banshee -q "inurl:admin"',
      details: [
        'With stdin targets, the query is scoped to those domains.',
        'Without stdin, results are unfiltered (universal search).',
        'You can pass a file path to load one query per line.',
      ],
    },
    '--extensions': {
      summary: 'Limit results to specific file types.',
      usage: 'echo example.com | banshee -e pdf,docx,xlsx',
      details: [
        'Adds filetype filters to dorks for document discovery.',
        'Accepts comma-separated values or a file path.',
        'Pairs well with --analyze-docs for sensitive document triage.',
      ],
    },
    '--word': {
      summary: 'Add dictionary words or paths to searches.',
      usage: 'cat domains.txt | banshee -w admin,login,portal',
      details: [
        'Creates targeted dorks using the supplied word list.',
        'Accepts comma-separated terms or a file path.',
        'Useful for path discovery and common endpoint keywords.',
      ],
    },
    '--contents': {
      summary: 'Search for specific content inside files.',
      usage: 'echo example.com | banshee -c "confidential" -e pdf',
      details: [
        'Uses content operators (intext) for document queries.',
        'Combine with -e to focus on high-value formats.',
        'Expect more noise when content terms are generic.',
      ],
    },
    '--exclusions': {
      summary: 'Exclude targets or subdomains from results.',
      usage: 'echo example.com | banshee -q "inurl:admin" -x admin.example.com',
      details: [
        'Filters out exact hosts or patterns you specify.',
        'Accepts comma-separated values.',
        'Applied before analysis to reduce wasted work.',
      ],
    },
    '--oos-file': {
      summary: 'Use a custom out-of-scope pattern file.',
      usage: 'cat targets.txt | banshee -q "inurl:admin" --oos-file ./oos.txt',
      details: [
        'Default file is ~/.config/banshee/oos.txt.',
        'Supports wildcards like *.example.com and path patterns.',
        'Bug bounty compatible scope filtering.',
      ],
    },
    '--recursive': {
      summary: 'Include subdomains aggressively during search.',
      usage: 'echo example.com | banshee -q "login" -a',
      details: [
        'Expands target scope to subdomains early.',
        'Increases query volume and coverage.',
        'Use with care on large scopes.',
      ],
    },
    '--subdomains': {
      summary: 'Enumerate and include subdomains.',
      usage: 'echo example.com | banshee -s -q "login"',
      details: [
        'Discovers subdomains and adds them as targets.',
        'Pairs well with --deep for recursive discovery.',
        'Improves coverage for multi-tenant targets.',
      ],
    },
    '--find-apex': {
      summary: 'Expand stdin targets to tenant apex domains.',
      usage: 'echo login.example.com | banshee --find-apex -ai "find admin portals"',
      details: [
        'Queries the Microsoft OpenID configuration to extract the tenant ID.',
        'Uses the tenant-domains service to list apex domains for that tenant.',
        'Feeds expanded targets into AI, random, and targeted dorking flows.',
      ],
    },
    '--deep': {
      summary: 'Enable recursive subdomain discovery.',
      usage: 'echo example.com | banshee -s -deep -q "admin"',
      details: [
        'Expands enumeration up to multiple levels.',
        'Produces more targets but increases runtime.',
        'Use with -adaptive to keep rate limits in check.',
      ],
    },
    '--save': {
      summary: 'Stop pagination when results drop off.',
      usage: 'echo example.com | banshee -q "inurl:admin" -save',
      details: [
        'Detects diminishing returns and halts extra pages.',
        'Reduces wasted requests on low-yield queries.',
        'Useful for broad scopes with many dorks.',
      ],
    },
    '--include-dates': {
      summary: 'Add date operators for time-based targeting.',
      usage: 'echo example.com | banshee -q "incident report" -include-dates',
      details: [
        'Adds date ranges to queries for recent content.',
        'Helps surface fresh docs or recent leaks.',
        'Not compatible with monitor mode.',
      ],
    },
    '--ai': {
      summary: 'Generate dorks from an AI prompt.',
      usage: 'echo example.com | banshee -ai "find exposed admin panels"',
      details: [
        'Requires gemini-cli for prompt processing.',
        'Accepts a prompt string or file path (one prompt per line).',
        'Produces focused dorks using target context.',
      ],
    },
    '--quantity': {
      summary: 'Number of AI or random dorks to generate.',
      usage: 'echo example.com | banshee -random sqli -quantity 15',
      details: [
        'Valid range is 1-50 (default 10).',
        'Higher values increase request volume and API usage.',
        'Applies to -ai and -random modes.',
      ],
    },
    '--random': {
      summary: 'Generate random dorks by category.',
      usage: 'echo example.com | banshee -random xss -quantity 5',
      details: [
        'Categories include any, sqli, xss, redirect, lfi, rce, idor, api, cloud.',
        'Useful when you do not want to craft a prompt.',
        'Combine with --research for better targeting.',
      ],
    },
    '--ignore-file': {
      summary: 'Skip dorks listed in a file.',
      usage: 'echo example.com | banshee -random any -ignore-file used.txt',
      details: [
        'Prevents rerunning dorks already used in earlier scans.',
        'Supports one dork per line.',
        'Works with -random and -ai.',
      ],
    },
    '--flush': {
      summary: 'Ignore the ignore file and run fresh dorks.',
      usage: 'echo example.com | banshee -random any -ignore-file used.txt -flush',
      details: [
        'Overrides ignore-file filtering for a clean run.',
        'Useful when you want to re-run a previous set.',
        'Pair with -v to confirm the behavior.',
      ],
    },
    '--simplify': {
      summary: 'Simplify AI prompts before generation.',
      usage: 'echo example.com | banshee -ai "find admin panels quickly" -simplify',
      details: [
        'Removes filler words to focus the prompt.',
        'Reduces token usage and improves signal.',
        'Only affects AI-based dork generation.',
      ],
    },
    '--smart': {
      summary: 'Enable SMART chaining and contextual follow-ups.',
      usage: 'echo example.com | banshee -ai "find admin" -smart',
      details: [
        'Generates follow-up dorks from discoveries.',
        'Uses successful patterns from ~/.config/banshee/successful.txt.',
        'Best paired with -learn for improved intelligence.',
      ],
    },
    '--suggestions': {
      summary: 'Show optimization suggestions for dorks.',
      usage: 'echo example.com | banshee -ai "find admin" -smart --suggestions',
      details: [
        'Prints recommended mutations and improvements.',
        'Requires -smart to be enabled.',
        'Does not modify the run unless you apply suggestions manually.',
      ],
    },
    '--no-followup': {
      summary: 'Disable SMART follow-up dorks.',
      usage: 'echo example.com | banshee -ai "find admin" -smart --no-followup',
      details: [
        'Keeps the original dorks only.',
        'Useful for deterministic runs or tight budgets.',
        'Still logs SMART insights when available.',
      ],
    },
    '--max-followup': {
      summary: 'Limit the number of follow-up dorks per subdomain.',
      usage: 'echo example.com | banshee -ai "find admin" -smart --max-followup 3',
      details: [
        'Caps the follow-up dorks generated by SMART mode.',
        'Lower values reduce requests and output volume.',
        'Useful when scanning many targets at once.',
      ],
    },
    '--correlation': {
      summary: 'Enable multi-layer correlation analysis.',
      usage: 'echo example.com | banshee -ai "find APIs" -smart -correlation',
      details: [
        'Cross-references discoveries for deeper intelligence.',
        'Adds extra dorks based on correlated patterns.',
        'Requires -smart to be enabled.',
      ],
    },
    '-max-correlation': {
      summary: 'Limit correlation dorks generated by SMART.',
      usage: 'echo example.com | banshee -ai "find APIs" -smart -correlation -max-correlation 5',
      details: [
        'Caps the extra correlation dorks.',
        'Helps control query volume in large scans.',
        'Use with -correlation and -smart.',
      ],
    },
    '--learn': {
      summary: 'Persist intelligence for future runs.',
      usage: 'echo example.com | banshee -ai "find admin" -learn',
      details: [
        'Stores per-target intelligence in ~/.config/banshee/.intel.',
        'Tracks successful dorks in ~/.config/banshee/successful.txt.',
        'Improves SMART mode and future AI prompts.',
      ],
    },
    '--waf-bypass': {
      summary: 'Generate obfuscated dorks for WAF evasion.',
      usage: 'echo example.com | banshee -ai "find admin" -waf-bypass',
      details: [
        'Adds encoding and obfuscation variants to dorks.',
        'Useful for bypassing basic filters in search results.',
        'May increase false positives; validate findings.',
      ],
    },
    '--research': {
      summary: 'Enable OSINT research mode.',
      usage: 'echo example.com | banshee -ai "find vulnerabilities" -research',
      details: [
        'Requires -ai or -random mode.',
        'Adds reconnaissance intelligence before generating dorks.',
        'Produces more targeted, high-signal queries.',
      ],
    },
    '--research-depth': {
      summary: 'Set OSINT research depth (1-4).',
      usage: 'echo example.com | banshee -random any -research -research-depth 3',
      details: [
        'Higher depths expand OSINT coverage and time.',
        'Depth 1 is quick, depth 4 is comprehensive.',
        'Use with -research for best results.',
      ],
    },
    '--multi-lang': {
      summary: 'Generate a portion of dorks in the target language.',
      usage: 'echo example.com | banshee -ai "find admin" --multi-lang',
      details: [
        'Detects the target language and localizes dorks.',
        'Works with AI and random modes.',
        'Tune the ratio with --multi-lang-multiplier.',
      ],
    },
    '--multi-lang-multiplier': {
      summary: 'Set the percentage of localized dorks.',
      usage: 'echo example.com | banshee -ai "find admin" --multi-lang --multi-lang-multiplier 40',
      details: [
        'Accepts 0-100 with a default of 25.',
        'Higher values generate more local-language dorks.',
        'Use with --multi-lang.',
      ],
    },
    '--dedupe': {
      summary: 'Enable intelligent deduplication.',
      usage: 'echo example.com | banshee -ai "docs" --dedupe',
      details: [
        'Removes duplicate URLs and similar endpoints.',
        'Required for --analyze-responses.',
        'Reduces repeated analysis and saves AI tokens.',
      ],
    },
    '--analyze-responses': {
      summary: 'Analyze HTTP responses with AI.',
      usage: 'echo example.com | banshee -ai "login" --dedupe --analyze-responses',
      details: [
        'Fetches response bodies and scans for sensitive data.',
        'Requires --dedupe to avoid repeated analysis.',
        'Detects credentials, API keys, and exposed dashboards.',
      ],
    },
    '--analyze-response-only': {
      summary: 'Analyze stdin URLs without dorking.',
      usage: 'echo https://example.com/login | banshee --analyze-response-only',
      details: [
        'Reads URLs from stdin and skips search generation.',
        'Good for pipeline workflows or hand-picked URLs.',
        'Works without -ai or -random flags.',
      ],
    },
    '--analyze-docs': {
      summary: 'Analyze downloaded documents for sensitive data.',
      usage: 'echo example.com | banshee -e pdf,docx --analyze-docs',
      details: [
        'Downloads discovered documents and extracts text.',
        'Uses AI to detect credentials, PII, and secrets.',
        'Pair with -e for tighter file type control.',
      ],
    },
    '--filter-docs': {
      summary: 'Filter out non-sensitive documents.',
      usage: 'echo example.com | banshee -e pdf,docx --analyze-docs --filter-docs',
      details: [
        'Keeps only documents flagged as sensitive.',
        'Reduces output noise for large document sets.',
        'Requires --analyze-docs.',
      ],
    },
    '--inline-code-analysis': {
      summary: 'Extract and analyze inline JavaScript from HTML.',
      usage: 'echo example.com | banshee -ai "find dashboards" --inline-code-analysis',
      details: [
        'Pulls HTML and inspects inline scripts for risky patterns.',
        'Detects sinks related to DOM XSS and redirects.',
        'Requires AI mode (-ai, -random, -smart, or -learn).',
      ],
    },
    '--analyze-code-only': {
      summary: 'Analyze code from stdin without dorking.',
      usage: 'cat app.js | banshee --analyze-code-only',
      details: [
        'Reads raw code from stdin and scans for issues.',
        'No search, no crawling, just code analysis.',
        'Useful for quick checks on downloaded JS.',
      ],
    },
    '--monitor': {
      summary: 'Run continuous monitoring cycles with AI dorks.',
      usage: 'cat domains.txt | banshee --monitor "sensitive pdf" --filter-mon',
      details: [
        'Generates intent-driven dorks every cycle.',
        'Not compatible with -ai, -random, -q, or -include-dates.',
        'Ideal for recurring scans across a fixed target list.',
      ],
    },
    '--monitor-time': {
      summary: 'Minutes between monitor cycles.',
      usage: 'cat domains.txt | banshee --monitor "documents" --monitor-time 30',
      details: [
        'Default interval is 60 minutes.',
        'Lower values increase coverage but add load.',
        'Use with --monitor only.',
      ],
    },
    '--filter-mon': {
      summary: 'Dedupe results across monitor cycles.',
      usage: 'cat domains.txt | banshee --monitor "documents" --filter-mon',
      details: [
        'Keeps only new URLs each cycle.',
        'Filters non-sensitive documents in doc intents.',
        'Reduces noise during long-running monitoring.',
      ],
    },
    '--analyze-mon': {
      summary: 'Analyze monitor results.',
      usage: 'cat domains.txt | banshee --monitor "documents" --analyze-mon',
      details: [
        'Runs document and response analysis in monitor mode.',
        'Skips inline code analysis for performance.',
        'Use with --monitor and optionally --filter-mon.',
      ],
    },
    '--foresee': {
      summary: 'Enable Wayback architecture intelligence.',
      usage: 'echo example.com | banshee --foresee -ai "find XSS" -v',
      details: [
        'Pulls historical URLs from the Internet Archive.',
        'Builds architectural patterns for creative dorks.',
        'Caches URLs and intelligence for faster repeat runs.',
      ],
    },
    '--wmc': {
      summary: 'Filter Wayback results by status code.',
      usage: 'echo example.com | banshee --foresee --wmc 200,301',
      details: [
        'Limits Wayback URLs to specific HTTP status codes.',
        'Use only with --foresee.',
        'Helps focus on reachable URLs.',
      ],
    },
    '--no-wayback-cache': {
      summary: 'Bypass the Wayback cache.',
      usage: 'echo example.com | banshee --foresee --no-wayback-cache',
      details: [
        'Forces fresh Wayback queries for up-to-date data.',
        'Slower and uses more requests.',
        'Use when cache freshness is critical.',
      ],
    },
    '--auto-cleanup-cache': {
      summary: 'Auto-remove Wayback cache entries older than 30 days.',
      usage: 'echo example.com | banshee --foresee --auto-cleanup-cache',
      details: [
        'Deletes stale cache entries after a threshold.',
        'Requires --foresee to be enabled.',
        'Helps keep cache size under control.',
      ],
    },
    '--clear-wayback-cache': {
      summary: 'Clear local Wayback cache and exit.',
      usage: 'banshee --clear-wayback-cache',
      details: [
        'Deletes cached Wayback URLs and intelligence.',
        'Does not run a scan.',
        'Use before a full refresh of results.',
      ],
    },
    '--update-cve-db': {
      summary: 'Update the CVE database with exploitable vulnerabilities.',
      usage: 'banshee --update-cve-db',
      details: [
        'Downloads exploitable CVEs from NVD.',
        'Supports filters like --cve-year and --severity.',
        'Stores results locally for CVE dork generation.',
      ],
    },
    '--cve-year': {
      summary: 'Filter CVEs by year.',
      usage: 'banshee --update-cve-db --cve-year 2025',
      details: [
        'Used only with --update-cve-db.',
        'Accepts a single year like 2024 or 2025.',
        'Combine with --severity for tighter scopes.',
      ],
    },
    '--severity': {
      summary: 'Filter CVEs by severity.',
      usage: 'banshee --update-cve-db --severity critical,high',
      details: [
        'Accepts comma-separated levels: critical, high, medium, low.',
        'Used with --update-cve-db.',
        'Reduces database size to high-signal CVEs.',
      ],
    },
    '--cve-results-per-page': {
      summary: 'Set NVD results per page for CVE updates.',
      usage: 'banshee --update-cve-db --cve-results-per-page 500',
      details: [
        'Higher values reduce API pagination overhead.',
        'Maximum is 2000 per page.',
        'May hit rate limits without an API key.',
      ],
    },
    '--ai-dork-generation': {
      summary: 'Generate AI-powered CVE dorks.',
      usage: 'banshee --update-cve-db --cve-year 2025 --severity critical --ai-dork-generation',
      details: [
        'Uses gemini-cli to craft attack-focused dorks per CVE.',
        'Produces more targeted results than generic CVE strings.',
        'Requires a working AI setup.',
      ],
    },
    '--nvd-api-key': {
      summary: 'Provide an NVD API key for CVE updates.',
      usage: 'banshee --update-cve-db --nvd-api-key YOUR_KEY',
      details: [
        'Increases rate limits and reliability for NVD access.',
        'Alternatively store the key in ~/.config/banshee/nvd-api-key.txt.',
        'Used only with CVE update commands.',
      ],
    },
    '--view-intel': {
      summary: 'View saved intelligence for a target domain.',
      usage: 'banshee --view-intel example.com',
      details: [
        'Prints target intelligence from ~/.config/banshee/.intel.',
        'Includes successful dorks, subdomains, and metadata.',
        'Does not run a scan or generate dorks.',
      ],
    },
    '--export-intel': {
      summary: 'Export saved intelligence to JSON.',
      usage: 'banshee --export-intel example.com -o example-intel.json',
      details: [
        'Writes a JSON snapshot of target intelligence.',
        'Use -o to specify the output file name.',
        'Useful for reports and offline analysis.',
      ],
    },
    '--proxy': {
      summary: 'Route requests through a proxy.',
      usage: 'echo example.com | banshee -q "admin" --proxy http://127.0.0.1:8080',
      details: [
        'Supports HTTP and SOCKS5 proxies.',
        'Useful for Burp or traffic inspection.',
        'Applies to search and analysis requests.',
      ],
    },
    '--insecure': {
      summary: 'Skip TLS certificate verification.',
      usage: 'echo example.com | banshee -q "admin" --proxy http://127.0.0.1:8080 -insecure',
      details: [
        'Allows interception with self-signed certificates.',
        'Use only in controlled environments.',
        'Works with proxy or direct connections.',
      ],
    },
    '--adaptive': {
      summary: 'Enable adaptive delay control.',
      usage: 'echo example.com | banshee -q "admin" -adaptive',
      details: [
        'Adjusts delay based on errors and rate limits.',
        'Pairs well with a low baseline --delay.',
        'Helps stabilize long-running scans.',
      ],
    },
    '--tech-detect': {
      summary: 'Detect tech stack and generate specialized dorks.',
      usage: 'echo example.com | banshee -tech-detect -ai "find admin"',
      details: [
        'Fingerprints frameworks and services for the target.',
        'Feeds tech hints into AI dork generation.',
        'Helps create more relevant, stack-specific queries.',
      ],
    },
    '--scoring': {
      summary: 'Score and prioritize results with AI.',
      usage: 'echo example.com | banshee -ai "find endpoints" -scoring',
      details: [
        'Assigns relevance scores to findings.',
        'Helps triage large output sets.',
        'Best paired with --dedupe and --analyze-responses.',
      ],
    },
    '--budget': {
      summary: 'Optimize dorks based on expected yield.',
      usage: 'echo example.com | banshee -ai "find admin" -budget',
      details: [
        'Allocates query budget to higher-signal dorks.',
        'Reduces wasted queries on low-value patterns.',
        'Useful for limited API quotas.',
      ],
    },
    '--check-leaks': {
      summary: 'Scan paste sites for leaked data.',
      usage: 'echo example.com | banshee -check-leaks -keywords "api,password"',
      details: [
        'Searches paste services for exposed credentials.',
        'Not limited to the target domain.',
        'Use -keywords or AI prompts to focus the scan.',
      ],
    },
    '--keywords': {
      summary: 'Keywords for leak scanning.',
      usage: 'echo example.com | banshee -check-leaks -keywords "aws,token,password"',
      details: [
        'Comma-separated list or file path.',
        'Used only with -check-leaks.',
        'Combine with -ai for richer detection.',
      ],
    },
    '--interactive': {
      summary: 'Launch the interactive TUI assistant.',
      usage: 'banshee --interactive',
      details: [
        'Starts the interactive terminal interface.',
        'Provides quick commands like /help and /dork.',
        'Available in the full Banshee binary, not the demo shell.',
      ],
    },
  };

  const aliasFlags = [
    ['-engine', '--engine'],
    ['-ai', '--ai'],
    ['-random', '--random'],
    ['-quantity', '--quantity'],
    ['-ignore-file', '--ignore-file'],
    ['-flush', '--flush'],
    ['-simplify', '--simplify'],
    ['-smart', '--smart'],
    ['-correlation', '--correlation'],
    ['-learn', '--learn'],
    ['-waf-bypass', '--waf-bypass'],
    ['-research', '--research'],
    ['-research-depth', '--research-depth'],
    ['-save', '--save'],
    ['-include-dates', '--include-dates'],
    ['-tech-detect', '--tech-detect'],
    ['-adaptive', '--adaptive'],
    ['-deep', '--deep'],
    ['-scoring', '--scoring'],
    ['-budget', '--budget'],
    ['-check-leaks', '--check-leaks'],
    ['-keywords', '--keywords'],
    ['-insecure', '--insecure'],
  ];

  aliasFlags.forEach(([alias, target]) => {
    if (flagDetails[target]) {
      flagDetails[alias] = flagDetails[target];
    }
  });

  const getFlagKey = (label) => {
    const match = label.match(/--[\w-]+/);
    if (match) return match[0];
    const token = label.split(/[,\s]+/).find(Boolean);
    return token || label;
  };

  let activeRow = null;

  const closePanel = () => {
    panel.classList.remove('is-active');
    panel.setAttribute('aria-hidden', 'true');
    document.body.classList.remove('flag-detail-open');
    if (activeRow) {
      activeRow.classList.remove('is-active');
      activeRow = null;
    }
  };

  const openPanel = (row) => {
    const label = row.dataset.flagLabel || row.textContent.trim();
    const desc = row.dataset.flagDesc || '';
    const key = row.dataset.flagKey || getFlagKey(label);
    const detail = flagDetails[key];
    const summary = detail?.summary || desc || 'Flag details for this command.';
    const usage = detail?.usage || `banshee ${label.split(',')[0] || label}`;
    const steps = detail?.details || ['Review the help menu for full usage.', 'Combine with other flags as needed.'];

    if (titleNode) titleNode.textContent = detail?.title || label;
    if (summaryNode) summaryNode.textContent = summary;
    if (usageNode) usageNode.textContent = usage;
    if (detailsNode) {
      detailsNode.innerHTML = '';
      steps.forEach((step) => {
        const item = document.createElement('li');
        item.textContent = step;
        detailsNode.appendChild(item);
      });
    }

    panel.classList.add('is-active');
    panel.setAttribute('aria-hidden', 'false');
    document.body.classList.add('flag-detail-open');

    if (activeRow && activeRow !== row) {
      activeRow.classList.remove('is-active');
    }
    activeRow = row;
    activeRow.classList.add('is-active');
    closeButton?.focus();
  };

  rows.forEach((row) => {
    if (row.dataset.flagReady === 'true') return;
    const labelNode = Array.from(row.childNodes).find(
      (node) => node.nodeType === Node.TEXT_NODE && node.textContent.trim()
    );
    const label = labelNode ? labelNode.textContent.trim() : row.textContent.trim();
    const desc = row.querySelector('span')?.textContent.trim() || '';
    const key = getFlagKey(label);

    row.dataset.flagKey = key;
    row.dataset.flagLabel = label;
    row.dataset.flagDesc = desc;
    row.dataset.flagReady = 'true';

    row.textContent = '';
    const main = document.createElement('div');
    main.className = 'flag-row-main';
    const code = document.createElement('code');
    code.textContent = label;
    const descNode = document.createElement('span');
    descNode.className = 'flag-row-desc';
    descNode.textContent = desc;
    main.append(code, descNode);

    const button = document.createElement('button');
    button.className = 'flag-more';
    button.type = 'button';
    button.textContent = 'More';
    button.addEventListener('click', () => openPanel(row));

    row.append(main, button);
  });

  closeButton?.addEventListener('click', closePanel);
  panel.addEventListener('click', (event) => {
    if (event.target === panel) {
      closePanel();
    }
  });
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && panel.classList.contains('is-active')) {
      closePanel();
    }
  });
};

const initScrollTop = () => {
  if (!scrollTopLink) return;
  const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  scrollTopLink.addEventListener('click', (event) => {
    event.preventDefault();
    window.scrollTo({ top: 0, behavior: prefersReducedMotion ? 'auto' : 'smooth' });
  });
};

const initExampleTabs = () => {
  const tabSets = document.querySelectorAll('[data-example-tabs]');
  tabSets.forEach((tabs) => {
    const card = tabs.closest('.example-card');
    if (!card) return;
    const buttons = Array.from(tabs.querySelectorAll('[data-example-tab]'));
    const panels = Array.from(card.querySelectorAll('[data-example-panel]'));

    const activate = (name) => {
      buttons.forEach((btn) => btn.classList.toggle('active', btn.dataset.exampleTab === name));
      panels.forEach((panel) => panel.classList.toggle('active', panel.dataset.examplePanel === name));
    };

    buttons.forEach((btn) => {
      btn.addEventListener('click', () => activate(btn.dataset.exampleTab));
    });
  });
};

const initParticles = () => {
  if (!particleCanvas) return;
  const ctx = particleCanvas.getContext('2d');
  if (!ctx) return;
  const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (prefersReducedMotion) return;

  let width = 0;
  let height = 0;
  let dpr = window.devicePixelRatio || 1;
  let particles = [];
  let rafId = 0;

  const colors = ['rgba(56, 217, 169, 0.6)', 'rgba(85, 193, 255, 0.5)', 'rgba(255, 209, 102, 0.45)'];

  const resize = () => {
    width = window.innerWidth;
    height = window.innerHeight;
    dpr = window.devicePixelRatio || 1;
    particleCanvas.width = width * dpr;
    particleCanvas.height = height * dpr;
    particleCanvas.style.width = `${width}px`;
    particleCanvas.style.height = `${height}px`;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    const count = Math.min(140, Math.max(60, Math.floor((width * height) / 22000)));
    particles = Array.from({ length: count }, () => ({
      x: Math.random() * width,
      y: Math.random() * height,
      vx: (Math.random() - 0.5) * 0.35,
      vy: (Math.random() - 0.5) * 0.35,
      radius: 1 + Math.random() * 1.6,
      color: colors[Math.floor(Math.random() * colors.length)],
    }));
  };

  const step = () => {
    ctx.clearRect(0, 0, width, height);
    ctx.globalCompositeOperation = 'lighter';

    particles.forEach((p) => {
      p.x += p.vx;
      p.y += p.vy;
      if (p.x < -40) p.x = width + 40;
      if (p.x > width + 40) p.x = -40;
      if (p.y < -40) p.y = height + 40;
      if (p.y > height + 40) p.y = -40;

      ctx.beginPath();
      ctx.fillStyle = p.color;
      ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
      ctx.fill();
    });

    for (let i = 0; i < particles.length; i += 1) {
      for (let j = i + 1; j < particles.length; j += 1) {
        const dx = particles[i].x - particles[j].x;
        const dy = particles[i].y - particles[j].y;
        const dist = Math.hypot(dx, dy);
        if (dist < 130) {
          ctx.strokeStyle = `rgba(56, 217, 169, ${0.12 - dist / 1200})`;
          ctx.lineWidth = 0.6;
          ctx.beginPath();
          ctx.moveTo(particles[i].x, particles[i].y);
          ctx.lineTo(particles[j].x, particles[j].y);
          ctx.stroke();
        }
      }
    }

    ctx.globalCompositeOperation = 'source-over';
    rafId = window.requestAnimationFrame(step);
  };

  resize();
  step();

  window.addEventListener('resize', () => {
    window.cancelAnimationFrame(rafId);
    resize();
    step();
  });
};

const initShell = () => {
  const shell = document.querySelector('[data-shell]');
  if (!shell) return;
  const output = shell.querySelector('[data-shell-output]');
  const input = shell.querySelector('[data-shell-input]');
  const promptNode = shell.querySelector('[data-shell-prompt]');
  if (!output || !input || !promptNode) return;
  const fullscreenButton = shell.querySelector('[data-shell-fullscreen]');
  const minimizeButton = shell.querySelector('[data-shell-minimize]');
  const shellHome = shell.parentElement;
  const shellAnchor = document.createComment('shell-anchor');
  if (shellHome) {
    shellHome.insertBefore(shellAnchor, shell);
  }
  let shellOverlay = null;

  const setShellFullscreen = (enabled) => {
    shell.classList.toggle('is-fullscreen', enabled);
    document.body.classList.toggle('shell-fullscreen', enabled);
    if (minimizeButton) {
      minimizeButton.disabled = !enabled;
      minimizeButton.setAttribute('aria-disabled', enabled ? 'false' : 'true');
    }
    if (fullscreenButton) {
      fullscreenButton.setAttribute('aria-pressed', enabled ? 'true' : 'false');
    }
    if (enabled) {
      if (!shellOverlay) {
        shellOverlay = document.createElement('div');
        shellOverlay.className = 'shell-overlay';
        shellOverlay.addEventListener('click', () => setShellFullscreen(false));
      }
      if (!shellOverlay.isConnected) {
        document.body.appendChild(shellOverlay);
      }
      if (shell.parentElement !== document.body) {
        document.body.appendChild(shell);
      }
      input.focus();
      return;
    }
    if (shellOverlay?.isConnected) {
      shellOverlay.remove();
    }
    if (shellHome && shellAnchor.parentElement === shellHome) {
      shellHome.insertBefore(shell, shellAnchor.nextSibling);
    }
    if (!enabled) {
      shell.scrollIntoView({ block: 'center', behavior: 'smooth' });
    }
  };

  fullscreenButton?.addEventListener('click', () => {
    const enabled = shell.classList.contains('is-fullscreen');
    setShellFullscreen(!enabled);
  });

  minimizeButton?.addEventListener('click', () => {
    if (!shell.classList.contains('is-fullscreen')) return;
    setShellFullscreen(false);
  });

  const state = {
    cwd: '/home/elite',
    user: 'elite',
    host: 'banshee',
    isRoot: false,
  };

  const directories = new Map([
    ['/', new Set(['home', 'root'])],
    ['/home', new Set(['elite'])],
    ['/home/elite', new Set(['flag.txt', '.exploit', 'go'])],
    ['/home/elite/.exploit', new Set(['main.sh'])],
    ['/home/elite/go', new Set(['bin'])],
    ['/home/elite/go/bin', new Set(['banshee'])],
    ['/root', new Set(['flag.txt'])],
  ]);

  const files = new Map([
    ['/home/elite/go/bin/banshee', { type: 'binary', content: '' }],
    ['/home/elite/flag.txt', { type: 'flag', content: '' }],
    [
      '/home/elite/.exploit/main.sh',
      {
        type: 'script',
        content:
          '#!/usr/bin/env bash\n# Demo-only privilege escalation walkthrough (simulated).\n# This script is safe and intended for the documentation shell.\n\nset -euo pipefail\n\nLOG=\"/tmp/banshee-exploit-demo.log\"\nUSER_NAME=\"${USER:-elite}\"\n\necho \"[*] Enumerating sudo rules for ${USER_NAME}\" | tee -a \"${LOG}\"\nsudo -n -l 2>/dev/null | tee -a \"${LOG}\"\n\nif sudo -n -l 2>/dev/null | grep -q \"/bin/bash\"; then\n  echo \"[+] NOPASSWD /bin/bash found\" | tee -a \"${LOG}\"\n  echo \"[*] Spawning root shell via sudo /bin/bash -p\" | tee -a \"${LOG}\"\n  sudo -n /bin/bash -p -c \"id && whoami\" 2>/dev/null || true\n  exit 0\nfi\n\necho \"[-] No sudo escape found (demo)\" | tee -a \"${LOG}\"\nexit 1\n',
      },
    ],
    ['/root/flag.txt', { type: 'flag', content: '' }],
  ]);

  const sudoAllow = new Set(['/home/elite/.exploit/main.sh', '/bin/bash']);

  const ensureDir = (path) => {
    if (!directories.has(path)) {
      directories.set(path, new Set());
    }
  };

  const getParentPath = (path) => {
    if (path === '/') return null;
    const parts = path.split('/').filter(Boolean);
    parts.pop();
    return parts.length ? `/${parts.join('/')}` : '/';
  };

  const getBaseName = (path) => {
    const parts = path.split('/').filter(Boolean);
    return parts[parts.length - 1] || '';
  };

  const addChild = (dir, name) => {
    ensureDir(dir);
    directories.get(dir).add(name);
  };

  const createDir = (path, recursive) => {
    if (directories.has(path)) return { ok: true };
    const parent = getParentPath(path);
    if (!parent) return { error: `mkdir: cannot create directory '${path}': File exists` };
    if (!directories.has(parent)) {
      if (!recursive) {
        return { error: `mkdir: cannot create directory '${path}': No such file or directory` };
      }
      const parentResult = createDir(parent, true);
      if (parentResult.error) return parentResult;
    }
    ensureDir(path);
    addChild(parent, getBaseName(path));
    return { ok: true };
  };

  const createFile = (path) => {
    if (directories.has(path)) {
      return { error: `touch: cannot create file '${path}': Is a directory` };
    }
    if (files.has(path)) return { ok: true };
    const parent = getParentPath(path);
    if (!parent || !directories.has(parent)) {
      return { error: `touch: cannot create file '${path}': No such file or directory` };
    }
    const name = getBaseName(path);
    const type = name === 'flag.txt' ? 'flag' : name === 'banshee' ? 'binary' : 'text';
    files.set(path, { type, content: '' });
    addChild(parent, name);
    return { ok: true };
  };

  const removeFile = (path) => {
    if (!files.has(path)) {
      return { error: `rm: cannot remove '${path}': No such file` };
    }
    const parent = getParentPath(path);
    if (parent && directories.has(parent)) {
      directories.get(parent).delete(getBaseName(path));
    }
    files.delete(path);
    return { ok: true };
  };

  const removeDir = (path) => {
    if (!directories.has(path)) {
      return { error: `rmdir: failed to remove '${path}': No such file or directory` };
    }
    if (path === '/' || path === '/home' || path === '/home/elite') {
      return { error: `rmdir: failed to remove '${path}': Permission denied` };
    }
    const children = directories.get(path);
    if (children && children.size > 0) {
      return { error: `rmdir: failed to remove '${path}': Directory not empty` };
    }
    const parent = getParentPath(path);
    if (parent && directories.has(parent)) {
      directories.get(parent).delete(getBaseName(path));
    }
    directories.delete(path);
    return { ok: true };
  };

  const writeFile = (path, content, append) => {
    if (!files.has(path)) {
      const createResult = createFile(path);
      if (createResult.error) return { error: createResult.error };
    }
    const entry = files.get(path);
    if (!entry) {
      return { error: `bash: ${path}: No such file or directory` };
    }
    if (entry.type === 'binary' || entry.type === 'flag') {
      return { error: `bash: ${path}: Permission denied` };
    }
    const current = entry.content || '';
    entry.content = append ? `${current}${content}` : content;
    files.set(path, entry);
    return { ok: true };
  };

  const shellHelp = `Available commands:
  help                 Show this help
  ls [-a] [path]       List files
  pwd                  Print working directory
  cd [path]            Change directory
  whoami               Print current user
  id                   Show user and groups
  neofetch             Show system information (demo)
  history              Show command history
  date                 Show current time
  uname                Show system info
  sudo -l              Show sudo permissions
  sudo <cmd>           Run a command as root (demo)
  exit                 Exit root shell
  bash <file>          Run a script file (demo)
  cat <file>           Print a file (flag.txt returns a random flag)
  echo [-e] <text>     Print text (-e enables \\n)
  touch <file>         Create an empty file
  mkdir [-p] <dir>     Create directory
  rmdir <dir>          Remove empty directory
  rm <file>            Remove a file
  clear                Clear the terminal
  banshee [flags]      Run the demo Banshee binary (~/go/bin/banshee)
  ~/go/bin/banshee     Explicit path to the demo binary

Examples:
  echo target.com | banshee -q "inurl:admin"
  echo target.com | banshee -ai "sensitive dashboards"
  echo target.com | banshee -random sqli
  bash .exploit/main.sh
  sudo -l
  sudo /home/elite/.exploit/main.sh
  sudo /bin/bash
  exit

Notes:
  This is a simulated shell for learning Banshee. No real system commands run.`;

  const bansheeUsage = `Banshee (demo)
Usage examples:
  echo example.com | banshee -q "inurl:admin" -a --tech-detect
  cat domains.txt | banshee --monitor "sensitive pdf" --filter-mon
  banshee --update-cve-db --cve-year 2025 --severity critical --ai-dork-generation

Run "banshee --help" for the full help menu.`;

  const bansheeHelp = String.raw`
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡄⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣇⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢀⣠⠴⠚⠋⠉⢹⣯⠉⠉⠛⠲⢤⣀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢀⡴⠋⠀⣣⠤⠒⠒⣺⣿⡒⠒⠢⢤⡃⠉⠳⣄⠀⠀⠀⠀
⢀⡀⠀⣠⠋⠀⡰⠊⠀⠀⢀⣼⠏⠈⢿⣄⠀⠀⠈⠲⡀⠈⢧⡀⠀⣀
⠀⠈⢳⠧⢤⣞⠀⠀⠀⢀⣾⠏⠀⠀⠈⢿⣆⠀⠀⠀⢘⣦⠤⢷⠋⠀
⠀⠀⡾⠤⡼⠈⠛⢦⣤⣾⡏⣠⠶⠲⢦⡈⣿⣦⣤⠞⠋⢹⡤⠼⡇⠀
⠀⠀⡇⠀⠆⠀⠀⢾⣿⣿⢸⡁⣾⣿⠆⣻⢸⣿⢾⠄⠀⠀⠆⠀⡇⠀
⠀⠀⣧⠐⢲⠀⣠⡼⠟⣿⡆⠳⢬⣥⠴⢃⣿⡟⠻⣤⡀⢸⠒⢠⡇⠀
⠀⢀⣸⡤⠞⢏⠁⠀⠀⠘⢿⡄⠀⠀⠀⣼⠟⠀⠀⠀⢙⠟⠦⣼⣀⠀
⠐⠉⠀⠹⡄⠈⠣⡀⠀⠀⠈⢿⣄⢀⣾⠏⠀⠀⠀⡠⠋⢀⡼⠁⠈⠑
⠀⠀⠀⠀⠙⢦⣀⠈⡗⠢⠤⢈⣻⣿⣃⠠⠤⠲⡍⢀⣠⠞⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠈⠛⠦⣄⣀⡀⢸⣏⠀⣀⣀⡤⠞⠋⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⡏⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
 Banshee v1.37.1
 - Made by Vulnpire


╔════════════════════════════════════════════════════════════════════════════════╗
║                   Banshee AI - Advanced OSINT & Dorking Tool                   ║
║                         Version 1.37.1 - Powered by AI                         ║
╚════════════════════════════════════════════════════════════════════════════════╝

# USAGE
  banshee [FLAGS] [OPTIONS]

# CORE OPTIONS
  -h, --help                    Display this help message
  (stdin)                     Pipe targets via stdin (cat domains.txt | banshee ...)
                               • -q works without stdin for universal search
  -p, --pages <NUM>             Number of search result pages [default: 1]
  -d, --delay <SEC>             Delay in seconds between requests [default: 1.5]
  --workers <NUM>              Number of parallel workers for processing [default: 5]
                               • Speeds up document analysis & response processing
                               • Recommended: 3-10 workers (based on system resources)
  -v, --verbose                 Enable verbose output (detailed logging)
  -o, --output <FILE>           Export results to file (URLs only)
                               • Always writes unique URLs; skips doc/inline-code/response analysis for URLs already in the file

# SEARCH OPTIONS
  -e, --extensions <EXT>       Comma-separated file extensions (pdf,doc,xls)
  -w, --word <WORD>            Dictionary/paths/files to search
  -q, --query <QUERY>          Custom dork query or file with queries
  -c, --contents <TEXT>        Search for specific content in files
  -x, --exclusions <EXC>       Exclude targets (www,admin,test)
  --oos-file <FILE>           Out-of-scope file (supports wildcards, one per line)
                               • Default: ~/.config/banshee/oos.txt
                               • Compatible with bug bounty scope files
                               • Wildcards: *.example.com, csd-*.domain.com
  -a, --recursive              Aggressive crawling (includes subdomains)
  -s, --subdomains             Enumerate subdomains
  --find-apex                  Resolve apex domains via tenant lookup (expands stdin targets)
  -engine <ENGINE>            Search engine: both (default), google, brave

# PROXY & NETWORK
  -r, --proxy <PROXY>         Proxy URL: http://127.0.0.1:8080 or socks5://user:pass@host:1080
  -insecure                    Skip TLS certificate verification (for Burp Suite)

# AI-POWERED FEATURES ✨
  -ai <PROMPT>                AI-powered dork generation (requires gemini-cli)
                               • Can be prompt string or file path (one prompt per line)
                               • Example: -ai "find exposed admin panels"
  -random <TYPE>              Generate random dorks:
                               • any: Diverse dorks across all categories
                               • sqli, xss, redirect, lfi, rce, idor, api, cloud
  -quantity <NUM>             Number of AI/random dorks to generate [1-50, default: 10]
  -simplify                   Simplify AI prompts (removes filler words)
  --model <MODEL>             AI model to use (gemini-3-pro-preview, gemini-3-flash-preview)

  --multi-lang               Generate a portion of dorks in detected target language (uses config: multi-lang-multiplier)
  --multi-lang-multiplier <0-100>  Percentage of dorks in target language when --multi-lang is enabled (default 25)

# MONITOR MODE 🛰
  --monitor <INTENT>         Continuous monitoring with AI-generated dorks
                               • Examples: "sensitive pdf", "sqli,xss,redirect", "monitor for new docs"
                               • Intent-driven: "documents", "dashboards", "all" (multi-intent supported)
                               • Not compatible with -ai, -random, -q, or --include-dates
  --monitor-time <MIN>        Minutes between monitor cycles [default: 60]
  --filter-mon                 Dedupe URLs across cycles + filter non-sensitive docs (doc intents)
  --analyze-mon                Analyze monitor results (documents + responses; skips inline code)

# OSINT & RESEARCH 🔍
  -research                   OSINT research mode (reconnaissance + specialized dorks)
                               • Must be used with -ai or -random
  -research-depth <1-4>      Research depth level [default: 1]
                               • 1: Basic info, CVEs, tech stack
                               • 2: Detailed security posture, infrastructure
                               • 3: Comprehensive OSINT, historical analysis
                               • 4: Linguistic intelligence (emails, departments)
  -learn                      Continuous learning mode (saves intelligence)
                               • Tracks successful/failed dorks per target
                               • Generates progressively better dorks
                               • Intelligence: ~/.config/banshee/.intel

# SMART MODE & AI ENHANCEMENTS ⚡
  -smart                      Context-aware dork chaining and optimization
                               • Generates contextual follow-up dorks from discoveries
                               • Post-scan optimization suggestions
  --suggestions                Show dork optimization suggestions (requires --smart)
  --no-followup                Skip follow-up dork generation (requires --smart)
  --max-followup <NUM>        Max follow-up dorks per subdomain [default: 5]
  -correlation                 Multi-layer correlation analysis (requires --smart)
  -max-correlation <NUM>     Max correlation dorks [default: 10]
  -waf-bypass                  Adversarial dork generation with obfuscation
  -save                        Smart pagination (stops on diminishing returns)
  -include-dates               Strategic date operators for targeting
  -tech-detect                 Auto-detect tech stack and generate specialized dorks
  -adaptive                    Adaptive rate limiting based on response patterns
  -deep                        Recursive subdomain discovery (up to 3 levels)
  -scoring                     AI-based result classification and vulnerability scoring
  -budget                      Smart query budget optimization

# SECURITY ANALYSIS 🛡
  --analyze-docs               Analyze documents (PDF, DOCX, XLSX) for sensitive info
  --filter-docs                Filter non-sensitive documents (requires --analyze-docs)
  --dedupe                     Intelligent deduplication with semantic analysis
  --analyze-responses          AI-powered response analysis (requires --dedupe)
                               • Detects: credentials, API keys, PII, dashboards
  --analyze-response-only      Analyze URL(s) from STDIN without dorking
                               • Example: echo "https://site.com" | banshee --analyze-response-only
  --analyze-code-only          Analyze CODE from STDIN for vulnerabilities (no dorking)
                               • Analyzes JavaScript/code for security issues
                               • Example: cat script.js | banshee --analyze-code-only
  --inline-code-analysis       Extract & analyze inline JavaScript from HTML
                               • Detects: DOM-XSS, dangerous sinks, open redirects
                               • Requires AI mode (-ai, -random, -smart, or -learn)
  -check-leaks                 Check paste sites for leaked credentials
  -keywords <KEYWORDS>       Keywords for leak checking (comma-separated or file)

# WAYBACK MACHINE - AI FORESEE MODE (ARCHITECTURE INTELLIGENCE) 🔮 🤖
  --foresee                     Enable AI foresee mode: study target architecture and generate creative dorks
                               • Discovers historical URLs from Internet Archive (Wayback Machine)
                               • AI studies architecture: URL patterns, tech stack, naming conventions
                               • AI understands WHERE vulnerabilities might exist based on structure
                               • Generates CREATIVE dorks that infer similar patterns (not copy exact URLs)
                               • Forecasts target architecture to find related vulnerabilities
                               • Caches: 24h URLs, 7d intelligence
  --wmc <CODES>                Filter by status codes (requires --foresee)
                               • Format: 200 or 200,301,404 | Default: all
  --no-wayback-cache           Bypass cache, fetch fresh data (requires --foresee)
  --auto-cleanup-cache        Auto-remove cache >30 days (requires --foresee)
  --clear-wayback-cache       Clear ALL Wayback cache and exit
  Examples:
    echo domain.com | banshee --foresee --ai "find XSS" -v
    echo domain.com | banshee --foresee --wmc 200 --no-wayback-cache
    echo domain.com | banshee --foresee --ai "find admin" --smart --dedupe
    banshee --clear-wayback-cache  # Cleanup command

# CVE DATABASE & MANAGEMENT 🔓
  --update-cve-db              Update CVE database with exploitable vulnerabilities
  --cve-year <YEAR>           Filter CVEs by year (e.g., 2024, 2025)
  --severity <LEVEL>          Filter by severity: critical, high, medium, low
  --ai-dork-generation         Generate AI-powered CVE dorks (requires gemini-cli)
  --nvd-api-key <KEY>         NVD API key (or save to ~/.config/banshee/nvd-api-key.txt)
  --view-intel <DOMAIN>       View saved intelligence for a domain
  --export-intel <DOMAIN>     Export intelligence to JSON

# INTERACTIVE MODE 💬
  --interactive                Launch interactive TUI with AI assistant
                               • Commands: /help, /research, /dork, /smart, /intel, /exit

# STDIN SUPPORT 📥
  Pipe domains/URLs via stdin:
    • echo "example.com" | banshee -ai "find admin" -v
    • cat domains.txt | banshee -random any -quantity 10
    • cat domains.txt | banshee --monitor "sensitive pdf" -learn -smart -quantity 5

    • subfinder -d example.com | banshee -e pdf,doc

# EXAMPLES
  echo "example.com" | banshee -e pdf,doc,bak
  cat domains.txt | banshee -w login.html,search,redirect,?id= -x admin.example.com
  echo "example.com" | banshee -ai "find sensitive docs" --analyze-docs -v
  cat domains.txt | banshee --monitor "documents" -learn -smart -quantity 5 -adaptive -deep --no-followup -p 5 -x www
  subfinder -d example.com | banshee -s -p 10 -d 5 -o banshee-subdomains.txt
  banshee -q "intitle:index of" -p 2

# Out-of-Scope Filtering (Bug Bounty Compatible):
  Use default OOS file:
    echo "example.com" | banshee -e pdf,doc -v
    # Automatically filters URLs matching patterns in ~/.config/banshee/oos.txt

  Use custom OOS file:
    cat targets.txt | banshee -random any --oos-file ./bug-bounty-oos.txt -v

  OOS file format (supports wildcards):
    # Comment lines start with #
    *.out-of-scope.com          # Wildcard subdomain
    csd-*.contentsquare.com     # Wildcard pattern
    subdomain.example.com        # Exact match
    example.com/public/*         # Path wildcard

# Smart Mode & AI Enhancement Examples:
  Basic smart mode (contextual follow-up dorks):
    echo dell.com | banshee -ai "find admin dashboards" -smart -v
    # Discovers i.dell.com → generates: site:i.dell.com find admin dashboards

  With optimization suggestions:
    echo dell.com | banshee -ai "find admin" -smart --suggestions -v
    # Shows [MUTATE], [MERGE], [SPECIALIZE], [NEW] dork improvements

  Skip follow-up dorks:
    echo dell.com | banshee -ai "find admin" -smart --no-followup -v
    # Only executes original dorks, no follow-ups

  Limit follow-up dorks:
    echo dell.com | banshee -ai "find admin" -smart --max-followup 10 -v
    # Generates max 10 follow-up dorks instead of default 5

  Smart mode with correlation:
    echo dell.com | banshee -ai "find APIs" -smart -correlation -v
    # Cross-correlates discoveries for deeper intelligence

  All smart features combined:
    echo dell.com | banshee -ai "find admin" -smart --suggestions --max-followup 3 -correlation -v

# Random Dork Generation:
  Generate 10 diverse random dorks:
    echo "example.com" | banshee -random any -quantity 10 -v

  Generate SQLi-focused dorks:
    echo "example.com" | banshee -random sqli -quantity 5 -v

  With ignore file to avoid duplicates:
    echo "example.com" | banshee -random any -quantity 15 -ignore-file used-dorks.txt -v

  Flush mode - ignore previous dorks:
    echo "example.com" | banshee -random any -quantity 20 -flush -v

  Multiple domains:
    cat domains.txt | banshee -random any -quantity 20 -ignore-file used.txt -o results.txt

  Cloud asset enumeration (S3, Azure, GCP):
    echo "example.com" | banshee -random cloud -quantity 15 -v
    echo "dell.com" | banshee -random cloud -research -research-depth 2 -v

# Universal Search (No Target Domain Filter):
  Search without domain restriction (shows ALL results):
    banshee -q 'site:s3.amazonaws.com "dell"' -v
    banshee -q '"company-backup" (site:storage.googleapis.com OR site:digitaloceanspaces.com)' -v
    banshee -q 'site:blob.core.windows.net filetype:xlsx' -o results.txt

  Find cloud assets for any company:
    banshee -q 'site:s3.amazonaws.com inurl:backup' -v
    banshee -q 'site:storage.googleapis.com "confidential"' -v

  Note: When using -q without piping targets via stdin, ALL matching results are returned (no domain filtering).
        This is useful for cloud enumeration and broad searches.

# OSINT Research Mode:
  Basic research with AI dorks:
    echo "example.com" | banshee -ai "find vulnerabilities" -research -v

  Moderate depth research with random dorks:
    echo "example.com" | banshee -random any -research -research-depth 2 -quantity 15 -v

  Comprehensive research (depth 3):
    echo "example.com" | banshee -ai "security assessment" -research -research-depth 3 -quantity 20 -v

  Research mode with specific vulnerability focus:
    echo "example.com" | banshee -random sqli -research -research-depth 2 -v

  Multiple targets with research mode:
    cat domains.txt | banshee -random any -research -research-depth 1 -o results.txt -v

  Note: Research mode performs OSINT on the target company to identify:
    - Known vulnerabilities and CVEs
    - Past security incidents
    - Technology stack and infrastructure
    - Common exposed assets
    - Industry-specific weaknesses
  Then generates highly targeted dorks based on this intelligence.

# Continuous Learning Mode (-learn):
  Enable learning for better dork generation over time:
    echo "example.com" | banshee -random any -learn -v
    echo "example.com" | banshee -ai "find admin panels" -learn -quantity 15 -v

  AI-powered subdomain enumeration with learning:
    echo "example.com" | banshee -subdomains -learn -v
    echo "example.com" | banshee -s -learn -quantity 20 -v

  Research mode with continuous learning:
    echo "example.com" | banshee -random sqli -research -learn -v

  Multiple scans - intelligence improves each time:
    echo "example.com" | banshee -random any -learn -v    # First scan - builds intelligence
    echo "example.com" | banshee -random any -learn -v    # Second scan - uses learned patterns
    echo "example.com" | banshee -random any -learn -v    # Third scan - even better targeting

  How it works:
    1. Stores successful/failed dorks in ~/.config/banshee/.intel/<target-hash>.json
    2. Successful dorks also saved to ~/.config/banshee/successful.txt (for --smart mode)
    3. Tracks discovered: subdomains, paths, file types, API endpoints, cloud assets
    4. Analyzes which dork patterns/types work best for this target
    5. Generates NEW dorks using successful patterns as a guide
    6. Each scan produces BETTER, more targeted dorks (not reused ones)
    7. Saves AI quota by focusing on what actually works for this target

  Storage Locations:
    • Target intelligence: ~/.config/banshee/.intel/<target-hash>.json
    • Successful dorks: ~/.config/banshee/successful.txt (analyzed by --smart mode)
    • Wayback cache: ~/.config/banshee/.wayback_cache/<domain_hash>.json
    • Response cache: ~/.config/banshee/.response_cache/<url_hash>.json

  What it discovers and learns from:
    - Successful dork patterns (inurl, filetype, intitle, etc.)
    - Discovered subdomains and naming patterns
    - Common paths and directory structures
    - File extensions that exist on the target
    - API endpoints and cloud assets
    - Best dork categories (admin, api, config, etc.)
    - Statistical trends (average results per dork type)

  Benefits:
    ✓ Generates progressively BETTER dorks with each scan
    ✓ Learns what works specifically for this target
    ✓ Reduces wasted AI API calls (smarter from the start)
    ✓ Builds target-specific intelligence over time
    ✓ Works with ALL AI features (-ai, -random, -subdomains)
    ✓ No duplicate dorks - always generates fresh, improved variations

# Document Analysis Examples:
  Basic document analysis (verbose mode shows all documents):
    echo "example.com" | banshee -e pdf,docx,xlsx --analyze-docs -v

  Filter out non-sensitive documents (user guides, manuals, etc.):
    echo "example.com" | banshee -e pdf,docx --analyze-docs --filter-docs -v

  Search for specific document types with AI-powered analysis:
    echo "example.com" | banshee -ai "find technical documents" --analyze-docs -v

  Non-verbose mode (only shows sensitive documents):
    echo "example.com" | banshee -e pdf,docx,xlsx --analyze-docs

  Combine with SMART mode for comprehensive analysis:
    echo "example.com" | banshee -ai "find documents" -smart --analyze-docs --filter-docs -v

  How it works:
    - Downloads found documents (PDF, DOCX, PPTX, XLSX, XLS, CSV, TXT)
    - Extracts text content (uses pdftotext for PDFs, ZIP/XML parsing for XLSX)
    - Analyzes with AI for sensitive information: credentials, PII, API keys, etc.
    - Verbose mode: Shows summary for ALL documents found
    - Non-verbose: Only reports documents containing sensitive information
    - Filter mode: Skips non-sensitive documents (user guides, manuals, datasheets)

# Leak Checking (Paste Site Monitoring):
  Stdin input (newline-separated):
    echo "example.com" | banshee -check-leaks -v
    cat domains.txt | banshee -check-leaks -keywords "api,password" -v

  With comma-separated keywords:
    echo "example.com" | banshee -check-leaks -keywords "api,token,password,secret" -v

  With keywords from file:
    echo "example.com" | banshee -check-leaks -keywords keywords.txt -v

  AI-powered leak detection:
    echo "example.com" | banshee -check-leaks -ai "find credentials and API keys" -v

  Combine keywords with AI:
    echo "example.com" | banshee -check-leaks -keywords "aws,azure,gcp" -ai "cloud credentials" -v

  With specific search engine:
    echo "example.com" | banshee -check-leaks -engine brave -v

  Note: Leak checking searches 15+ paste sites including:
    - pastebin.com, ghostbin.com, paste.ee
    - gist.github.com, gitlab.com/-/snippets
    - hastebin.com, rentry.co, controlc.com
    - dpaste.com, privatebin.net, and more
  The -check-leaks feature searches for exposed credentials WITHOUT filtering
  to the target domain (it searches paste sites, not the target).

# CVE Database Management (Update & Filter Exploitable CVEs):
  Update CVE database with all exploitable CVEs:
    banshee --update-cve-db

  Get only 2024 critical exploits:
    banshee --update-cve-db --cve-year 2024 --severity critical

  Get 2024 critical AND high severity:
    banshee --update-cve-db --cve-year 2024 --severity critical,high

  Bulk download with higher results per page (faster):
    banshee --update-cve-db --cve-year 2024 --cve-results-per-page 500

  Maximum results per page (2000 max):
    banshee --update-cve-db --severity critical,high --cve-results-per-page 2000

  Use API key from file (recommended):
    echo "YOUR_NVD_API_KEY" > ~/.config/banshee/nvd-api-key.txt
    banshee --update-cve-db

  Or provide API key via flag:
    banshee --update-cve-db --nvd-api-key YOUR_KEY

  AI-Powered Dork Generation (RECOMMENDED for Defcon quality):
    banshee --update-cve-db --cve-year 2025 --severity critical --ai-dork-generation

    This uses gemini-cli to generate specialized, attack-focused dorks for each CVE.
    Instead of generic dorks like 'intext:"CVE-2025-1234"', you get targeted dorks
    based on the CVE's specific attack vector, vulnerable endpoints, and technology
    fingerprints. Install gemini-cli: https://github.com/reugn/gemini-cli

    Example AI-generated dorks (vs traditional):
    Traditional: intext:"Spring" "CVE-2025-2320"
    AI-powered:  inurl:/actuator/env intitle:"Whitelabel Error Page" "Spring Framework"
                 site:*.com inurl:/api/v1 "Spring Boot" filetype:json
                 intitle:"Error" "SpringBootApplication" inurl:/error

  View intelligence for a target:
    banshee --view-intel example.com

  Export intelligence to JSON:
    banshee --export-intel example.com -o example-intel.json

  Note: CVE updates only include EXPLOITABLE vulnerabilities:
    ✓ RCE, SQLi, XSS, Path Traversal, Auth Bypass, File Upload
    ✓ SSRF, Command Injection, Privilege Escalation, Info Disclosure
    ✗ DoS-only CVEs are skipped (not useful for Google dorking)
  Get your free NVD API key: https://nvd.nist.gov/developers/request-an-api-key

[INFO] This is a simulated help output for the documentation shell.
[INFO] The real Banshee binary behaves differently and supports more features.
`;

  const history = [];
  let historyIndex = -1;

  const formatCwd = (path) => {
    if (path.startsWith('/home/elite')) {
      const suffix = path.slice('/home/elite'.length);
      return `~${suffix || ''}`;
    }
    if (path.startsWith('/root')) {
      const suffix = path.slice('/root'.length);
      return `~${suffix || ''}`;
    }
    return path;
  };

  const updatePrompt = () => {
    const suffix = state.isRoot ? '#' : '$';
    promptNode.textContent = `${state.user}@${state.host}:${formatCwd(state.cwd)}${suffix}`;
  };

  const setRoot = (useRootHome) => {
    state.isRoot = true;
    state.user = 'root';
    if (useRootHome && isDir('/root')) {
      state.cwd = '/root';
    }
    updatePrompt();
  };

  const dropRoot = () => {
    state.isRoot = false;
    state.user = 'elite';
    state.cwd = '/home/elite';
    updatePrompt();
  };

  const renderSudoList = () => {
    if (state.isRoot) {
      return `User root may run the following commands on ${state.host}:\n    (ALL) ALL`;
    }
    return `Matching Defaults entries for ${state.user} on ${state.host}:\n    env_reset, mail_badpass, secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nUser ${state.user} may run the following commands on ${state.host}:\n    (root) NOPASSWD: /home/elite/.exploit/main.sh\n    (root) NOPASSWD: /bin/bash`;
  };

  const scrollToBottom = () => {
    output.scrollTop = output.scrollHeight;
  };

  const appendLine = (text, className) => {
    const line = document.createElement('div');
    line.className = className ? `shell-line ${className}` : 'shell-line';
    line.textContent = text;
    output.appendChild(line);
  };

  const appendOutput = (text, className, isMarkup = false) => {
    text.split('\n').forEach((line) => {
      if (!isMarkup) {
        appendLine(line, className);
        return;
      }
      const row = document.createElement('div');
      row.className = className ? `shell-line ${className}` : 'shell-line';
      row.innerHTML = line;
      output.appendChild(row);
    });
  };

  const appendCommandLine = (command) => {
    const line = document.createElement('div');
    line.className = 'shell-line shell-command-line';
    const promptSpan = document.createElement('span');
    promptSpan.className = 'shell-prompt';
    promptSpan.textContent = promptNode.textContent;
    const commandSpan = document.createElement('span');
    commandSpan.className = 'shell-command';
    commandSpan.textContent = command;
    line.append(promptSpan, document.createTextNode(' '), commandSpan);
    output.appendChild(line);
  };

  const normalizePath = (path) => {
    const parts = path.split('/').filter(Boolean);
    const stack = [];
    parts.forEach((part) => {
      if (part === '.') return;
      if (part === '..') {
        stack.pop();
        return;
      }
      stack.push(part);
    });
    return `/${stack.join('/')}`;
  };

  const resolvePath = (rawPath) => {
    const home = state.isRoot ? '/root' : '/home/elite';
    if (!rawPath || rawPath === '~') return home;
    if (rawPath.startsWith('~/')) return normalizePath(`${home}/${rawPath.slice(2)}`);
    if (rawPath.startsWith('/')) return normalizePath(rawPath);
    return normalizePath(`${state.cwd}/${rawPath}`);
  };

  const isDir = (path) => directories.has(path);
  const isFile = (path) => files.has(path);
  const isRootOnlyPath = (path) => path === '/root' || path.startsWith('/root/');

  const listDir = (path, showAll) => {
    const entries = Array.from(directories.get(path) || []).sort();
    if (showAll) return entries;
    return entries.filter((entry) => !entry.startsWith('.'));
  };

  const formatLsDate = () => {
    const now = new Date();
    const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    const month = months[now.getMonth()] || 'Jan';
    const day = String(now.getDate()).padStart(2, '0');
    const hour = String(now.getHours()).padStart(2, '0');
    const minute = String(now.getMinutes()).padStart(2, '0');
    return `${month} ${day} ${hour}:${minute}`;
  };

  const renderNeofetch = () => `..............
            ..,;:ccc,.
          ......''';lxO.                         elite@banshee
.....''''..........,:ld;                         OS: Kali Linux
           .';;;:::;,,.x,                        Kernel: x86_64 Linux 6.12.0-kali-amd64
      ..'''.            0Xxoc:,.  ...            Uptime: 1d 2h 14m
  ....                ,ONkc;,;cokOdc',.          Packages: 5600
 .                   OMo           ':ddo.        Shell: zsh 5.9
                    dMc               :OO;       Resolution: 5120x1440
                    0M.                 .:o.     DE: KDE
                    ;Wd                          WM: KWin
                     ;XO,                        GTK Theme: Breeze-Dark [GTK2], Breeze [GTK3]
                       ,d0Odlc;,..               Icon Theme: Flat-Remix-Blue-Dark
                           ..',;:cdOOd::,.       Disk: 1.2T / 4.0T (30%)
                                    .:d;.':;.    CPU: AMD Ryzen Threadripper PRO 7995WX @ 96x 5.1GHz
                                       'd,  .'   GPU: NVIDIA GeForce RTX 4090
                                         ;l   .. RAM: 64GiB / 256GiB
                                          .o
                                            c
                                            .'
                                             .`;

  const escapeHTML = (value) =>
    value
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');

  const getLsEntryClass = (path, name, isDirEntry) => {
    if (isDirEntry || directories.has(path)) {
      return 'shell-entry shell-entry--dir';
    }
    const entry = files.get(path);
    if (entry?.type === 'binary' || entry?.type === 'script') {
      return 'shell-entry shell-entry--exec';
    }
    if (entry?.type === 'flag') {
      return 'shell-entry shell-entry--flag';
    }
    return 'shell-entry shell-entry--file';
  };

  const formatLsName = (path, name, isDirEntry) => {
    const cls = getLsEntryClass(path, name, isDirEntry);
    const hidden = name.startsWith('.') ? ' shell-entry--hidden' : '';
    return `<span class="${cls}${hidden}">${escapeHTML(name)}</span>`;
  };

  const getEntryMeta = (path, name, isDirEntry) => {
    const fileEntry = files.get(path);
    const isDirPath = isDirEntry || directories.has(path);
    const isRootPath = path.startsWith('/root');
    const owner = isRootPath ? 'root' : 'elite';
    const group = isRootPath ? 'root' : 'elite';
    let perms = '-rw-r--r--';
    let size = 0;

    if (isDirPath) {
      perms = isRootPath ? 'drwx------' : 'drwxr-xr-x';
      size = 4096;
    } else if (fileEntry?.type === 'binary') {
      perms = '-rwxr-xr-x';
      size = 13852;
    } else if (fileEntry?.type === 'script') {
      perms = '-rwxr-xr-x';
      size = (fileEntry.content || '').length;
    } else if (fileEntry?.type === 'flag') {
      perms = isRootPath ? '-rw-------' : '-rw-r--r--';
      size = 44;
    } else {
      perms = '-rw-r--r--';
      size = (fileEntry?.content || '').length;
    }

    return {
      name,
      perms,
      owner,
      group,
      size,
      date: formatLsDate(),
    };
  };

  const buildLsEntries = (dir, showAll) => {
    const entries = listDir(dir, showAll);
    const list = [];
    if (showAll) {
      list.push({ name: '.', path: dir, isDirEntry: true });
      const parent = getParentPath(dir) || '/';
      list.push({ name: '..', path: parent, isDirEntry: true });
    }
    entries.forEach((name) => {
      const path = dir === '/' ? `/${name}` : `${dir}/${name}`;
      list.push({ name, path, isDirEntry: directories.has(path) });
    });
    return list;
  };

  const renderLongList = (dir, showAll) => {
    const entries = buildLsEntries(dir, showAll);
    const lines = entries.map((entry) => {
      const meta = getEntryMeta(entry.path, entry.name, entry.isDirEntry);
      return `${meta.perms} 1 ${meta.owner} ${meta.group} ${meta.size} ${meta.date} ${meta.name}`;
    });
    const total = Math.max(1, entries.length);
    return [`total ${total}`, ...lines].join('\n');
  };

  const renderLongListMarkup = (dir, showAll) => {
    const entries = buildLsEntries(dir, showAll);
    const lines = entries.map((entry) => {
      const meta = getEntryMeta(entry.path, entry.name, entry.isDirEntry);
      const name = formatLsName(entry.path, entry.name, entry.isDirEntry);
      return `${meta.perms} 1 ${meta.owner} ${meta.group} ${meta.size} ${meta.date} ${name}`;
    });
    const total = Math.max(1, entries.length);
    return [`total ${total}`, ...lines].join('\n');
  };

  const renderShortListMarkup = (dir, showAll) => {
    const entries = buildLsEntries(dir, showAll);
    return entries.map((entry) => formatLsName(entry.path, entry.name, entry.isDirEntry)).join('  ');
  };

  const generateFlag = () => {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    const bytes = new Uint8Array(18);
    if (window.crypto && window.crypto.getRandomValues) {
      window.crypto.getRandomValues(bytes);
    } else {
      for (let i = 0; i < bytes.length; i += 1) {
        bytes[i] = Math.floor(Math.random() * 256);
      }
    }
    const token = Array.from(bytes, (byte) => chars[byte % chars.length]).join('');
    return `FLAG{${token}}`;
  };

  const splitPipeline = (raw) => {
    const segments = [];
    let current = '';
    let inSingle = false;
    let inDouble = false;

    for (let i = 0; i < raw.length; i += 1) {
      const char = raw[i];
      if (char === "'" && !inDouble) {
        inSingle = !inSingle;
      } else if (char === '"' && !inSingle) {
        inDouble = !inDouble;
      }

      if (char === '|' && !inSingle && !inDouble) {
        if (current.trim()) segments.push(current.trim());
        current = '';
        continue;
      }
      current += char;
    }

    if (current.trim()) segments.push(current.trim());
    return segments.length ? segments : [''];
  };

  const parseArgs = (raw) => {
    const args = [];
    const regex = /"([^"]*)"|'([^']*)'|\S+/g;
    let match = regex.exec(raw);
    while (match) {
      args.push(match[1] || match[2] || match[0]);
      match = regex.exec(raw);
    }
    return args;
  };

  const splitRedirection = (raw) => {
    let inSingle = false;
    let inDouble = false;
    for (let i = 0; i < raw.length; i += 1) {
      const char = raw[i];
      if (char === "'" && !inDouble) {
        inSingle = !inSingle;
        continue;
      }
      if (char === '"' && !inSingle) {
        inDouble = !inDouble;
        continue;
      }
      if (char === '>' && !inSingle && !inDouble) {
        const isAppend = raw[i + 1] === '>';
        const left = raw.slice(0, i).trim();
        const right = raw.slice(i + (isAppend ? 2 : 1)).trim();
        return {
          command: left,
          redirect: { target: right, append: isAppend },
        };
      }
    }
    return { command: raw.trim(), redirect: null };
  };

  const hashString = (value) => {
    let hash = 2166136261;
    for (let i = 0; i < value.length; i += 1) {
      hash ^= value.charCodeAt(i);
      hash = Math.imul(hash, 16777619);
    }
    return hash >>> 0;
  };

  const normalizeTarget = (value) => value.replace(/^https?:\/\//, '').replace(/\/.*$/, '');

  const toUrl = (value) => (value.startsWith('http') ? value : `https://${value}`);

  const pickItems = (items, seed, count) => {
    const pool = items.slice();
    const picks = [];
    let cursor = seed || 1;
    while (pool.length && picks.length < count) {
      const index = cursor % pool.length;
      picks.push(pool.splice(index, 1)[0]);
      cursor = (cursor * 1103515245 + 12345) >>> 0;
    }
    return picks;
  };

  const parseBansheeArgs = (args) => {
    const options = {
      mode: null,
      query: '',
      aiPrompt: '',
      randomFocus: '',
      monitor: '',
      pages: 1,
      delay: 1.5,
      workers: 5,
      engine: 'both',
      extensions: '',
      word: '',
      contents: '',
      exclusions: '',
      oosFile: '',
      recursive: false,
      subdomains: false,
      output: '',
      verbose: false,
      quantity: 10,
      simplify: false,
      model: '',
      multiLang: false,
      multiLangMultiplier: 25,
      smart: false,
      suggestions: false,
      noFollowup: false,
      maxFollowup: 5,
      correlation: false,
      maxCorrelation: 10,
      wafBypass: false,
      save: false,
      includeDates: false,
      learn: false,
      research: false,
      researchDepth: 1,
      techDetect: false,
      adaptive: false,
      deep: false,
      scoring: false,
      budget: false,
      proxy: '',
      insecure: false,
      dedupe: false,
      analyzeResponses: false,
      analyzeResponseOnly: false,
      analyzeDocs: false,
      filterDocs: false,
      inlineCodeAnalysis: false,
      analyzeCodeOnly: false,
      checkLeaks: false,
      keywords: '',
      foresee: false,
      wmc: '',
      noWaybackCache: false,
      autoCleanupCache: false,
      clearWaybackCache: false,
      monitorTime: 60,
      filterMon: false,
      analyzeMon: false,
      ignoreFile: '',
      flush: false,
      updateCveDb: false,
      cveYear: '',
      severity: '',
      cveResultsPerPage: '',
      aiDorkGeneration: false,
      nvdApiKey: '',
      viewIntel: '',
      exportIntel: '',
      interactive: false,
    };

    const modeSet = (mode) => {
      if (options.mode && options.mode !== mode) {
        return `banshee: choose a single mode (-q, -ai, -random, or --monitor)`;
      }
      options.mode = mode;
      return '';
    };

    for (let i = 0; i < args.length; i += 1) {
      const arg = args[i];
      switch (arg) {
        case '-h':
        case '--help':
          return { help: true, options };
        case '--version':
        case '-V':
          return { version: true, options };
        case '-q':
        case '--query': {
          const value = args[i + 1];
          if (!value) return { error: 'banshee: -q/--query requires a value' };
          const err = modeSet('query');
          if (err) return { error: err };
          options.query = value;
          i += 1;
          break;
        }
        case '-ai': {
          const value = args[i + 1];
          if (!value) return { error: 'banshee: -ai requires a prompt value' };
          const err = modeSet('ai');
          if (err) return { error: err };
          options.aiPrompt = value;
          i += 1;
          break;
        }
        case '-random':
        case '--random':
        case 'random': {
          const value = args[i + 1];
          const err = modeSet('random');
          if (err) return { error: err };
          if (value && !value.startsWith('-')) {
            options.randomFocus = value;
            i += 1;
          } else {
            options.randomFocus = 'any';
          }
          break;
        }
        case '-quantity':
        case '--quantity': {
          const value = parseInt(args[i + 1], 10);
          if (!Number.isNaN(value)) {
            options.quantity = value;
            i += 1;
          }
          break;
        }
        case '--ignore-file':
        case '-ignore-file': {
          const value = args[i + 1];
          if (!value) return { error: 'banshee: --ignore-file requires a value' };
          options.ignoreFile = value;
          i += 1;
          break;
        }
        case '--flush':
        case '-flush':
          options.flush = true;
          break;
        case '-simplify':
        case '--simplify':
          options.simplify = true;
          break;
        case '--model': {
          const value = args[i + 1];
          if (value) {
            options.model = value;
            i += 1;
          }
          break;
        }
        case '--multi-lang':
          options.multiLang = true;
          break;
        case '--multi-lang-multiplier': {
          const value = parseInt(args[i + 1], 10);
          if (!Number.isNaN(value)) {
            options.multiLangMultiplier = value;
            i += 1;
          }
          break;
        }
        case '--monitor': {
          const value = args[i + 1];
          if (!value) return { error: 'banshee: --monitor requires an intent string' };
          const err = modeSet('monitor');
          if (err) return { error: err };
          options.monitor = value;
          i += 1;
          break;
        }
        case '-p':
        case '--pages': {
          const value = parseInt(args[i + 1], 10);
          if (!Number.isNaN(value)) {
            options.pages = value;
            i += 1;
          }
          break;
        }
        case '-d':
        case '--delay': {
          const value = parseFloat(args[i + 1]);
          if (!Number.isNaN(value)) {
            options.delay = value;
            i += 1;
          }
          break;
        }
        case '--workers': {
          const value = parseInt(args[i + 1], 10);
          if (!Number.isNaN(value)) {
            options.workers = value;
            i += 1;
          }
          break;
        }
        case '-engine':
        case '--engine': {
          const value = args[i + 1];
          if (value) {
            options.engine = value;
            i += 1;
          }
          break;
        }
        case '-e':
        case '--extensions': {
          const value = args[i + 1];
          if (!value) return { error: 'banshee: -e/--extensions requires a value' };
          options.extensions = value;
          i += 1;
          break;
        }
        case '-w':
        case '--word': {
          const value = args[i + 1];
          if (!value) return { error: 'banshee: -w/--word requires a value' };
          options.word = value;
          i += 1;
          break;
        }
        case '-c':
        case '--contents': {
          const value = args[i + 1];
          if (!value) return { error: 'banshee: -c/--contents requires a value' };
          options.contents = value;
          i += 1;
          break;
        }
        case '-x':
        case '--exclusions': {
          const value = args[i + 1];
          if (!value) return { error: 'banshee: -x/--exclusions requires a value' };
          options.exclusions = value;
          i += 1;
          break;
        }
        case '--oos-file': {
          const value = args[i + 1];
          if (!value) return { error: 'banshee: --oos-file requires a value' };
          options.oosFile = value;
          i += 1;
          break;
        }
        case '-a':
        case '--recursive':
          options.recursive = true;
          break;
        case '-s':
        case '--subdomains':
          options.subdomains = true;
          break;
        case '-r':
        case '--proxy': {
          const value = args[i + 1];
          if (value) {
            options.proxy = value;
            i += 1;
          }
          break;
        }
        case '-insecure':
        case '--insecure':
          options.insecure = true;
          break;
        case '-o':
        case '--output': {
          const value = args[i + 1];
          if (value) {
            options.output = value;
            i += 1;
          }
          break;
        }
        case '-v':
        case '--verbose':
          options.verbose = true;
          break;
        case '--smart':
        case '-smart':
          options.smart = true;
          break;
        case '--suggestions':
          options.suggestions = true;
          break;
        case '--no-followup':
          options.noFollowup = true;
          break;
        case '--max-followup': {
          const value = parseInt(args[i + 1], 10);
          if (!Number.isNaN(value)) {
            options.maxFollowup = value;
            i += 1;
          }
          break;
        }
        case '-correlation':
          options.correlation = true;
          break;
        case '-max-correlation': {
          const value = parseInt(args[i + 1], 10);
          if (!Number.isNaN(value)) {
            options.maxCorrelation = value;
            i += 1;
          }
          break;
        }
        case '-waf-bypass':
          options.wafBypass = true;
          break;
        case '-save':
          options.save = true;
          break;
        case '-include-dates':
        case '--include-dates':
          options.includeDates = true;
          break;
        case '--learn':
        case '-learn':
          options.learn = true;
          break;
        case '-research':
        case '--research':
          options.research = true;
          break;
        case '-research-depth':
        case '--research-depth': {
          const value = parseInt(args[i + 1], 10);
          if (!Number.isNaN(value)) {
            options.researchDepth = value;
            i += 1;
          }
          break;
        }
        case '--tech-detect':
        case '-tech-detect':
          options.techDetect = true;
          break;
        case '-adaptive':
          options.adaptive = true;
          break;
        case '-deep':
          options.deep = true;
          break;
        case '-scoring':
          options.scoring = true;
          break;
        case '-budget':
          options.budget = true;
          break;
        case '--dedupe':
          options.dedupe = true;
          break;
        case '--analyze-responses':
          options.analyzeResponses = true;
          break;
        case '--analyze-response-only':
          options.analyzeResponseOnly = true;
          break;
        case '--analyze-docs':
          options.analyzeDocs = true;
          break;
        case '--filter-docs':
          options.filterDocs = true;
          break;
        case '--inline-code-analysis':
          options.inlineCodeAnalysis = true;
          break;
        case '--analyze-code-only':
          options.analyzeCodeOnly = true;
          break;
        case '-check-leaks':
        case '--check-leaks':
          options.checkLeaks = true;
          break;
        case '-keywords':
        case '--keywords': {
          const value = args[i + 1];
          if (value) {
            options.keywords = value;
            i += 1;
          }
          break;
        }
        case '--foresee':
          options.foresee = true;
          break;
        case '--no-wayback-cache':
          options.noWaybackCache = true;
          break;
        case '--auto-cleanup-cache':
          options.autoCleanupCache = true;
          break;
        case '--clear-wayback-cache':
          options.clearWaybackCache = true;
          break;
        case '--wmc': {
          const value = args[i + 1];
          if (value) {
            options.wmc = value;
            i += 1;
          }
          break;
        }
        case '--monitor-time': {
          const value = parseInt(args[i + 1], 10);
          if (!Number.isNaN(value)) {
            options.monitorTime = value;
            i += 1;
          }
          break;
        }
        case '--filter-mon':
          options.filterMon = true;
          break;
        case '--analyze-mon':
          options.analyzeMon = true;
          break;
        case '--update-cve-db':
          options.updateCveDb = true;
          break;
        case '--cve-year': {
          const value = args[i + 1];
          if (!value) return { error: 'banshee: --cve-year requires a value' };
          options.cveYear = value;
          i += 1;
          break;
        }
        case '--severity': {
          const value = args[i + 1];
          if (!value) return { error: 'banshee: --severity requires a value' };
          options.severity = value;
          i += 1;
          break;
        }
        case '--cve-results-per-page': {
          const value = parseInt(args[i + 1], 10);
          if (!Number.isNaN(value)) {
            options.cveResultsPerPage = value;
            i += 1;
          } else {
            return { error: 'banshee: --cve-results-per-page requires a numeric value' };
          }
          break;
        }
        case '--ai-dork-generation':
          options.aiDorkGeneration = true;
          break;
        case '--nvd-api-key': {
          const value = args[i + 1];
          if (!value) return { error: 'banshee: --nvd-api-key requires a value' };
          options.nvdApiKey = value;
          i += 1;
          break;
        }
        case '--view-intel': {
          const value = args[i + 1];
          if (!value) return { error: 'banshee: --view-intel requires a domain' };
          options.viewIntel = value;
          i += 1;
          break;
        }
        case '--export-intel': {
          const value = args[i + 1];
          if (!value) return { error: 'banshee: --export-intel requires a domain' };
          options.exportIntel = value;
          i += 1;
          break;
        }
        case '--interactive':
          options.interactive = true;
          break;
        default:
          break;
      }
    }

    return { options };
  };

  const buildDemoResults = (target, options) => {
    const seed = hashString(`${target}:${options.mode}:${options.query}:${options.aiPrompt}:${options.randomFocus}`);
    const pool = [
      { sub: 'admin', path: '/login', tag: '[PANEL]' },
      { sub: 'portal', path: '/auth/login', tag: '[AUTH]' },
      { sub: 'api', path: '/v1/status', tag: '[API]' },
      { sub: 'api', path: '/v2/users', tag: '[API]' },
      { sub: 'files', path: '/backup.zip', tag: '[EXPOSED]' },
      { sub: 'docs', path: '/finance/q2-report.pdf', tag: '[DOC]' },
      { sub: 'cdn', path: '/app/config.json', tag: '[CONFIG]' },
      { sub: '', path: '/.env', tag: '[SECRETS]' },
      { sub: 'grafana', path: '/', tag: '[DASHBOARD]' },
    ];
    const statuses = [200, 200, 302, 403, 401];
    const picks = pickItems(pool, seed, 3);
    return picks.map((item, index) => {
      const host = item.sub ? `${item.sub}.${target}` : target;
      const status = statuses[(seed + index) % statuses.length];
      return `${toUrl(`${host}${item.path}`)} | [${status}] ${item.tag}`;
    });
  };

  const buildUniversalResults = (query) => {
    const seed = hashString(query || 'banshee');
    const pool = [
      'https://s3.amazonaws.com/acme-backups/2024/finance.xlsx | [200] [CLOUD]',
      'https://storage.googleapis.com/acme-public/exports/users.csv | [200] [CLOUD]',
      'https://acme-archives.example.net/public/.env | [200] [SECRETS]',
      'https://cdn.acme.example.org/app/config.json | [200] [CONFIG]',
      'https://blob.core.windows.net/acme-data/backup.sql | [200] [CLOUD]',
    ];
    return pickItems(pool, seed, 3);
  };

  const buildIntelExportPayload = (target) => {
    const rootTarget = normalizeTarget(target).replace(/^www\./, '');
    const wwwTarget = rootTarget.startsWith('www.') ? rootTarget : `www.${rootTarget}`;
    const seed = hashString(rootTarget);
    const apiTemplates = [
      `https://${wwwTarget}/api/v1`,
      `https://${wwwTarget}/api/v2`,
      `https://${wwwTarget}/api/internal`,
      `https://${wwwTarget}/api/admin`,
      `https://${wwwTarget}/api/public`,
      `https://${wwwTarget}/api/v1-beta`,
      `https://${wwwTarget}/api/internal-v2`,
      `https://${wwwTarget}/api/admin-v2`,
      `https://${wwwTarget}/api/internal-tmp`,
      `https://${wwwTarget}/api/admin-temp`,
      `https://developer.${rootTarget}/apis/11538/versions/3.0.0/Order_Status_Push_API_3.0.0.json`,
    ];
    const apiEndpoints = pickItems(apiTemplates, seed, 10);

    const cloudAssets = pickItems(
      [
        'https://awsmedia.s3.amazonaws.com/pdf/RESTandS3.pdf',
        'https://aws-ml-blog.s3.amazonaws.com/artifacts/comprehend-realtime-endpoint/aws-service-offerings.txt',
        'https://media2store2.blob.core.windows.net/storage/item_spec/19/196108.pdf',
        'https://portalimages.blob.core.windows.net/products/pdfs/vonvfs1t_SBOX-2602.pdf',
        'https://doc.s3.amazonaws.com/betadesign/Versioning.html',
        'https://agfstorage.blob.core.windows.net/misc/FP_com/2021/09/13/Dell2.pdf',
      ],
      seed,
      6,
    );

    const discoveredPaths = pickItems(
      [
        '/',
        '/search-jobs',
        '/campaign/',
        '/dfo/cart.asp',
        '/dfo/order.asp',
        '/en/global-operations',
        '/en/sales-career-paths',
        '/en/software-engineering',
        '/en/summer-internship-experiences',
        '/en/pride-employee-resource-group',
      ],
      seed,
      8,
    );

    const payload = {
      api_endpoints: apiEndpoints,
      cloud_assets: cloudAssets,
      detected_cves: null,
      discovered_paths: discoveredPaths,
    };

    const markdown = [
      `# Banshee Intelligence: ${rootTarget}`,
      '',
      '## Summary',
      '- First scan: 2025-11-20',
      '- Last scan: 2026-01-08',
      '- Total scans: 159',
      '- Total dorks executed: 613 (50.7% success)',
      '',
      '## Key Stats',
      '- Subdomains: 0',
      '- Paths: 2025',
      '- API endpoints: 154',
      '- Cloud assets: 25',
      '- CVEs detected: 0',
      '',
      '## Insights',
      '- ⚠ Low result density - consider more targeted dorks',
      '- ✓ Moderate scanning effectiveness - 51% success rate',
      '- ✓ Highly API-driven architecture - 154 endpoints discovered',
      '- ⚠ Potentially sensitive files exposed - 4 file types',
      '- ✓ Cloud infrastructure detected - 25 cloud assets',
      '- ✓ Extensive directory structure - 2025 paths discovered',
      '',
      '## Recommendations',
      `- [CRITICAL] Test https://${wwwTarget}/api/internal-tmp for broken access control - may expose admin functions`,
      `- [CRITICAL] Test https://${wwwTarget}/api/internal-temp for broken access control - may expose admin functions`,
      `- [CRITICAL] Test https://${wwwTarget}/api/internal-prod for broken access control - may expose admin functions`,
      `- [CRITICAL] Test https://${wwwTarget}/api/internal-2 for broken access control - may expose admin functions`,
      `- [CRITICAL] Test https://${wwwTarget}/api/internal-v2 for broken access control - may expose admin functions`,
      `- [CRITICAL] Test https://${wwwTarget}/api/admin for broken access control - may expose admin functions`,
      `- [CRITICAL] Test https://${wwwTarget}/api/admin-tmp for broken access control - may expose admin functions`,
      `- [CRITICAL] Test https://${wwwTarget}/api/admin-temp for broken access control - may expose admin functions`,
      `- [CRITICAL] Test https://${wwwTarget}/api/admin-prod for broken access control - may expose admin functions`,
      `- [CRITICAL] Test https://${wwwTarget}/api/admin-2 for broken access control - may expose admin functions`,
      `- [CRITICAL] Test https://${wwwTarget}/api/admin-v2 for broken access control - may expose admin functions`,
      `- [CRITICAL] Attempt to access https://${rootTarget}/dfo/config.asp - may contain sensitive configuration data`,
      `- [CRITICAL] Attempt to access https://${rootTarget}/config - may contain sensitive configuration data`,
      '...',
    ].join('\n');

    return {
      json: JSON.stringify(payload, null, 2),
      markdown,
    };
  };

  const buildDorks = (target, options) => {
    if (options.mode === 'query') {
      return [
        `site:${target} ${options.query}`,
        `site:*.${target} ${options.query}`,
        `inurl:admin site:${target}`,
      ];
    }
    if (options.mode === 'ai') {
      return [
        `site:${target} "admin" ${options.aiPrompt.split(' ')[0] || ''}`.trim(),
        `site:${target} intitle:"login" ${options.aiPrompt.split(' ')[1] || ''}`.trim(),
        `site:*.${target} ${options.aiPrompt}`.trim(),
      ];
    }
    if (options.mode === 'random') {
      const focus = options.randomFocus || 'any';
      const focusMap = {
        sqli: ['inurl:php?id=', '"SQL syntax"'],
        xss: ['inurl:search?', '"<script>alert(1)</script>"'],
        redirect: ['inurl:redirect=', '"returnUrl="'],
        lfi: ['inurl:../../', '"root:x:0:0"'],
        rce: ['inurl:cmd=', '"uid=0(root)"'],
        idor: ['inurl:id=', '"userId"'],
        api: ['inurl:/api/v1', '"swagger"'],
        cloud: ['site:s3.amazonaws.com', 'site:storage.googleapis.com', 'site:blob.core.windows.net'],
      };
      const picks = focusMap[focus] || ['inurl:admin', 'intitle:login'];
      if (focus === 'cloud') {
        return picks.map((dork) => `${dork} "${target}"`);
      }
      return picks.map((dork) => `${dork} site:${target}`);
    }
    if (options.mode === 'monitor') {
      const intent = (options.monitor || '').trim() || 'documents';
      const words = intent.split(/[,\s]+/).filter(Boolean);
      const core = words.slice(0, 2).join(' ');
      return [
        `site:${target} ${core} filetype:pdf`,
        `site:${target} ${core} filetype:docx`,
        `site:${target} "${core}"`,
      ];
    }
    return [`site:${target} inurl:admin`];
  };

  const simulateBansheeRun = (targets, options, stdin) => {
    const lines = [];
    lines.push('[BANSHEE] Demo run started');
    lines.push('[INFO] Simulated output for the documentation shell.');

    if (options.clearWaybackCache) {
      lines.push('[FORESEE] Clearing Wayback cache (demo)');
      lines.push('Removed 42 cached entries (demo)');
      lines.push('[DONE] Cache cleared');
      return lines.join('\n');
    }

    if (options.updateCveDb) {
      lines.push('[CVE] Updating exploitable CVE database (demo)');
      if (options.cveYear) lines.push(`[CVE] Year filter: ${options.cveYear}`);
      if (options.severity) lines.push(`[CVE] Severity filter: ${options.severity}`);
      if (options.cveResultsPerPage) lines.push(`[CVE] Results per page: ${options.cveResultsPerPage}`);
      if (options.aiDorkGeneration) lines.push('[CVE] AI dork generation enabled (demo)');
      if (options.nvdApiKey) lines.push('[CVE] NVD API key provided (demo)');
      lines.push('[CVE] Downloaded 128 CVEs (demo)');
      lines.push('[DONE] CVE database updated (demo)');
      return lines.join('\n');
    }

    if (options.viewIntel) {
      lines.length = 0;
      const target = normalizeTarget(options.viewIntel) || options.viewIntel;
      const rootTarget = target.replace(/^www\./, '');
      const wwwTarget = target.startsWith('www.') ? target : `www.${rootTarget}`;
      lines.push('');
      lines.push('╔════════════════════════════════════════════════════════════════╗');
      lines.push('║           INTELLIGENCE DASHBOARD                               ║');
      lines.push('╚════════════════════════════════════════════════════════════════╝');
      lines.push('');
      lines.push(`▸ Target:           ${rootTarget}`);
      lines.push('▸ First Scan:       2025-11-20');
      lines.push('▸ Last Scan:        2026-01-08');
      lines.push('▸ Total Scans:      159');
      lines.push('');
      lines.push('╭─ Scanning Statistics ─────────────────────────────────────────╮');
      lines.push('│ Total Dorks Executed:    613');
      lines.push('│ Successful Dorks:        311 (50.7%)');
      lines.push('│ Failed Dorks:            302 (49.3%)');
      lines.push('│ Average Results/Dork:    0.1');
      lines.push('╰───────────────────────────────────────────────────────────────╯');
      lines.push('');
      lines.push('╭─ Best Dork Patterns ──────────────────────────────────────────╮');
      lines.push(`│ 1. site:${rootTarget} (inurl:controlpanel OR intit...      avg: 988 results`);
      lines.push(`│ 2. site:*.${rootTarget} -www                               avg: 150 results`);
      lines.push(`│ 3. site:${rootTarget} (intitle:"management console...      avg: 145 results`);
      lines.push(`│ 4. site:${rootTarget} (intitle:"Admin" OR inurl:ad...      avg: 119 results`);
      lines.push(`│ 5. site:${rootTarget} (intitle:"dashboard" OR inur...      avg: 112 results`);
      lines.push(`│ 6. site:${rootTarget} (inurl:login OR inurl:signin...      avg: 104 results`);
      lines.push(`│ 7. site:*.${rootTarget} (inurl:setup OR intitle:ma...      avg: 100 results`);
      lines.push(`│ 8. site:${rootTarget} (filetype:pdf (intext:"for i...      avg: 100 results`);
      lines.push(`│ 9. site:${rootTarget} (filetype:pdf (intext:confid...      avg: 100 results`);
      lines.push(`│ 10. site:${rootTarget} (inurl:/content/dam/ (filety...      avg: 100 results`);
      lines.push('╰───────────────────────────────────────────────────────────────╯');
      lines.push('');
      lines.push('╭─ Insights ────────────────────────────────────────────────────╮');
      lines.push('│ ⚠ Low result density - consider more targeted dorks');
      lines.push('│ ✓ Moderate scanning effectiveness - 51% success rate');
      lines.push('│ ✓ Highly API-driven architecture - 154 endpoints discovered');
      lines.push('│ ⚠ Potentially sensitive files exposed - 4 file types');
      lines.push('│ ✓ Cloud infrastructure detected - 25 cloud assets');
      lines.push('│ ✓ Extensive directory structure - 2025 paths discovered');
      lines.push('╰───────────────────────────────────────────────────────────────╯');
      lines.push('');
      lines.push('╭─ Recommendations ─────────────────────────────────────────────╮');
      lines.push(`│ ⚠ Test https://${wwwTarget}/api/internal-tmp for broken access control - may expose admin functions`);
      lines.push(`│ ⚠ Test https://${wwwTarget}/api/internal-temp for broken access control - may expose admin functions`);
      lines.push(`│ ⚠ Test https://${wwwTarget}/api/internal-prod for broken access control - may expose admin functions`);
      lines.push(`│ ⚠ Test https://${wwwTarget}/api/internal-2 for broken access control - may expose admin functions`);
      lines.push(`│ ⚠ Test https://${wwwTarget}/api/internal-v2 for broken access control - may expose admin functions`);
      lines.push(`│ ⚠ Test https://${wwwTarget}/api/admin for broken access control - may expose admin functions`);
      lines.push(`│ ⚠ Test https://${wwwTarget}/api/admin-tmp for broken access control - may expose admin functions`);
      lines.push(`│ ⚠ Test https://${wwwTarget}/api/admin-temp for broken access control - may expose admin functions`);
      lines.push(`│ ⚠ Test https://${wwwTarget}/api/admin-prod for broken access control - may expose admin functions`);
      lines.push(`│ ⚠ Test https://${wwwTarget}/api/admin-2 for broken access control - may expose admin functions`);
      lines.push(`│ ⚠ Test https://${wwwTarget}/api/admin-v2 for broken access control - may expose admin functions`);
      lines.push(`│ ⚠ Attempt to access https://${rootTarget}/dfo/config.asp - may contain sensitive configuration data`);
      lines.push(`│ ⚠ Attempt to access https://${rootTarget}/config - may contain sensitive configuration data`);
      lines.push('│ ⚠ Test https://aws-ml-blog.s3.amazonaws.com/artifacts/comprehend-realtime-endpoint/aws-service-offerings.txt for public bucket access and object enumeration');
      lines.push('│ ⚠ Test https://awsmedia.s3.amazonaws.com/pdf/RESTandS3.pdf for public bucket access and object enumeration');
      lines.push('│   ... and 91 more recommendations');
      lines.push('╰───────────────────────────────────────────────────────────────╯');
      return lines.join('\n');
    }

    if (options.exportIntel) {
      const target = normalizeTarget(options.exportIntel);
      const safeTarget = target.replace(/[^a-z0-9]+/gi, '_').replace(/^_+|_+$/g, '').toLowerCase();
      const jsonDefault = `${safeTarget}_intelligence.json`;
      const mdDefault = `${safeTarget}_intelligence_insights.md`;
      const jsonDisplay = options.output || jsonDefault;
      const jsonPath = resolvePath(jsonDisplay);
      const jsonDir = getParentPath(jsonPath) || state.cwd;
      const mdPath = normalizePath(`${jsonDir}/${mdDefault}`);
      const mdDisplay = jsonDir === state.cwd ? mdDefault : mdPath;
      const payload = buildIntelExportPayload(target);

      const jsonResult = writeFile(jsonPath, payload.json, false);
      if (jsonResult.error) return { error: jsonResult.error };
      const mdResult = writeFile(mdPath, payload.markdown, false);
      if (mdResult.error) return { error: mdResult.error };

      lines.length = 0;
      lines.push(`[✓] Intelligence exported to: ${jsonDisplay}`);
      lines.push(`[✓] Insights + recommendations (Markdown) exported to: ${mdDisplay}`);
      return lines.join('\n');
    }

    if (options.interactive) {
      lines.length = 0;
      lines.push('Good afternoon, elite | IP: 89.36.76.78 | Time: 14:53:35 | Session: SID-1615 | Status: READY');
      lines.push('');
      lines.push('╭─ Latest Cybersecurity News');
      lines.push('│  - Chrome/Edge emergency updates ship often—apply latest zero-day fixes quickly.');
      lines.push('│  - Ransomware targeting healthcare/municipal networks—patch VPN/edge appliances.');
      lines.push('│  - Microsoft Patch Tuesday: prioritize recent Exchange/Office/Windows critical RCEs.');
      lines.push('│  - Monitor OpenSSL/Apache/Nginx point releases for fresh CVE drops this week.');
      lines.push('╰───────────────────────────────────────────────────────────────────────────');
      lines.push('');
      lines.push('╭─ Quick Commands');
      lines.push('│  /execute    - Execute ANY Banshee feature (interactive prompt)');
      lines.push('│  /help       - Show all available commands with examples');
      lines.push('│  /ask        - Ask AI about Google dorking, Banshee, or OSINT techniques');
      lines.push('│  /smart      - Smart mode with AI: echo <domain> | banshee --smart -v');
      lines.push('│  /leaks      - Check paste sites: banshee -check-leaks <domain> -v');
      lines.push('│  /analyze    - Find & analyze docs: echo <domain> | banshee -ai "find sensitive docs" --analyze-docs');
      lines.push('│  /dork       - Custom dorks: banshee -q <query>');
      lines.push('│  /intel      - View learned intelligence for a target domain');
      lines.push('│  /exit       - Exit interactive mode');
      lines.push('│');
      lines.push('│  Talk to me: Find assets, search for leaks, generate dorks, ask questions, etc.');
      lines.push('│  Examples:');
      lines.push('│    • find leaked credentials for example.com');
      lines.push('│    • search for sensitive files on dell.com');
      lines.push('│    • how to find admin panels with google dorks?');
      lines.push('╰───────────────────────────────────────────────────────────────────────────');
      lines.push('');
      lines.push('What intel are you seeking, operator? ❯');
      lines.push('');
      lines.push('[INFO] This feature is available in the full Banshee binary.');
      return lines.join('\n');
    }

    if (options.proxy) lines.push(`[PROXY] ${options.proxy}`);
    if (options.insecure) lines.push('[TLS] Certificate verification disabled (demo)');
    if (Number.isFinite(options.delay)) lines.push(`[DELAY] ${options.delay}s between requests`);
    if (options.workers) lines.push(`[WORKERS] ${options.workers}`);
    lines.push(`[ENGINE] ${options.engine} | pages ${options.pages}`);

    if (options.oosFile) lines.push(`[OOS] Loaded patterns from ${options.oosFile} (demo)`);
    if (options.extensions) lines.push(`[FILTER] Extensions: ${options.extensions}`);
    if (options.word) lines.push(`[WORD] ${options.word}`);
    if (options.contents) lines.push(`[CONTENTS] ${options.contents}`);
    if (options.exclusions) lines.push(`[EXCLUDE] ${options.exclusions}`);
    if (options.subdomains) lines.push('[SUBDOMAINS] Enumeration enabled (demo)');
    if (options.recursive) lines.push('[CRAWL] Aggressive crawling enabled (demo)');
    if (options.ignoreFile) lines.push(`[IGNORE] Using ignore file ${options.ignoreFile} (demo)`);
    if (options.flush) lines.push('[RANDOM] Flush mode enabled (demo)');

    if (options.mode === 'query') {
      lines.push(`[MODE] Query: ${options.query}`);
    } else if (options.mode === 'ai') {
      lines.push(`[AI] Prompt: ${options.aiPrompt}`);
      lines.push(`[AI] Generated ${Math.min(3, options.quantity)} dorks (demo)`);
    } else if (options.mode === 'random') {
      lines.push(`[RANDOM] Focus: ${options.randomFocus || 'any'} | quantity ${options.quantity}`);
    } else if (options.mode === 'monitor') {
      lines.push(`[MONITOR] Intent: "${options.monitor}"`);
      if (options.monitorTime) lines.push(`[MONITOR] Interval: ${options.monitorTime} min`);
      if (options.filterMon) lines.push('[MONITOR] Dedupe + doc filter enabled (demo)');
      if (options.analyzeMon) lines.push('[MONITOR] Analysis enabled (demo)');
      lines.push('[MONITOR] Cycle 1/1 (demo)');
    }

    if (options.simplify) lines.push('[AI] Prompt simplification enabled (demo)');
    if (options.model) lines.push(`[AI] Model: ${options.model}`);
    if (options.multiLang) lines.push(`[LANG] Multi-language dorks (${options.multiLangMultiplier}%)`);
    if (options.research) lines.push(`[RESEARCH] Depth ${options.researchDepth} enabled (demo)`);
    if (options.learn) lines.push('[LEARN] Loaded intelligence cache (demo)');
    if (options.smart) {
      lines.push('[SMART] Follow-up dorks enabled (demo)');
      if (options.suggestions) lines.push('[SMART] Suggestions enabled (demo)');
      if (options.noFollowup) lines.push('[SMART] Follow-up disabled (demo)');
      if (options.maxFollowup && options.maxFollowup !== 5) {
        lines.push(`[SMART] Max follow-up dorks: ${options.maxFollowup}`);
      }
    }
    if (options.correlation) lines.push(`[CORRELATION] Enabled (max ${options.maxCorrelation})`);
    if (options.wafBypass) lines.push('[WAF] Bypass mode enabled (demo)');
    if (options.save) lines.push('[SAVE] Smart pagination enabled (demo)');
    if (options.includeDates) lines.push('[DATES] Date operators enabled (demo)');
    if (options.techDetect) lines.push('[TECH] Detecting tech stack (demo)');
    if (options.adaptive) lines.push('[RATE] Adaptive throttling enabled (demo)');
    if (options.deep) lines.push('[DISCOVERY] Deep subdomain discovery enabled (demo)');
    if (options.scoring) lines.push('[SCORING] AI-based scoring enabled (demo)');
    if (options.budget) lines.push('[BUDGET] Query budget optimization enabled (demo)');
    if (options.foresee) {
      lines.push('[FORESEE] Wayback intelligence enabled (demo)');
      if (options.wmc) lines.push(`[FORESEE] Status codes filter: ${options.wmc}`);
      if (options.noWaybackCache) lines.push('[FORESEE] Bypass cache enabled (demo)');
      if (options.autoCleanupCache) lines.push('[FORESEE] Auto cache cleanup enabled (demo)');
    }
    if (options.dedupe) lines.push('[DEDUPE] Deduplication enabled (demo)');
    if (options.inlineCodeAnalysis) lines.push('[INLINE-CODE] Inline JS analysis enabled (demo)');
    if (options.analyzeDocs) lines.push('[DOCS] Document analysis enabled (demo)');
    if (options.analyzeResponses) lines.push('[RESPONSES] Response analysis enabled (demo)');

    if (options.analyzeCodeOnly) {
      const payload = (stdin || '').trim();
      const lineCount = payload ? payload.split(/\r?\n/).length : 0;
      lines.push(`[stdin] Loaded ${lineCount} line(s) of code`);
      lines.push('[CODE-ANALYSIS] Analyzing stdin payload (demo)');
      lines.push('Findings: potential DOM XSS sink in untrusted input');
      lines.push('[DONE] Demo complete');
      return lines.join('\n');
    }

    if (!targets.length && options.mode === 'query') {
      lines.push('[stdin] No targets provided (unfiltered search)');
      lines.push(`[DORK] ${options.query}`);
      buildUniversalResults(options.query).forEach((result) => lines.push(result));
      if (options.output) {
        lines.push(`[OUTPUT] Results saved to ${options.output} (demo)`);
      }
      lines.push('[DONE] Demo complete');
      return lines.join('\n');
    }

    lines.push(`[stdin] Loaded ${targets.length} target(s)`);

    targets.forEach((raw) => {
      const target = normalizeTarget(raw);
      if (!target) return;
      lines.push(`[target] ${target}`);

      if (options.checkLeaks) {
        lines.push('[LEAKS] Searching paste sites (demo)');
        if (options.keywords) lines.push(`[LEAKS] Keywords: ${options.keywords}`);
        lines.push(`[LEAKS] Found 2 hits for ${target} (demo)`);
        lines.push(`https://pastebin.com/${target}-access-key | [LEAK] demo token`);
        lines.push(`https://rentry.co/${target}-backup | [LEAK] config snippet`);
        return;
      }

      if (options.analyzeResponseOnly) {
        const url = toUrl(raw);
        lines.push('[RESPONSE-ANALYSIS] Analyzing 1 URL');
        lines.push(
          `${url} | [RA] - Demo exposure: public API token in JS | Sensitive: API_KEY:DEMO_${target.toUpperCase()}`
        );
        return;
      }

      if (options.foresee) {
        lines.push(`[WAYBACK] ${target}: 12 historical URLs found (demo)`);
      }

      if (options.techDetect) {
        lines.push(`[TECH] ${target}: nginx, react, postgres (demo)`);
      }

      const dorks = buildDorks(target, options);
      dorks.forEach((dork) => lines.push(`[DORK] ${dork}`));

      const results = buildDemoResults(target, options);
      results.forEach((line) => lines.push(line));

      if (options.inlineCodeAnalysis) {
        lines.push(`${toUrl(`${target}/`)} | [INLINE-JS] Potential DOM XSS sink in search.js (demo)`);
      }

      if (options.analyzeDocs || options.analyzeMon) {
        lines.push('[DOCS] Found 2 documents (demo)');
        lines.push(`${toUrl(`docs.${target}/security/incident-response.pdf`)} | [DOC] Sensitive: internal contacts`);
        if (options.filterDocs || options.filterMon) {
          lines.push('[DOCS] Filtered 3 non-sensitive docs (demo)');
        }
      }

      if (options.analyzeResponses || options.analyzeMon) {
        lines.push('[RESPONSE-ANALYSIS] Analyzing responses (demo)');
        lines.push(`${toUrl(`${target}/api/config`)} | [RA] - Demo exposure: internal endpoint list`);
      }

      if (options.mode === 'monitor') {
        lines.push(`[MONITOR] ${target}: 6 new URLs (demo)`);
      }
    });

    if (options.output) {
      lines.push(`[OUTPUT] Results saved to ${options.output} (demo)`);
    }
    lines.push('[DONE] Demo complete');
    return lines.join('\n');
  };

  const runBanshee = (args, stdin) => {
    if (args.includes('help')) {
      return { stdout: bansheeHelp };
    }
    const parsed = parseBansheeArgs(args);
    if (parsed.help) return { stdout: bansheeHelp };
    if (parsed.version) return { stdout: 'Banshee demo v1.37.1' };
    if (parsed.error) return { error: parsed.error };
    if (!args.length) return { stdout: bansheeHelp };

    const targets = (stdin || '')
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean);

    const allowNoTargets =
      parsed.options.mode === 'query' ||
      parsed.options.updateCveDb ||
      parsed.options.clearWaybackCache ||
      parsed.options.viewIntel ||
      parsed.options.exportIntel ||
      parsed.options.interactive;

    if (!targets.length) {
      if (parsed.options.analyzeCodeOnly) {
        return { error: 'banshee: no stdin code detected. Try: cat script.js | banshee --analyze-code-only' };
      }
      if (parsed.options.analyzeResponseOnly) {
        return {
          error:
            'banshee: no stdin URLs detected. Try: echo "https://site.com" | banshee --analyze-response-only',
        };
      }
      if (!allowNoTargets) {
        return {
          error:
            'banshee: no stdin targets detected. Try: echo target.com | banshee -q "inurl:admin"',
        };
      }
    }

    return { stdout: simulateBansheeRun(targets, parsed.options, stdin) };
  };

  const runExploitScript = (path) => {
    const currentUser = state.user;
    const currentHost = state.host;
    const lines = [
      `[*] Enumerating sudo rules for ${currentUser}`,
      `Matching Defaults entries for ${currentUser} on ${currentHost}:`,
      '    env_reset, mail_badpass, secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
      `User ${currentUser} may run the following commands on ${currentHost}:`,
      '    (root) NOPASSWD: /home/elite/.exploit/main.sh',
      '    (root) NOPASSWD: /bin/bash',
      '[+] NOPASSWD /bin/bash found',
      '[*] Spawning root shell via sudo /bin/bash -p',
      'uid=0(root) gid=0(root) groups=0(root)',
      'root',
      '[+] Privilege escalation successful (demo)',
      'root shell granted (demo)',
    ];
    setRoot(false);
    return { stdout: lines.join('\n') };
  };

  const runExecutable = (path, args, stdin, label) => {
    const display = label || path;
    if (!isFile(path)) {
      return { error: `bash: ${display}: No such file or directory` };
    }
    const entry = files.get(path);
    if (entry?.type === 'binary') {
      if (path.endsWith('/banshee')) {
        return runBanshee(args, stdin);
      }
      return { error: `bash: ${display}: cannot execute binary file` };
    }
    if (entry?.type === 'script') {
      if (path === '/home/elite/.exploit/main.sh') {
        return runExploitScript(path);
      }
      return { stdout: entry?.content || '' };
    }
    return { error: `bash: ${display}: Permission denied` };
  };

  const runSegment = (segment, stdin, isPiped) => {
    const { command: commandPart, redirect } = splitRedirection(segment);
    const args = parseArgs(commandPart);
    const command = args.shift();
    if (!command) return {};

    const applyRedirect = (result) => {
      if (!redirect || result.clear) return result;
      if (result.error) return result;
      const targetTokens = parseArgs(redirect.target || '');
      const targetArg = targetTokens[0];
      if (!targetArg) {
        return { error: 'bash: syntax error near unexpected token `newline`' };
      }
      const resolved = resolvePath(targetArg);
      if (!state.isRoot && isRootOnlyPath(resolved)) {
        return { error: `bash: ${targetArg}: Permission denied` };
      }
      if (isDir(resolved)) {
        return { error: `bash: ${targetArg}: Is a directory` };
      }
      const output = result.stdout ?? '';
      const content = output && !output.endsWith('\n') ? `${output}\n` : output;
      const writeResult = writeFile(resolved, content, redirect.append);
      if (writeResult.error) return { error: writeResult.error };
      return { stdout: '', forceOutput: false };
    };

    if (command.startsWith('./') || command.startsWith('/') || command.startsWith('~/')) {
      const target = resolvePath(command);
      if (!state.isRoot && isRootOnlyPath(target)) {
        return applyRedirect({ error: `bash: ${command}: Permission denied` });
      }
      return applyRedirect(runExecutable(target, args, stdin, command));
    }

    switch (command) {
      case 'help':
        return applyRedirect({ stdout: shellHelp });
      case 'ls': {
        const flagArgs = args.filter((arg) => arg.startsWith('-'));
        const flagString = flagArgs.join('').replace(/-/g, '');
        const showAll = flagString.includes('a') || flagString.includes('A');
        const longList = flagString.includes('l');
        const targetArg = args.find((arg) => !arg.startsWith('-'));
        const target = targetArg ? resolvePath(targetArg) : state.cwd;
        if (isFile(target)) {
          const name = getBaseName(target);
          const markup = formatLsName(target, name, false);
          return applyRedirect({ stdout: name, stdoutMarkup: markup });
        }
        if (!isDir(target)) {
          return applyRedirect({ error: `ls: cannot access '${targetArg || ''}': No such file or directory` });
        }
        if (!state.isRoot && isRootOnlyPath(target)) {
          return applyRedirect({ error: `ls: cannot open directory '${target}': Permission denied` });
        }
        if (longList) {
          return applyRedirect({ stdout: renderLongList(target, showAll), stdoutMarkup: renderLongListMarkup(target, showAll) });
        }
        const entries = listDir(target, showAll);
        if (showAll) {
          return applyRedirect({
            stdout: ['.', '..', ...entries].join('  '),
            stdoutMarkup: renderShortListMarkup(target, true),
          });
        }
        return applyRedirect({
          stdout: entries.join('  '),
          stdoutMarkup: renderShortListMarkup(target, false),
        });
      }
      case 'pwd':
        return applyRedirect({ stdout: state.cwd });
      case 'whoami':
        return applyRedirect({ stdout: state.user });
      case 'id':
        if (state.isRoot) {
          return applyRedirect({ stdout: 'uid=0(root) gid=0(root) groups=0(root)' });
        }
        return applyRedirect({ stdout: 'uid=1000(elite) gid=1000(elite) groups=1000(elite)' });
      case 'neofetch':
        return applyRedirect({ stdout: renderNeofetch() });
      case 'history':
        if (!history.length) return applyRedirect({ stdout: '' });
        return applyRedirect({
          stdout: history.map((entry, index) => ` ${index + 1}  ${entry}`).join('\n'),
        });
      case 'date':
        return applyRedirect({ stdout: new Date().toString() });
      case 'uname':
        return applyRedirect({ stdout: `Linux ${state.host} 6.8.0-banshee #1 SMP` });
      case 'bash':
      case 'sh': {
        if (!args.length) {
          return applyRedirect({ stdout: 'bash: interactive shells are disabled in demo mode' });
        }
        const target = resolvePath(args[0]);
        if (!state.isRoot && isRootOnlyPath(target)) {
          return applyRedirect({ error: `bash: ${args[0]}: Permission denied` });
        }
        return applyRedirect(runExecutable(target, args.slice(1), stdin, args[0]));
      }
      case 'sudo': {
        if (!args.length) return applyRedirect({ error: 'sudo: no command specified' });
        if (args.includes('-l') || args.includes('--list')) {
          return applyRedirect({ stdout: renderSudoList() });
        }
        if (state.isRoot) {
          return applyRedirect({ stdout: 'root already has full privileges (demo)' });
        }

        const wantsShell = args[0] === '-s' || args[0] === '-i';
        if (wantsShell) {
          setRoot(args[0] === '-i');
          return applyRedirect({ stdout: 'root shell granted (demo)' });
        }

        const commandArg = args[0];
        const resolved = resolvePath(commandArg);
        if (commandArg === 'bash') {
          if (!sudoAllow.has('/bin/bash')) {
            return applyRedirect({ error: 'sudo: bash: command not permitted (demo)' });
          }
          setRoot(false);
          return applyRedirect({ stdout: 'root shell granted (demo)' });
        }
        if (resolved === '/bin/bash') {
          setRoot(false);
          return applyRedirect({ stdout: 'root shell granted (demo)' });
        }
        if (resolved === '/home/elite/.exploit/main.sh' && sudoAllow.has(resolved) && files.has(resolved)) {
          setRoot(false);
          return applyRedirect({
            stdout:
              '[*] Running /home/elite/.exploit/main.sh (demo)\n[+] Privilege escalation successful (demo)\nroot shell granted (demo)',
          });
        }
        return applyRedirect({ error: `sudo: ${commandArg}: command not permitted (demo)` });
      }
      case 'exit':
        if (state.isRoot) {
          dropRoot();
          return applyRedirect({ stdout: 'logout' });
        }
        return applyRedirect({ error: 'exit: command not found' });
      case 'cd': {
        const target = resolvePath(args[0] || '~');
        if (!isDir(target)) {
          return applyRedirect({ error: `cd: ${args[0] || ''}: No such file or directory` });
        }
        if (!state.isRoot && isRootOnlyPath(target)) {
          return applyRedirect({ error: `cd: ${target}: Permission denied` });
        }
        state.cwd = target;
        updatePrompt();
        return applyRedirect({});
      }
      case 'echo': {
        const hasEscapes = args[0] === '-e';
        const textArgs = hasEscapes ? args.slice(1) : args;
        let text = textArgs.join(' ');
        if (hasEscapes) {
          text = text.replace(/\\n/g, '\n').replace(/\\t/g, '\t');
        }
        return applyRedirect({ stdout: text, forceOutput: true });
      }
      case 'cat': {
        if (!args.length && stdin) {
          return applyRedirect({ stdout: stdin, forceOutput: true });
        }
        if (!args.length) {
          return applyRedirect({ error: 'cat: missing file operand' });
        }
        const outputs = [];
        for (const arg of args) {
          if (arg === '-') {
            outputs.push(stdin);
            continue;
          }
          const target = resolvePath(arg);
          if (!isFile(target)) {
            return applyRedirect({ error: `cat: ${arg}: No such file or directory` });
          }
          if (!state.isRoot && isRootOnlyPath(target)) {
            return applyRedirect({ error: `cat: ${arg}: Permission denied` });
          }
          const entry = files.get(target);
          if (entry?.type === 'flag') {
            outputs.push(generateFlag());
            continue;
          }
          if (entry?.type === 'binary') {
            return applyRedirect({ error: `cat: ${arg}: binary file` });
          }
          outputs.push(entry?.content || '');
        }
        return applyRedirect({ stdout: outputs.join('\n'), forceOutput: true });
      }
      case 'touch': {
        if (!args.length) return applyRedirect({ error: 'touch: missing file operand' });
        const errors = [];
        args.forEach((arg) => {
          if (arg.startsWith('-')) return;
          const target = resolvePath(arg);
          if (!state.isRoot && isRootOnlyPath(target)) {
            errors.push(`touch: cannot touch '${arg}': Permission denied`);
            return;
          }
          const result = createFile(target);
          if (result.error) errors.push(result.error);
        });
        if (errors.length) return applyRedirect({ error: errors.join('\n') });
        return applyRedirect({});
      }
      case 'mkdir': {
        if (!args.length) return applyRedirect({ error: 'mkdir: missing operand' });
        const recursive = args.includes('-p');
        const errors = [];
        args.forEach((arg) => {
          if (arg.startsWith('-')) return;
          const target = resolvePath(arg);
          if (!state.isRoot && isRootOnlyPath(target)) {
            errors.push(`mkdir: cannot create directory '${arg}': Permission denied`);
            return;
          }
          const result = createDir(target, recursive);
          if (result.error) errors.push(result.error);
        });
        if (errors.length) return applyRedirect({ error: errors.join('\n') });
        return applyRedirect({});
      }
      case 'rmdir': {
        if (!args.length) return applyRedirect({ error: 'rmdir: missing operand' });
        const errors = [];
        args.forEach((arg) => {
          if (arg.startsWith('-')) return;
          const target = resolvePath(arg);
          if (!state.isRoot && isRootOnlyPath(target)) {
            errors.push(`rmdir: failed to remove '${arg}': Permission denied`);
            return;
          }
          const result = removeDir(target);
          if (result.error) errors.push(result.error);
        });
        if (errors.length) return applyRedirect({ error: errors.join('\n') });
        return applyRedirect({});
      }
      case 'rm': {
        if (!args.length) return applyRedirect({ error: 'rm: missing operand' });
        const errors = [];
        args.forEach((arg) => {
          if (arg.startsWith('-')) return;
          const target = resolvePath(arg);
          if (isDir(target)) {
            errors.push(`rm: cannot remove '${arg}': Is a directory`);
            return;
          }
          if (!state.isRoot && isRootOnlyPath(target)) {
            errors.push(`rm: cannot remove '${arg}': Permission denied`);
            return;
          }
          const result = removeFile(target);
          if (result.error) errors.push(result.error);
        });
        if (errors.length) return applyRedirect({ error: errors.join('\n') });
        return applyRedirect({});
      }
      case 'clear':
        return { clear: true };
      case 'banshee':
        return applyRedirect(runBanshee(args, stdin));
      default:
        if (isPiped) {
          return applyRedirect({ error: `shell: cannot pipe from '${command}' (demo shell)` });
        }
        return applyRedirect({ error: `${command}: command not found` });
    }
  };

  const runPipeline = (segments) => {
    const lines = [];
    let stdin = '';
    let clear = false;

    for (let i = 0; i < segments.length; i += 1) {
      const isLast = i === segments.length - 1;
      const result = runSegment(segments[i], stdin, !isLast);
      if (result.clear) {
        clear = true;
        lines.length = 0;
      }
      if (result.error) {
        lines.push({ text: result.error, className: 'shell-error' });
        return { lines, clear };
      }
      stdin = result.stdout ?? '';
      if (isLast && (result.stdout !== undefined || result.stdoutMarkup !== undefined)) {
        const outputText = result.stdoutMarkup ?? result.stdout ?? '';
        if (outputText !== '' || result.forceOutput) {
          lines.push({
            text: outputText,
            className: result.className,
            isMarkup: result.stdoutMarkup !== undefined,
          });
        }
      }
    }

    return { lines, clear };
  };

  const handleCommand = (raw) => {
    const trimmed = raw.trim();
    appendCommandLine(trimmed);
    if (!trimmed) {
      scrollToBottom();
      return;
    }

    const segments = splitPipeline(trimmed);
    const result = runPipeline(segments);
    if (result.clear) {
      output.innerHTML = '';
    }
    result.lines.forEach((line) => appendOutput(line.text, line.className, line.isMarkup));
    scrollToBottom();
  };

  input.addEventListener('keydown', (event) => {
    if (event.key === 'Enter') {
      event.preventDefault();
      const value = input.value;
      if (value.trim()) {
        history.push(value);
        historyIndex = history.length;
      }
      handleCommand(value);
      input.value = '';
      return;
    }

    if (event.key === 'ArrowUp') {
      if (!history.length) return;
      historyIndex = Math.max(0, historyIndex - 1);
      input.value = history[historyIndex] || '';
      event.preventDefault();
    }

    if (event.key === 'ArrowDown') {
      if (!history.length) return;
      historyIndex = Math.min(history.length, historyIndex + 1);
      input.value = history[historyIndex] || '';
      event.preventDefault();
    }
  });

  shell.addEventListener('click', () => {
    input.focus();
  });

  updatePrompt();
};

const initDock = () => {
  if (!dock || (!dockToggle && !dockShow)) return;
  const storageKey = 'bansheeDockHidden';

  const setDockHidden = (hidden) => {
    document.body.classList.toggle('dock-hidden', hidden);
    dock.setAttribute('aria-hidden', hidden ? 'true' : 'false');
    if (dockToggle) {
      dockToggle.setAttribute('aria-expanded', hidden ? 'false' : 'true');
    }
    if (dockShow) {
      dockShow.setAttribute('aria-expanded', hidden ? 'false' : 'true');
    }
  };

  const stored = window.localStorage.getItem(storageKey);
  const initialHidden = stored === 'true';
  setDockHidden(initialHidden);

  dockToggle?.addEventListener('click', () => {
    setDockHidden(true);
    window.localStorage.setItem(storageKey, 'true');
  });

  dockShow?.addEventListener('click', () => {
    setDockHidden(false);
    window.localStorage.setItem(storageKey, 'false');
  });
};

const init = () => {
  updateProgress();
  initScrollSpy();
  initReveal();
  initCounters();
  initTabs();
  initCopyButtons();
  initFilter();
  initFlagDetails();
  initScrollTop();
  initExampleTabs();
  initParticles();
  initShell();
  initDock();
  window.addEventListener('scroll', updateProgress, { passive: true });
};

init();
