package cve

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/Vulnpire/Banshee-AI/internal/app/console"
	"github.com/Vulnpire/Banshee-AI/internal/app/core"
)

// CVEEntry represents a comprehensive CVE database entry
type CVEEntry struct {
	CVEID           string   // CVE identifier
	Technology      string   // Affected technology
	VersionPattern  string   // Regex pattern for vulnerable versions
	Severity        string   // critical, high, medium, low
	CVSS            float64  // CVSS score
	HasPublicExploit bool    // From GHDB/Exploit-DB
	ExploitType     string   // RCE, SQLi, XSS, LFI, SSRF, Auth Bypass, etc.
	Description     string   // Brief description
	Dorks           []string // GHDB-style Google dorks for finding vulnerable instances
	VersionDorks    []string // Dorks for version detection
	Keywords        []string // Keywords to look for in responses
}

// IndustryVulnPattern represents industry-specific vulnerability patterns
type IndustryVulnPattern struct {
	Industry     string   // healthcare, finance, saas, ecommerce, government
	VulnCategory string   // PII leak, PCI-DSS violation, HIPAA violation, etc.
	Severity     string   // critical, high, medium, low
	Description  string   // What this pattern looks for
	Dorks        []string // Google dorks for this pattern
	Compliance   []string // Affected compliance frameworks
	FalsePositiveRate float64 // 0.0-1.0, lower is better
}

// CVEDatabase contains comprehensive CVE entries with public exploits
var CVEDatabase = []CVEEntry{
	// ==================== WEB SERVERS ====================
	{
		CVEID:           "CVE-2021-41773",
		Technology:      "Apache HTTP Server",
		VersionPattern:  `2\.4\.(49|50)`,
		Severity:        "critical",
		CVSS:            9.8,
		HasPublicExploit: true,
		ExploitType:     "Path Traversal + RCE",
		Description:     "Apache 2.4.49/2.4.50 path traversal and RCE vulnerability",
		Dorks: []string{
			`intext:"Apache/2.4.49" OR intext:"Apache/2.4.50"`,
			`intitle:"Index of" "Apache/2.4.49"`,
			`inurl:cgi-bin/.%%32e/.%%32e`,
		},
		VersionDorks: []string{
			`intext:"Apache/2.4" intitle:"Apache HTTP Server Test Page"`,
			`intitle:"Test Page for the Apache HTTP Server"`,
		},
		Keywords: []string{"Apache/2.4.49", "Apache/2.4.50"},
	},
	{
		CVEID:           "CVE-2020-1938",
		Technology:      "Apache Tomcat",
		VersionPattern:  `[6-9]\.[0-9]\.[0-9]+`,
		Severity:        "critical",
		CVSS:            9.8,
		HasPublicExploit: true,
		ExploitType:     "File Read + RCE (Ghostcat)",
		Description:     "Apache Tomcat AJP File Read/Inclusion vulnerability (Ghostcat)",
		Dorks: []string{
			`inurl:8009 "Apache Tomcat"`,
			`inurl:8080 intitle:"Apache Tomcat"`,
			`inurl:8080/manager/html`,
			`inurl:8080/manager/status`,
			`filetype:xml intext:"<Context" intext:"Tomcat"`,
		},
		VersionDorks: []string{
			`intext:"Apache Tomcat/6" OR intext:"Apache Tomcat/7" OR intext:"Apache Tomcat/8" OR intext:"Apache Tomcat/9"`,
			`intitle:"Apache Tomcat" inurl:8080`,
		},
		Keywords: []string{"Apache Tomcat/6", "Apache Tomcat/7", "Apache Tomcat/8", "Apache Tomcat/9", "AJP"},
	},
	{
		CVEID:           "CVE-2017-5638",
		Technology:      "Apache Struts",
		VersionPattern:  `2\.[0-3]\.[0-9]+|2\.5\.[0-9]|2\.5\.1[0-2]`,
		Severity:        "critical",
		CVSS:            10.0,
		HasPublicExploit: true,
		ExploitType:     "Remote Code Execution",
		Description:     "Apache Struts2 Jakarta Multipart parser RCE",
		Dorks: []string{
			`inurl:.action`,
			`filetype:action`,
			`inurl:struts inurl:.action`,
			`intext:"Struts Problem Report"`,
			`inurl:showcase.action`,
		},
		VersionDorks: []string{
			`intext:"Powered by Struts"`,
			`intext:"Struts" intitle:"Welcome"`,
		},
		Keywords: []string{"Struts", ".action", "struts2"},
	},

	// ==================== CMS PLATFORMS ====================
	{
		CVEID:           "CVE-2019-16223",
		Technology:      "WordPress",
		VersionPattern:  `[1-4]\.[0-9]\.[0-9]+|5\.[0-2]\.[0-9]+`,
		Severity:        "high",
		CVSS:            7.5,
		HasPublicExploit: true,
		ExploitType:     "User Enumeration + Auth Bypass",
		Description:     "WordPress REST API user enumeration vulnerability",
		Dorks: []string{
			`inurl:wp-json/wp/v2/users`,
			`inurl:/wp-json/wp/v2/users?per_page=100`,
			`inurl:?author=1`,
			`inurl:wp-content/uploads filetype:sql`,
			`inurl:wp-config.php.bak OR inurl:wp-config.bak`,
			`filetype:sql intext:"wp_users" intext:"INSERT INTO"`,
		},
		VersionDorks: []string{
			`inurl:wp-includes/version.php`,
			`intext:"WordPress" intitle:"readme"`,
			`inurl:/readme.html "WordPress"`,
		},
		Keywords: []string{"WordPress", "wp-json", "wp_users"},
	},
	{
		CVEID:           "CVE-2018-7600",
		Technology:      "Drupal",
		VersionPattern:  `7\.x|8\.[0-5]\.x`,
		Severity:        "critical",
		CVSS:            9.8,
		HasPublicExploit: true,
		ExploitType:     "Remote Code Execution (Drupalgeddon2)",
		Description:     "Drupal < 7.58, < 8.5.1 RCE vulnerability",
		Dorks: []string{
			`inurl:user/register`,
			`inurl:?q=user/password`,
			`inurl:CHANGELOG.txt "Drupal"`,
			`intext:"Powered by Drupal"`,
			`inurl:sites/default/files`,
		},
		VersionDorks: []string{
			`inurl:CHANGELOG.txt "Drupal 7" OR "Drupal 8"`,
			`intext:"Drupal" intitle:"Welcome"`,
		},
		Keywords: []string{"Drupal", "Drupal 7", "Drupal 8"},
	},
	{
		CVEID:           "CVE-2015-8562",
		Technology:      "Joomla",
		VersionPattern:  `3\.[0-4]\.[0-9]+`,
		Severity:        "critical",
		CVSS:            9.8,
		HasPublicExploit: true,
		ExploitType:     "Remote Code Execution",
		Description:     "Joomla 3.0-3.4.5 RCE vulnerability",
		Dorks: []string{
			`inurl:administrator/index.php`,
			`inurl:administrator/components/com_`,
			`intext:"Joomla!" intitle:"Administration"`,
			`inurl:configuration.php.bak`,
		},
		VersionDorks: []string{
			`inurl:/administrator/ intext:"Joomla"`,
			`intext:"Joomla!" "Version"`,
		},
		Keywords: []string{"Joomla", "Joomla!"},
	},

	// ==================== FILE UPLOAD & INCLUSION ====================
	{
		CVEID:           "CVE-2021-3129",
		Technology:      "Laravel",
		VersionPattern:  `[1-7]\.[0-9]\.[0-9]+|8\.0\.[0-9]+`,
		Severity:        "critical",
		CVSS:            9.8,
		HasPublicExploit: true,
		ExploitType:     "Remote Code Execution",
		Description:     "Laravel <= 8.4.2 RCE via Ignition",
		Dorks: []string{
			`inurl:_ignition/execute-solution`,
			`inurl:telescope`,
			`inurl:horizon/dashboard`,
			`filetype:env intext:APP_KEY intext:DB_PASSWORD`,
			`inurl:storage/logs`,
		},
		VersionDorks: []string{
			`intext:"Laravel" intitle:"Application"`,
			`inurl:public/storage`,
		},
		Keywords: []string{"Laravel", "Ignition", "_ignition"},
	},
	{
		CVEID:           "CVE-2018-19518",
		Technology:      "PHP",
		VersionPattern:  `[5-7]\.[0-9]\.[0-9]+`,
		Severity:        "high",
		CVSS:            7.5,
		HasPublicExploit: true,
		ExploitType:     "File Upload + RCE",
		Description:     "PHP imap_open RCE vulnerability",
		Dorks: []string{
			`inurl:upload.php`,
			`inurl:fileupload.php`,
			`intitle:"File Upload"`,
			`inurl:"/upload/" filetype:php`,
		},
		VersionDorks: []string{
			`intext:"PHP Version" intitle:"phpinfo()"`,
			`intitle:"phpinfo()" intext:"System"`,
		},
		Keywords: []string{"PHP", "phpinfo"},
	},

	// ==================== AUTHENTICATION BYPASS ====================
	{
		CVEID:           "CVE-2022-0540",
		Technology:      "Atlassian Jira",
		VersionPattern:  `[1-8]\.[0-9]+\.[0-9]+`,
		Severity:        "critical",
		CVSS:            9.8,
		HasPublicExploit: true,
		ExploitType:     "Authentication Bypass",
		Description:     "Jira Seraph authentication bypass",
		Dorks: []string{
			`inurl:"/jira/" intitle:"Log in"`,
			`inurl:secure/Dashboard.jspa`,
			`inurl:/rest/api/2/serverInfo`,
			`intext:"JIRA" intitle:"System Dashboard"`,
		},
		VersionDorks: []string{
			`inurl:/rest/api/2/serverInfo`,
			`intext:"Atlassian Jira" intitle:"Login"`,
		},
		Keywords: []string{"Jira", "Atlassian"},
	},
	{
		CVEID:           "CVE-2021-26855",
		Technology:      "Microsoft Exchange",
		VersionPattern:  `201[3-9]|202[0-1]`,
		Severity:        "critical",
		CVSS:            9.8,
		HasPublicExploit: true,
		ExploitType:     "SSRF + RCE (ProxyLogon)",
		Description:     "Microsoft Exchange Server SSRF vulnerability (ProxyLogon chain)",
		Dorks: []string{
			`inurl:/owa/auth/logon.aspx`,
			`inurl:/ecp/ intitle:"Outlook"`,
			`intext:"Outlook Web App"`,
			`inurl:"/autodiscover/autodiscover.json"`,
		},
		VersionDorks: []string{
			`inurl:/owa/ intext:"Outlook Web App"`,
			`inurl:/ecp/ intitle:"Exchange"`,
		},
		Keywords: []string{"Exchange Server", "Outlook Web App", "OWA"},
	},

	// ==================== SQL INJECTION ====================
	{
		CVEID:           "CVE-2021-20090",
		Technology:      "Buffalo routers",
		VersionPattern:  `.*`,
		Severity:        "critical",
		CVSS:            9.8,
		HasPublicExploit: true,
		ExploitType:     "Path Traversal + Command Injection",
		Description:     "Buffalo WSR series router command injection",
		Dorks: []string{
			`intext:"Buffalo" inurl:"/login.html"`,
			`intitle:"AirStation" "Buffalo"`,
			`inurl:cgi-bin/luci`,
		},
		VersionDorks: []string{
			`intext:"Buffalo Inc." intitle:"Web Control"`,
		},
		Keywords: []string{"Buffalo", "AirStation"},
	},

	// ==================== XXE / XML EXTERNAL ENTITY ====================
	{
		CVEID:           "CVE-2021-40438",
		Technology:      "Apache HTTP Server",
		VersionPattern:  `2\.4\.(4[8-9]|5[0-1])`,
		Severity:        "critical",
		CVSS:            9.0,
		HasPublicExploit: true,
		ExploitType:     "SSRF + Proxy",
		Description:     "Apache mod_proxy SSRF vulnerability",
		Dorks: []string{
			`intitle:"Apache" "It works!"`,
			`intext:"Apache" intitle:"Test Page"`,
		},
		VersionDorks: []string{
			`intext:"Apache/2.4" intitle:"Apache"`,
		},
		Keywords: []string{"Apache/2.4.48", "Apache/2.4.49", "Apache/2.4.50", "Apache/2.4.51"},
	},

	// ==================== DESERIALIZATION ====================
	{
		CVEID:           "CVE-2020-14882",
		Technology:      "Oracle WebLogic",
		VersionPattern:  `1[0-4]\.[0-9]\.[0-9]+`,
		Severity:        "critical",
		CVSS:            9.8,
		HasPublicExploit: true,
		ExploitType:     "Remote Code Execution",
		Description:     "Oracle WebLogic Console RCE",
		Dorks: []string{
			`inurl:/console/login/LoginForm.jsp`,
			`intitle:"Oracle WebLogic Server Administration Console"`,
			`inurl:"/console/jsp/"`,
		},
		VersionDorks: []string{
			`intitle:"WebLogic" "Console"`,
			`inurl:/console/ intext:"WebLogic"`,
		},
		Keywords: []string{"WebLogic", "Oracle WebLogic"},
	},

	// ==================== LOG4J ====================
	{
		CVEID:           "CVE-2021-44228",
		Technology:      "Log4j",
		VersionPattern:  `2\.[0-9]+\.[0-9]+`,
		Severity:        "critical",
		CVSS:            10.0,
		HasPublicExploit: true,
		ExploitType:     "Remote Code Execution (Log4Shell)",
		Description:     "Apache Log4j2 JNDI RCE vulnerability",
		Dorks: []string{
			`inurl:/solr/admin/`,
			`intitle:"Solr Admin"`,
			`inurl:/api/swagger`,
			`inurl:/actuator/health`,
			`intext:"Spring Boot" inurl:/actuator`,
		},
		VersionDorks: []string{
			`intext:"Apache Solr" intitle:"Admin"`,
			`inurl:/actuator/info`,
		},
		Keywords: []string{"Apache Solr", "Spring Boot", "log4j"},
	},

	// ==================== KUBERNETES / CONTAINERS ====================
	{
		CVEID:           "CVE-2018-1002105",
		Technology:      "Kubernetes",
		VersionPattern:  `1\.[0-9]+\.[0-9]+`,
		Severity:        "critical",
		CVSS:            9.8,
		HasPublicExploit: true,
		ExploitType:     "Privilege Escalation",
		Description:     "Kubernetes privilege escalation vulnerability",
		Dorks: []string{
			`inurl:"/api/v1/namespaces/kube-system"`,
			`inurl:8080/api/v1`,
			`inurl:10250/pods`,
			`inurl:"/dashboard/" intitle:"Kubernetes"`,
			`intext:"Kubernetes Dashboard"`,
		},
		VersionDorks: []string{
			`inurl:/api/v1 intext:"kubernetes"`,
			`intitle:"Kubernetes Dashboard"`,
		},
		Keywords: []string{"Kubernetes", "k8s"},
	},

	// ==================== GRAPHQL ====================
	{
		CVEID:           "CVE-2021-41277",
		Technology:      "Metabase",
		VersionPattern:  `0\.[0-9]+\.[0-9]+`,
		Severity:        "critical",
		CVSS:            9.8,
		HasPublicExploit: true,
		ExploitType:     "Remote Code Execution",
		Description:     "Metabase GeoJSON RCE",
		Dorks: []string{
			`inurl:/api/session/properties`,
			`intitle:"Metabase"`,
			`inurl:/app/admin`,
		},
		VersionDorks: []string{
			`intext:"Metabase" intitle:"Admin"`,
		},
		Keywords: []string{"Metabase"},
	},

	// ==================== MONGODB ====================
	{
		CVEID:           "CVE-2020-7598",
		Technology:      "MongoDB",
		VersionPattern:  `[2-4]\.[0-9]\.[0-9]+`,
		Severity:        "high",
		CVSS:            7.5,
		HasPublicExploit: true,
		ExploitType:     "NoSQL Injection",
		Description:     "MongoDB Express unauthenticated access",
		Dorks: []string{
			`inurl:27017`,
			`intitle:"Home - Mongo Express"`,
			`inurl:"/db/" intitle:"Mongo Express"`,
		},
		VersionDorks: []string{
			`intitle:"Mongo Express"`,
		},
		Keywords: []string{"MongoDB", "Mongo Express"},
	},

	// ==================== ELASTICSEARCH ====================
	{
		CVEID:           "CVE-2021-22145",
		Technology:      "Elasticsearch",
		VersionPattern:  `[1-7]\.[0-9]+\.[0-9]+`,
		Severity:        "high",
		CVSS:            7.5,
		HasPublicExploit: true,
		ExploitType:     "Information Disclosure",
		Description:     "Elasticsearch unauthenticated access",
		Dorks: []string{
			`inurl:9200/_cat/indices`,
			`inurl:9200/_cluster/health`,
			`inurl:9200/_search`,
			`intitle:"Elastic"`,
		},
		VersionDorks: []string{
			`inurl:9200/ intext:"elasticsearch"`,
			`inurl:9200/_cluster/health`,
		},
		Keywords: []string{"Elasticsearch", "elastic"},
	},

	// ==================== JENKINS ====================
	{
		CVEID:           "CVE-2019-1003000",
		Technology:      "Jenkins",
		VersionPattern:  `[1-2]\.[0-9]+`,
		Severity:        "critical",
		CVSS:            9.8,
		HasPublicExploit: true,
		ExploitType:     "Remote Code Execution",
		Description:     "Jenkins Script Security sandbox bypass",
		Dorks: []string{
			`inurl:"/jenkins/login"`,
			`intitle:"Dashboard [Jenkins]"`,
			`inurl:"/asynchPeople/"`,
			`inurl:"/securityRealm/"`,
		},
		VersionDorks: []string{
			`intitle:"Jenkins" "Dashboard"`,
			`inurl:/jenkins/ intitle:"Jenkins"`,
		},
		Keywords: []string{"Jenkins"},
	},

	// ==================== GRAFANA ====================
	{
		CVEID:           "CVE-2021-43798",
		Technology:      "Grafana",
		VersionPattern:  `[7-8]\.[0-9]\.[0-9]+`,
		Severity:        "high",
		CVSS:            7.5,
		HasPublicExploit: true,
		ExploitType:     "Path Traversal + File Read",
		Description:     "Grafana directory traversal vulnerability",
		Dorks: []string{
			`inurl:3000/login intitle:"Grafana"`,
			`inurl:/grafana/login`,
			`inurl:"/public/plugins/"`,
			`intitle:"Grafana" -login`,
		},
		VersionDorks: []string{
			`intitle:"Grafana" inurl:/login`,
			`inurl:/api/health`,
		},
		Keywords: []string{"Grafana"},
	},

	// ==================== REDIS ====================
	{
		CVEID:           "CVE-2022-0543",
		Technology:      "Redis",
		VersionPattern:  `[2-6]\.[0-9]\.[0-9]+`,
		Severity:        "critical",
		CVSS:            10.0,
		HasPublicExploit: true,
		ExploitType:     "Remote Code Execution",
		Description:     "Redis Lua sandbox escape RCE",
		Dorks: []string{
			`inurl:6379`,
			`intitle:"Redis Commander"`,
		},
		VersionDorks: []string{
			`intext:"Redis" intitle:"Commander"`,
		},
		Keywords: []string{"Redis"},
	},

	// ==================== GITLAB ====================
	{
		CVEID:           "CVE-2021-22205",
		Technology:      "GitLab",
		VersionPattern:  `1[1-3]\.[0-9]\.[0-9]+`,
		Severity:        "critical",
		CVSS:            10.0,
		HasPublicExploit: true,
		ExploitType:     "Remote Code Execution",
		Description:     "GitLab ExifTool RCE vulnerability",
		Dorks: []string{
			`inurl:"/users/sign_in" intitle:"GitLab"`,
			`inurl:"/explore" intitle:"GitLab"`,
			`inurl:"/api/v4/version"`,
		},
		VersionDorks: []string{
			`intitle:"GitLab" "Sign in"`,
			`inurl:/api/v4/version`,
		},
		Keywords: []string{"GitLab"},
	},

	// ==================== CONFLUENCE ====================
	{
		CVEID:           "CVE-2022-26134",
		Technology:      "Atlassian Confluence",
		VersionPattern:  `[1-7]\.[0-9]+\.[0-9]+`,
		Severity:        "critical",
		CVSS:            9.8,
		HasPublicExploit: true,
		ExploitType:     "Remote Code Execution (OGNL Injection)",
		Description:     "Confluence OGNL injection RCE",
		Dorks: []string{
			`inurl:"/login.action" intitle:"Confluence"`,
			`inurl:"/dashboard.action"`,
			`intitle:"Atlassian Confluence"`,
		},
		VersionDorks: []string{
			`intitle:"Confluence" inurl:/login.action`,
		},
		Keywords: []string{"Confluence", "Atlassian"},
	},

	// ==================== FORTINET ====================
	{
		CVEID:           "CVE-2018-13379",
		Technology:      "Fortinet FortiOS",
		VersionPattern:  `[4-6]\.[0-9]\.[0-9]+`,
		Severity:        "critical",
		CVSS:            9.8,
		HasPublicExploit: true,
		ExploitType:     "Path Traversal + Credential Disclosure",
		Description:     "FortiOS SSL VPN path traversal",
		Dorks: []string{
			`inurl:"/remote/login"`,
			`intitle:"FortiGate" "SSL-VPN"`,
			`intext:"Please enter your username and password" "FortiGate"`,
		},
		VersionDorks: []string{
			`intitle:"FortiGate" inurl:/remote/login`,
		},
		Keywords: []string{"FortiGate", "FortiOS"},
	},

	// ==================== SONICWALL ====================
	{
		CVEID:           "CVE-2021-20016",
		Technology:      "SonicWall",
		VersionPattern:  `.*`,
		Severity:        "critical",
		CVSS:            9.8,
		HasPublicExploit: true,
		ExploitType:     "SQL Injection",
		Description:     "SonicWall SSLVPN SQL injection",
		Dorks: []string{
			`inurl:"/cgi-bin/jarrewrite.sh"`,
			`intitle:"SonicWall" "SSL-VPN"`,
		},
		VersionDorks: []string{
			`intitle:"SonicWall" "SSL"`,
		},
		Keywords: []string{"SonicWall"},
	},

	// ==================== VMWARE ====================
	{
		CVEID:           "CVE-2021-21972",
		Technology:      "VMware vCenter",
		VersionPattern:  `[6-7]\.[0-9]`,
		Severity:        "critical",
		CVSS:            9.8,
		HasPublicExploit: true,
		ExploitType:     "Remote Code Execution",
		Description:     "VMware vCenter plugin upload RCE",
		Dorks: []string{
			`inurl:"/ui/" intitle:"vSphere"`,
			`inurl:"/ui/login" "VMware vCenter"`,
			`intext:"vCenter Server" intitle:"Login"`,
		},
		VersionDorks: []string{
			`intitle:"vSphere" inurl:/ui/`,
		},
		Keywords: []string{"vCenter", "vSphere", "VMware"},
	},

	// ==================== CITRIX ====================
	{
		CVEID:           "CVE-2019-19781",
		Technology:      "Citrix ADC",
		VersionPattern:  `1[0-3]\.[0-9]`,
		Severity:        "critical",
		CVSS:            9.8,
		HasPublicExploit: true,
		ExploitType:     "Path Traversal + RCE",
		Description:     "Citrix ADC/Gateway path traversal RCE",
		Dorks: []string{
			`inurl:"/vpn/index.html"`,
			`intitle:"Citrix Gateway"`,
			`inurl:"/vpns/portal/"`,
		},
		VersionDorks: []string{
			`intitle:"Citrix" "Gateway"`,
		},
		Keywords: []string{"Citrix", "NetScaler"},
	},

	// ==================== PULSE SECURE ====================
	{
		CVEID:           "CVE-2019-11510",
		Technology:      "Pulse Secure VPN",
		VersionPattern:  `[8-9]\.[0-9]`,
		Severity:        "critical",
		CVSS:            10.0,
		HasPublicExploit: true,
		ExploitType:     "Path Traversal + Credential Disclosure",
		Description:     "Pulse Secure VPN path traversal",
		Dorks: []string{
			`inurl:"/dana-na/"`,
			`intitle:"Pulse Secure"`,
		},
		VersionDorks: []string{
			`intitle:"Pulse Secure" inurl:/dana-na/`,
		},
		Keywords: []string{"Pulse Secure"},
	},

	// ==================== CISCO ====================
	{
		CVEID:           "CVE-2020-3452",
		Technology:      "Cisco ASA",
		VersionPattern:  `9\.[0-9]+`,
		Severity:        "high",
		CVSS:            7.5,
		HasPublicExploit: true,
		ExploitType:     "Path Traversal + File Read",
		Description:     "Cisco ASA/FTD path traversal",
		Dorks: []string{
			`inurl:"+CSCOE+" "webvpn"`,
			`intitle:"Cisco" "SSL VPN"`,
		},
		VersionDorks: []string{
			`intext:"Cisco" "ASA" intitle:"Login"`,
		},
		Keywords: []string{"Cisco ASA", "webvpn"},
	},
}

// Industry-specific vulnerability patterns
var IndustryVulnPatterns = []IndustryVulnPattern{
	// ==================== HEALTHCARE (HIPAA) ====================
	{
		Industry:     "healthcare",
		VulnCategory: "HIPAA - Protected Health Information (PHI) Exposure",
		Severity:     "critical",
		Description:  "Exposed patient records, medical data, diagnoses",
		Dorks: []string{
			`filetype:xls OR filetype:xlsx (intext:patient OR intext:medical OR intext:diagnosis) (intext:DOB OR intext:SSN)`,
			`filetype:csv (intext:"patient name" OR intext:"patient id") intext:"date of birth"`,
			`intext:"patient portal" inurl:login`,
			`inurl:ehr OR inurl:emr inurl:admin`,
			`intext:"Epic" OR intext:"Cerner" OR intext:"Allscripts" inurl:login`,
			`filetype:pdf (intext:"patient" OR intext:"medical record") (intext:"confidential" OR intext:"private")`,
			`inurl:patient inurl:?id=`,
			`intext:"prescription" filetype:xls OR filetype:csv`,
			`intext:"insurance" AND intext:"patient" AND (intext:"SSN" OR intext:"social security")`,
			`inurl:fhir/Patient`,
		},
		Compliance:   []string{"HIPAA", "HITECH"},
		FalsePositiveRate: 0.15,
	},
	{
		Industry:     "healthcare",
		VulnCategory: "Medical Device Web Interface Exposure",
		Severity:     "high",
		Description:  "Exposed medical device management interfaces",
		Dorks: []string{
			`intext:"Philips" inurl:"/radiology/" OR inurl:"/cardiology/"`,
			`intext:"GE Healthcare" inurl:admin`,
			`intext:"Siemens" intext:"Medical" intitle:"Login"`,
			`inurl:pacs inurl:admin`,
			`intext:"Picture Archiving" inurl:login`,
		},
		Compliance:   []string{"HIPAA", "FDA"},
		FalsePositiveRate: 0.10,
	},

	// ==================== FINANCE (PCI-DSS) ====================
	{
		Industry:     "finance",
		VulnCategory: "PCI-DSS - Payment Card Data Exposure",
		Severity:     "critical",
		Description:  "Exposed credit card numbers, CVV, payment data",
		Dorks: []string{
			`filetype:xls OR filetype:xlsx (intext:"card number" OR intext:"credit card") (intext:CVV OR intext:expir)`,
			`filetype:csv intext:"card" AND intext:"cvv" AND intext:"exp"`,
			`intext:"4111" OR intext:"4532" OR intext:"5425" filetype:xls`,
			`intext:"stripe_key" OR intext:"stripe_secret" filetype:env`,
			`intext:"payment" AND intext:"card" filetype:sql`,
			`inurl:checkout inurl:?card=`,
			`intext:"merchant" AND intext:"transaction" AND intext:"card" filetype:log`,
			`inurl:payment/process inurl:debug=true`,
		},
		Compliance:   []string{"PCI-DSS", "PA-DSS"},
		FalsePositiveRate: 0.20,
	},
	{
		Industry:     "finance",
		VulnCategory: "Banking Credentials and Account Exposure",
		Severity:     "critical",
		Description:  "Exposed bank account numbers, routing numbers, financial credentials",
		Dorks: []string{
			`filetype:xls OR filetype:xlsx (intext:"account number" OR intext:"routing number") intext:bank`,
			`intext:"ACH" AND (intext:"routing" OR intext:"account") filetype:csv`,
			`intext:"SWIFT" OR intext:"IBAN" filetype:xls`,
			`inurl:"/banking/" inurl:?account=`,
			`intext:"online banking" inurl:admin`,
			`filetype:sql intext:"account_balance" OR intext:"transaction"`,
		},
		Compliance:   []string{"PCI-DSS", "SOX", "GLBA"},
		FalsePositiveRate: 0.18,
	},
	{
		Industry:     "finance",
		VulnCategory: "Financial API Exposure",
		Severity:     "high",
		Description:  "Exposed Stripe, Plaid, PayPal API keys and endpoints",
		Dorks: []string{
			`intext:"sk_live_" OR intext:"pk_live_" filetype:env`,
			`intext:"stripe" AND intext:"secret" filetype:js`,
			`intext:"PLAID_SECRET" OR intext:"PLAID_CLIENT_ID"`,
			`intext:"paypal" AND intext:"secret" filetype:env`,
			`inurl:/api/payment inurl:swagger`,
			`inurl:/api/v1/transactions`,
		},
		Compliance:   []string{"PCI-DSS"},
		FalsePositiveRate: 0.12,
	},

	// ==================== SAAS ====================
	{
		Industry:     "saas",
		VulnCategory: "Cloud Infrastructure Exposure",
		Severity:     "critical",
		Description:  "Exposed Kubernetes, Grafana, Prometheus, admin dashboards",
		Dorks: []string{
			`inurl:"/grafana/" -login`,
			`inurl:9090/graph intitle:"Prometheus"`,
			`inurl:8080/dashboard intitle:"Kubernetes"`,
			`inurl:"/metrics" intext:"# HELP"`,
			`inurl:"/healthz" intext:"ok"`,
			`inurl:"/actuator/env" intext:"applicationConfig"`,
			`inurl:"/actuator/health" intext:"UP"`,
			`intitle:"Kubernetes Dashboard"`,
			`inurl:argocd inurl:login`,
			`intitle:"Rancher" inurl:login`,
		},
		Compliance:   []string{"SOC 2", "ISO 27001"},
		FalsePositiveRate: 0.08,
	},
	{
		Industry:     "saas",
		VulnCategory: "API Key and Secrets Exposure",
		Severity:     "critical",
		Description:  "Exposed AWS keys, database credentials, API tokens in public repos or URLs",
		Dorks: []string{
			`filetype:env intext:"AWS_ACCESS_KEY_ID" intext:"AWS_SECRET_ACCESS_KEY"`,
			`intext:"AKIA" filetype:env OR filetype:txt`,
			`intext:"-----BEGIN RSA PRIVATE KEY-----" filetype:key`,
			`intext:"mongodb://" intext:"@" filetype:env`,
			`intext:"mysql://" OR intext:"postgres://" filetype:env`,
			`intext:"DATABASE_URL" filetype:env`,
			`intext:"TWILIO_" OR intext:"SENDGRID_" filetype:env`,
			`intext:"GOOGLE_API_KEY" OR intext:"MAPS_API_KEY"`,
			`intext:"secret_key" OR intext:"api_secret" filetype:yml`,
		},
		Compliance:   []string{"SOC 2", "ISO 27001"},
		FalsePositiveRate: 0.10,
	},
	{
		Industry:     "saas",
		VulnCategory: "Database Exposure",
		Severity:     "critical",
		Description:  "Publicly accessible databases, database dumps, backups",
		Dorks: []string{
			`filetype:sql intext:"INSERT INTO" intext:"users"`,
			`filetype:sql intext:"CREATE TABLE" intext:"password"`,
			`inurl:"/backup/" filetype:sql`,
			`intext:"phpMyAdmin" intitle:"Welcome to phpMyAdmin"`,
			`inurl:9200 intext:"elastic"`,
			`inurl:27017 intext:"mongodb"`,
			`inurl:6379 intext:"redis"`,
			`inurl:5432 intext:"postgresql"`,
		},
		Compliance:   []string{"SOC 2", "GDPR"},
		FalsePositiveRate: 0.12,
	},

	// ==================== E-COMMERCE ====================
	{
		Industry:     "ecommerce",
		VulnCategory: "Customer Database Exposure",
		Severity:     "critical",
		Description:  "Exposed customer lists, order data, payment information",
		Dorks: []string{
			`filetype:csv (intext:"email" OR intext:"customer") (intext:"order" OR intext:"purchase")`,
			`filetype:xls (intext:"customer name" OR intext:"customer email") intext:"total"`,
			`inurl:"/admin/customers" OR inurl:"/admin/orders"`,
			`intext:"Shopify" inurl:admin`,
			`intext:"Magento" inurl:admin`,
			`intext:"WooCommerce" inurl:wp-admin`,
			`filetype:sql intext:"customer" AND intext:"orders" AND intext:"CREATE TABLE"`,
		},
		Compliance:   []string{"PCI-DSS", "GDPR"},
		FalsePositiveRate: 0.15,
	},
	{
		Industry:     "ecommerce",
		VulnCategory: "Admin Panel Default Credentials",
		Severity:     "high",
		Description:  "E-commerce admin panels with default or weak authentication",
		Dorks: []string{
			`inurl:"/admin" OR inurl:"/administrator" intext:"login"`,
			`inurl:"/backend/" intext:"admin"`,
			`inurl:"/manager/" intext:"login"`,
			`intext:"admin/admin" OR intext:"admin:admin"`,
			`inurl:"/wp-admin/" intitle:"Log In"`,
		},
		Compliance:   []string{"PCI-DSS"},
		FalsePositiveRate: 0.25,
	},
	{
		Industry:     "ecommerce",
		VulnCategory: "Abandoned Cart and Checkout Data",
		Severity:     "medium",
		Description:  "Exposed shopping cart data, abandoned checkouts with customer info",
		Dorks: []string{
			`inurl:"/checkout/" inurl:?`,
			`inurl:"/cart/" inurl:?email=`,
			`intext:"abandoned cart" filetype:csv`,
			`inurl:"/api/cart" inurl:?id=`,
		},
		Compliance:   []string{"GDPR", "CCPA"},
		FalsePositiveRate: 0.30,
	},

	// ==================== GOVERNMENT ====================
	{
		Industry:     "government",
		VulnCategory: "Citizen PII and Sensitive Government Data",
		Severity:     "critical",
		Description:  "Exposed citizen data, SSNs, classified documents",
		Dorks: []string{
			`site:gov filetype:pdf (intext:"social security" OR intext:SSN) (intext:"confidential" OR intext:"classified")`,
			`site:gov filetype:xls OR filetype:xlsx intext:"SSN" OR intext:"social security number"`,
			`site:gov filetype:doc OR filetype:docx intext:"classified" OR intext:"secret"`,
			`site:gov inurl:admin OR inurl:administrator`,
			`site:gov intext:"For Official Use Only" filetype:pdf`,
			`site:gov intext:"voter" OR intext:"election" filetype:xls`,
		},
		Compliance:   []string{"FISMA", "FedRAMP"},
		FalsePositiveRate: 0.20,
	},
	{
		Industry:     "government",
		VulnCategory: "FOIA and Internal Documents",
		Severity:     "medium",
		Description:  "Exposed FOIA requests, internal memos, communications",
		Dorks: []string{
			`site:gov filetype:pdf intext:"FOIA"`,
			`site:gov intext:"internal use only" filetype:pdf OR filetype:doc`,
			`site:gov intext:"memo" OR intext:"memorandum" (intext:"confidential" OR intext:"internal")`,
			`site:gov inurl:foia`,
		},
		Compliance:   []string{"FOIA"},
		FalsePositiveRate: 0.35,
	},
	{
		Industry:     "government",
		VulnCategory: "Government System Access",
		Severity:     "high",
		Description:  "Exposed government portals, authentication systems",
		Dorks: []string{
			`site:gov inurl:login intitle:"secure"`,
			`site:gov inurl:portal intitle:"employee"`,
			`site:gov intext:"Active Directory" inurl:login`,
		},
		Compliance:   []string{"FISMA", "NIST"},
		FalsePositiveRate: 0.18,
	},

	// ==================== EDUCATION ====================
	{
		Industry:     "education",
		VulnCategory: "Student Records and FERPA Violations",
		Severity:     "critical",
		Description:  "Exposed student records, grades, transcripts, SSNs",
		Dorks: []string{
			`site:edu filetype:xls OR filetype:xlsx (intext:"student" OR intext:"grade") intext:SSN`,
			`site:edu filetype:pdf intext:"transcript" (intext:"confidential" OR intext:"official")`,
			`site:edu inurl:sis OR inurl:student-portal`,
			`site:edu intext:"student id" AND intext:"grade" filetype:csv`,
		},
		Compliance:   []string{"FERPA"},
		FalsePositiveRate: 0.12,
	},

	// ==================== GENERAL - EXPOSED BACKUPS ====================
	{
		Industry:     "general",
		VulnCategory: "Exposed Backup Files and Archives",
		Severity:     "high",
		Description:  "Publicly accessible backup files, database dumps, archives",
		Dorks: []string{
			`inurl:"/backup/" OR inurl:"/backups/" OR inurl:"/bak/"`,
			`filetype:bak OR filetype:old OR filetype:backup`,
			`filetype:sql intext:"CREATE TABLE"`,
			`filetype:zip OR filetype:tar OR filetype:gz inurl:backup`,
			`inurl:.git/config`,
			`inurl:.env`,
			`filetype:log intext:"password" OR intext:"username"`,
		},
		Compliance:   []string{"General Security"},
		FalsePositiveRate: 0.25,
	},

	// ==================== GENERAL - EXPOSED CREDENTIALS ====================
	{
		Industry:     "general",
		VulnCategory: "Exposed Credentials in Source Code",
		Severity:     "critical",
		Description:  "Hardcoded credentials in publicly accessible source files",
		Dorks: []string{
			`filetype:js intext:"password" OR intext:"passwd" OR intext:"pwd"`,
			`filetype:php intext:"$password =" OR intext:"$pwd ="`,
			`filetype:py intext:"password = " OR intext:"PASSWORD ="`,
			`filetype:java intext:"password=" OR intext:"passwd="`,
			`filetype:config intext:"password"`,
			`intext:"admin" AND intext:"password" filetype:txt`,
		},
		Compliance:   []string{"General Security"},
		FalsePositiveRate: 0.35,
	},

	// ==================== GENERAL - DIRECTORY LISTINGS ====================
	{
		Industry:     "general",
		VulnCategory: "Open Directory Listings",
		Severity:     "medium",
		Description:  "Directory listings exposing sensitive files and folder structures",
		Dorks: []string{
			`intitle:"Index of /" OR intitle:"Directory Listing"`,
			`intitle:"Index of" inurl:admin`,
			`intitle:"Index of" inurl:backup`,
			`intitle:"Index of" (inurl:uploads OR inurl:files)`,
			`intitle:"Index of /" intext:"Parent Directory"`,
		},
		Compliance:   []string{"General Security"},
		FalsePositiveRate: 0.40,
	},
}

// detectTechnologyVersion uses AI to detect technology versions from discovered data
func (c *Config) detectTechnologyVersion(ctx context.Context, tech string, evidence []string) string {
	if len(evidence) == 0 {
		return ""
	}

	console.Logv(c.Verbose, "[CVE-VERSION] Detecting %s version using AI...", tech)

	evidenceStr := strings.Join(evidence, "\n")

	systemPrompt := fmt.Sprintf(`You are a technology version detection expert. Analyze the following evidence to determine the exact version of %s.

EVIDENCE:
%s

YOUR TASK:
1. Look for version numbers in HTTP headers, HTML meta tags, JavaScript comments, error messages
2. Extract the exact version number (e.g., "2.4.49", "8.5.23", "5.2.1")
3. If you find multiple version indicators, choose the most specific one
4. If no exact version found, provide the major version (e.g., "7.x", "2.4.x")

OUTPUT FORMAT:
Return ONLY the version number, nothing else. Examples:
- 2.4.49
- 8.5.23
- 7.x
- unknown

If you cannot determine any version information, return "unknown".`, tech, evidenceStr)

	userPrompt := fmt.Sprintf("What is the exact version of %s based on the evidence?", tech)

	output, err := c.callGeminiCLI(ctx, systemPrompt, userPrompt)
	if err != nil {
		console.Logv(c.Verbose, "[CVE-VERSION] AI version detection failed: %v", err)
		return ""
	}

	version := strings.TrimSpace(output)
	version = strings.TrimPrefix(version, "Version: ")
	version = strings.TrimPrefix(version, "v")

	if version != "unknown" && version != "" {
		console.Logv(c.Verbose, "[CVE-VERSION] Detected %s version: %s", tech, version)
	}

	return version
}

// matchCVEsByTechnology finds CVEs matching detected technologies and versions
func matchCVEsByTechnology(tech, version string) []CVEEntry {
	var matches []CVEEntry

	techLower := strings.ToLower(tech)

	// Use merged database (built-in + custom)
	database := getCVEDatabase()

	// Improve version detection (handle Ubuntu/Debian packages)
	if version != "" {
		version = improveVersionDetection(version)
	}

	for _, cve := range database {
		cveTechLower := strings.ToLower(cve.Technology)

		// Check if technology matches
		if strings.Contains(cveTechLower, techLower) || strings.Contains(techLower, cveTechLower) {
			// If we have a version, check if it matches the vulnerable version pattern
			if version != "" && version != "unknown" {
				if cve.VersionPattern != "" {
					matched, err := regexp.MatchString(cve.VersionPattern, version)
					if err != nil {
						// Log malformed regex pattern but continue
						// This prevents CVE database issues from breaking the scan
						continue
					}
					if matched {
						matches = append(matches, cve)
					}
				} else {
					// No version pattern, include anyway
					matches = append(matches, cve)
				}
			} else {
				// No version info, include all CVEs for this tech
				matches = append(matches, cve)
			}
		}
	}

	return matches
}

// getIndustryVulnPatterns returns vulnerability patterns for a specific industry
func getIndustryVulnPatterns(industry string) []IndustryVulnPattern {
	var patterns []IndustryVulnPattern

	industryLower := strings.ToLower(industry)

	for _, pattern := range IndustryVulnPatterns {
		if strings.ToLower(pattern.Industry) == industryLower {
			patterns = append(patterns, pattern)
		}
	}

	// Also include general patterns
	for _, pattern := range IndustryVulnPatterns {
		if pattern.Industry == "general" {
			patterns = append(patterns, pattern)
		}
	}

	return patterns
}

// generateCVEDorks generates comprehensive dorks for detected CVEs
func (c *Config) generateCVEDorks(cves []CVEEntry) []string {
	var allDorks []string

	for _, cve := range cves {
		console.Logv(c.Verbose, "[CVE-DORK] %s - %s (%s, CVSS: %.1f)", cve.CVEID, cve.Description, cve.Severity, cve.CVSS)

		// Add CVE-specific dorks
		for _, dork := range cve.Dorks {
			// Apply site filter
			if strings.Contains(dork, "site:") {
				allDorks = append(allDorks, dork)
			} else {
				allDorks = append(allDorks, fmt.Sprintf("site:%s %s", c.Target, dork))
			}
		}

		// Add version detection dorks if we don't have version yet
		for _, vDork := range cve.VersionDorks {
			if strings.Contains(vDork, "site:") {
				allDorks = append(allDorks, vDork)
			} else {
				allDorks = append(allDorks, fmt.Sprintf("site:%s %s", c.Target, vDork))
			}
		}
	}

	return allDorks
}

// generateIndustryVulnDorks generates dorks for industry-specific vulnerabilities
func (c *Config) generateIndustryVulnDorks(patterns []IndustryVulnPattern) []string {
	var allDorks []string

	for _, pattern := range patterns {
		console.Logv(c.Verbose, "[INDUSTRY-VULN] %s - %s (%s)", pattern.Industry, pattern.VulnCategory, pattern.Severity)
		console.Logv(c.Verbose, "[INDUSTRY-VULN] Compliance: %v (False Positive Rate: %.0f%%)",
			pattern.Compliance, pattern.FalsePositiveRate*100)

		// Add industry-specific dorks
		for _, dork := range pattern.Dorks {
			// Apply site filter if not already present
			if strings.Contains(dork, "site:") {
				allDorks = append(allDorks, dork)
			} else {
				allDorks = append(allDorks, fmt.Sprintf("site:%s %s", c.Target, dork))
			}
		}
	}

	return allDorks
}

// enhancedCVEDetection performs comprehensive CVE detection with AI-driven version detection
func (c *Config) enhancedCVEDetection(ctx context.Context) []CVEEntry {
	if c.Intelligence == nil || len(c.Intelligence.TechStack) == 0 {
		return nil
	}

	console.Logv(c.Verbose, "[CVE-DETECT] Performing enhanced CVE detection on %d detected technologies...", len(c.Intelligence.TechStack))

	var allCVEs []CVEEntry
	processedTech := make(map[string]bool)

	for _, tech := range c.Intelligence.TechStack {
		techLower := strings.ToLower(tech)

		// Avoid duplicate processing
		if processedTech[techLower] {
			continue
		}
		processedTech[techLower] = true

		// Try to detect version using AI
		evidence := []string{tech}
		// Add any version-related discoveries from paths or discovered files
		for _, path := range c.Intelligence.DiscoveredPaths {
			if strings.Contains(strings.ToLower(path), "version") ||
				strings.Contains(strings.ToLower(path), techLower) {
				evidence = append(evidence, path)
			}
		}

		version := c.detectTechnologyVersion(ctx, tech, evidence)

		// Match CVEs for this technology
		cves := matchCVEsByTechnology(tech, version)

		if len(cves) > 0 {
			console.Logv(c.Verbose, "[CVE-DETECT] Found %d CVEs for %s (version: %s)", len(cves), tech, version)
			allCVEs = append(allCVEs, cves...)

			// Update intelligence with detected CVEs
			for _, cve := range cves {
				c.Intelligence.DetectedCVEs = append(c.Intelligence.DetectedCVEs, core.CVEIntelligence{
					Technology:  tech,
					Version:     version,
					CVEList:     []string{cve.CVEID},
					Severity:    cve.Severity,
					LastChecked: time.Now(),
				})
			}
		}
	}

	return allCVEs
}
