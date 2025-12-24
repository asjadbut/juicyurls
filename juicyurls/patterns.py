"""
Pattern definitions for identifying potentially vulnerable URLs.

Each pattern category contains:
- name: Category name
- severity: high, medium, low
- description: What this category represents
- patterns: List of regex patterns or keywords to match
- param_patterns: Parameter names that indicate this vulnerability type

IMPORTANT: Patterns are designed to minimize false positives while catching
real vulnerabilities. Focus on actionable, testable endpoints.
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Pattern
from enum import Enum


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class VulnPattern:
    """Represents a vulnerability pattern category."""
    name: str
    severity: Severity
    description: str
    path_patterns: List[str] = field(default_factory=list)
    param_patterns: List[str] = field(default_factory=list)
    extension_patterns: List[str] = field(default_factory=list)
    # Negative patterns - if these match, skip this category
    exclude_patterns: List[str] = field(default_factory=list)
    # Require parameter to be present (not just path match)
    require_params: bool = False
    compiled_path: List[Pattern] = field(default_factory=list, repr=False)
    compiled_param: List[Pattern] = field(default_factory=list, repr=False)
    compiled_ext: List[Pattern] = field(default_factory=list, repr=False)
    compiled_exclude: List[Pattern] = field(default_factory=list, repr=False)
    
    def __post_init__(self):
        """Compile regex patterns for better performance."""
        self.compiled_path = [re.compile(p, re.IGNORECASE) for p in self.path_patterns]
        self.compiled_param = [re.compile(p, re.IGNORECASE) for p in self.param_patterns]
        self.compiled_ext = [re.compile(p, re.IGNORECASE) for p in self.extension_patterns]
        self.compiled_exclude = [re.compile(p, re.IGNORECASE) for p in self.exclude_patterns]


class PatternManager:
    """Manages all vulnerability patterns and matching logic."""
    
    def __init__(self):
        self.patterns: Dict[str, VulnPattern] = {}
        self._load_default_patterns()
    
    def _load_default_patterns(self):
        """Load all default vulnerability patterns."""
        
        # ==================== CRITICAL SEVERITY ====================
        
        # Remote Code Execution patterns - Based on GF-Patterns RCE
        self.patterns["rce"] = VulnPattern(
            name="Remote Code Execution",
            severity=Severity.CRITICAL,
            description="URLs that may allow command injection or code execution",
            path_patterns=[
                r"/exec\b", r"/execute\b", r"/run\b", r"/shell\b",
                r"/cmd\b", r"/command\b", r"/system\b", r"/eval\b",
                r"/ping\b",  # ping utility often vulnerable
            ],
            param_patterns=[
                # Core RCE parameters from GF-Patterns
                r"^cmd$", r"^exec$", r"^command$", r"^execute$",
                r"^ping$", r"^host$", r"^ip$", r"^target$",
                r"^code$", r"^run$", r"^daemon$", r"^cli$",
                r"^hostname$", r"^shell$",
                # Additional from GF-Patterns rce.json
                r"^do$", r"^func$", r"^function$", r"^arg$",
                r"^option$", r"^step$", r"^feature$",
                r"^module$", r"^payload$", r"^exe$",
                r"^reg$", r"^jump$", r"^print$",
            ],
            # Exclude static assets
            exclude_patterns=[
                r"\.(js|css|jpg|jpeg|png|gif|svg|ico|woff|woff2|ttf|eot|mp4|mp3|pdf)(\?|$)",
                r"/static/", r"/assets/", r"/dist/",
            ],
            require_params=True,  # Only flag if suspicious params present
        )
        
        # Server-Side Template Injection
        self.patterns["ssti"] = VulnPattern(
            name="Server-Side Template Injection",
            severity=Severity.CRITICAL,
            description="URLs that may be vulnerable to template injection",
            path_patterns=[
                r"/template[/?]", r"/render\b", r"/preview\b",
                r"/email[-_]?template", r"/mail[-_]?template",
                r"/newsletter[-_]?preview",
            ],
            param_patterns=[
                r"^template$", r"^tpl$", r"^view$", r"^layout$",
                r"^render$", r"^markup$",
            ],
            require_params=True,
        )
        
        # ==================== HIGH SEVERITY ====================
        
        # SQL Injection patterns - Based on GF-Patterns SQLi
        self.patterns["sqli"] = VulnPattern(
            name="SQL Injection",
            severity=Severity.HIGH,
            description="URLs with parameters that may be vulnerable to SQL injection",
            path_patterns=[
                r"/search\?", r"/query\?", r"/report\?",
                r"/lookup\?", r"/find\?",
            ],
            param_patterns=[
                # Numeric ID parameters from GF-Patterns
                r"^id$", r"^userid$", r"^user_id$", r"^uid$",
                r"^accountid$", r"^account_id$",
                r"^orderid$", r"^order_id$", r"^oid$",
                r"^productid$", r"^product_id$", r"^pid$",
                r"^itemid$", r"^item_id$",
                r"^articleid$", r"^article_id$",
                r"^postid$", r"^post_id$",
                r"^docid$", r"^doc_id$", r"^document_id$",
                # Query/filter parameters from GF-Patterns sqli.json
                r"^query$", r"^search$", r"^keyword$", r"^term$",
                r"^filter$", r"^where$", r"^select$",
                r"^order$", r"^orderby$", r"^order_by$", r"^sortby$", r"^sort_by$",
                r"^column$", r"^col$", r"^field$", r"^table$",
                # Additional from GF-Patterns
                r"^role$", r"^update$", r"^params$", r"^row$",
                r"^results$", r"^from$", r"^sel$", r"^delete$",
                r"^string$", r"^number$", r"^user$", r"^name$",
                r"^sort$", r"^process$", r"^fetch$", r"^sleep$",
                r"^report$", r"^view$",
            ],
            exclude_patterns=[
                r"\.(js|css|jpg|jpeg|png|gif|svg|ico|woff|woff2)(\?|$)",
            ],
            require_params=True,
        )
        
        # Local/Remote File Inclusion - Based on GF-Patterns LFI
        self.patterns["lfi_rfi"] = VulnPattern(
            name="File Inclusion (LFI/RFI)",
            severity=Severity.HIGH,
            description="URLs that may allow local or remote file inclusion",
            path_patterns=[
                r"/include\?", r"/require\?", r"/load\?",
                r"/read\?", r"/display\?", r"/show\?",
                r"/download\?", r"/get[-_]?file\?",
                r"/view[-_]?file\?", r"/open\?",
            ],
            param_patterns=[
                # Core LFI parameters from GF-Patterns lfi.json
                r"^file$", r"^filename$", r"^filepath$", r"^file_path$",
                r"^path$", r"^pathname$", r"^folder$",
                r"^include$", r"^require$", r"^inc$",
                r"^page$", r"^pg$", r"^pagename$",
                r"^template$", r"^tpl$", r"^tmpl$",
                r"^doc$", r"^document$", r"^root$",
                r"^dir$", r"^directory$", r"^location$",
                r"^load$", r"^read$", r"^fetch$",
                r"^src$", r"^source$", r"^conf$", r"^config$",
                # Additional from GF-Patterns lfi.json
                r"^cat$", r"^action$", r"^board$", r"^detail$",
                r"^prefix$", r"^locate$", r"^type$",
                r"^content$", r"^layout$", r"^mod$",
                r"^style$", r"^pdf$", r"^date$", r"^download$",
                r"^site$", r"^view$", r"^name$", r"^url$",
            ],
            exclude_patterns=[
                r"\.(js|css|jpg|jpeg|png|gif|svg|ico|woff|woff2|mp4|mp3)(\?|$)",
                r"/static/", r"/assets/",
            ],
            require_params=True,
        )
        
        # Server-Side Request Forgery - Based on GF-Patterns SSRF + HowToHunt
        self.patterns["ssrf"] = VulnPattern(
            name="Server-Side Request Forgery",
            severity=Severity.HIGH,
            description="URLs that may allow SSRF attacks",
            path_patterns=[
                r"/proxy\?", r"/fetch\?", r"/request\?", r"/curl\?",
                r"/retrieve\?", r"/connect\?", r"/forward\?",
                r"/webhook\?", r"/callback\?", r"/feed\?",
                r"/preview\?", r"/screenshot\?", r"/snap\?",
                r"/pdf\?", r"/print\?", r"/export\?", r"/convert\?",
                r"/import\?", r"/load[-_]?url\?", r"/get[-_]?url\?",
                r"/url[-_]?fetch", r"/url[-_]?load",
                r"/share\?.*url=",
            ],
            param_patterns=[
                # Core SSRF parameters from GF-Patterns + HowToHunt
                r"^url$", r"^uri$", r"^link$", r"^href$",
                r"^src$", r"^source$", r"^target$", r"^dest$",
                r"^destination$", r"^site$", r"^host$",
                r"^domain$", r"^callback$", r"^webhook$",
                r"^proxy$", r"^proxyurl$", r"^proxy_url$",
                r"^request$", r"^fetch$", r"^load$",
                r"^imageurl$", r"^image_url$", r"^imgurl$", r"^img$",
                r"^iconurl$", r"^icon_url$", r"^avatarurl$",
                r"^feedurl$", r"^feed_url$", r"^rssurl$",
                r"^xmlurl$", r"^apiurl$", r"^api_url$",
                r"^endpoint$", r"^service$", r"^server$",
                r"^remote$", r"^external$",
                # From HowToHunt SSRF.md
                r"^page$", r"^data$", r"^ret$", r"^return$",
                r"^next$", r"^redirect$", r"^redirectBack$",
                r"^referer$", r"^redir$", r"^forward$",
                r"^path$", r"^redirect_url$", r"^return_url$",
                r"^goto$", r"^navigation$", r"^open$",
                r"^file$", r"^document$", r"^folder$", r"^pg$",
                r"^doc$", r"^html$", r"^val$", r"^validate$",
                r"^reference$", r"^out$", r"^view$", r"^dir$", r"^show$",
                r"^window$", r"^continue$", r"^style$", r"^filename$",
            ],
            require_params=True,
        )
        
        # IDOR - Based on GF-Patterns IDOR + HowToHunt
        self.patterns["idor"] = VulnPattern(
            name="IDOR",
            severity=Severity.HIGH,
            description="URLs with object references that may be manipulated",
            path_patterns=[
                # Path-based IDORs with numeric IDs
                r"/user/\d+", r"/users/\d+",
                r"/account/\d+", r"/accounts/\d+",
                r"/profile/\d+", r"/profiles/\d+",
                r"/order/\d+", r"/orders/\d+",
                r"/invoice/\d+", r"/invoices/\d+",
                r"/document/\d+", r"/documents/\d+",
                r"/file/\d+", r"/files/\d+",
                r"/download/\d+", r"/attachment/\d+",
                r"/message/\d+", r"/messages/\d+",
                r"/ticket/\d+", r"/tickets/\d+",
                r"/report/\d+", r"/reports/\d+",
                r"/project/\d+", r"/projects/\d+",
                # API patterns
                r"/api/v\d+/users/\d+", r"/api/v\d+/accounts/\d+",
                r"/api/users/\d+", r"/api/accounts/\d+",
                r"/api/v\d+/\w+/\d+/edit",
                r"/api/v\d+/\w+/\d+/delete",
            ],
            param_patterns=[
                # Core IDOR params from GF-Patterns idor.json
                r"^id$", r"^user$", r"^account$", r"^number$",
                r"^order$", r"^no$", r"^doc$", r"^key$",
                r"^email$", r"^group$", r"^profile$", r"^edit$", r"^report$",
                # Specific ID parameters
                r"^userid$", r"^user_id$", r"^userId$",
                r"^accountid$", r"^account_id$", r"^accountId$",
                r"^profileid$", r"^profile_id$", r"^profileId$",
                r"^orderid$", r"^order_id$", r"^orderId$",
                r"^invoiceid$", r"^invoice_id$", r"^invoiceId$",
                r"^docid$", r"^doc_id$", r"^documentid$", r"^document_id$",
                r"^fileid$", r"^file_id$", r"^fileId$",
                r"^messageid$", r"^message_id$", r"^messageId$",
                r"^ticketid$", r"^ticket_id$", r"^ticketId$",
                r"^reportid$", r"^report_id$", r"^reportId$",
                r"^uuid$", r"^guid$",
            ],
            exclude_patterns=[
                r"\.(js|css|jpg|jpeg|png|gif|svg|ico|woff|woff2)(\?|$)",
            ],
        )
        
        # XML External Entity (XXE) - Focus on XML processing endpoints
        self.patterns["xxe"] = VulnPattern(
            name="XXE Injection",
            severity=Severity.HIGH,
            description="URLs that process XML and may be vulnerable to XXE",
            path_patterns=[
                r"/xml[-_]?upload", r"/import[-_]?xml", r"/parse[-_]?xml",
                r"/soap\b", r"/wsdl\b", r"/xmlrpc",
                r"/svg[-_]?upload", r"/process[-_]?xml",
            ],
            param_patterns=[
                r"^xml$", r"^xmldata$", r"^xml_data$",
                r"^soap$", r"^wsdl$", r"^xmlfile$",
            ],
            require_params=True,
        )
        
        # Sensitive Files - High confidence file exposure
        self.patterns["sensitive_files"] = VulnPattern(
            name="Sensitive Files",
            severity=Severity.HIGH,
            description="URLs pointing to potentially sensitive files",
            path_patterns=[
                # Config files
                r"/\.env$", r"/\.env\.\w+$",
                r"/\.git/config$", r"/\.git/HEAD$",
                r"/\.svn/entries$", r"/\.svn/wc\.db$",
                r"/\.htaccess$", r"/\.htpasswd$",
                r"/web\.config$", r"/config\.php$", r"/config\.inc\.php$",
                r"/wp-config\.php$", r"/wp-config\.php\.bak$",
                r"/configuration\.php$", r"/settings\.php$",
                r"/LocalSettings\.php$", r"/database\.yml$",
                r"/config/database\.yml$", r"/config\.yml$",
                r"/secrets\.yml$", r"/credentials\.json$",
                # Key files
                r"/id_rsa$", r"/id_dsa$", r"/id_ecdsa$",
                r"/\.ssh/", r"/\.gnupg/",
                r"\.pem$", r"\.key$", r"\.ppk$", r"\.p12$",
                # Backup files with source code
                r"\.php\.bak$", r"\.php~$", r"\.php\.old$",
                r"\.asp\.bak$", r"\.aspx\.bak$",
                r"/backup\.sql$", r"/dump\.sql$", r"/database\.sql$",
            ],
        )
        
        # Backup Files
        self.patterns["backup"] = VulnPattern(
            name="Backup Files",
            severity=Severity.MEDIUM,
            description="Backup files that may contain sensitive information",
            path_patterns=[
                r"/backup\.zip$", r"/backup\.tar\.gz$", r"/backup\.sql$",
                r"/site[-_]?backup", r"/db[-_]?backup", r"/full[-_]?backup",
                r"\.bak$", r"\.backup$", r"\.old$",
                r"\.sql\.gz$", r"\.sql\.zip$",
                r"/\w+\.tar\.gz$", r"/\w+\.zip$",
            ],
            exclude_patterns=[
                r"/download/", r"/release/", r"/dist/",  # Legitimate downloads
            ],
        )
        
        # ==================== MEDIUM SEVERITY ====================
        
        # Open Redirect - Based on GF-Patterns Redirect + HowToHunt
        self.patterns["redirect"] = VulnPattern(
            name="Open Redirect",
            severity=Severity.MEDIUM,
            description="URLs that may allow open redirect attacks",
            path_patterns=[
                r"/redirect\?", r"/redir\?", r"/go\?", r"/out\?",
                r"/away\?", r"/external\?", r"/link\?", r"/click\?",
                r"/track\?", r"/jump\?", r"/leave\?", r"/exit\?",
                r"/forward\?", r"/continue\?", r"/proceed\?",
                r"/logout\?.*(?:redirect|return|next|url)=",
                r"/login\?.*(?:redirect|return|next|url)=",
                r"/cgi-bin/redirect\.cgi",  # From GF-Patterns
            ],
            param_patterns=[
                # From GF-Patterns redirect.json
                r"^next$", r"^url$", r"^rurl$", r"^target$",
                r"^dest$", r"^destination$", r"^redir$", r"^redirect$",
                r"^redirect_uri$", r"^redirect_url$", r"^redirectUrl$",
                r"^return$", r"^return_url$", r"^returnUrl$", r"^returnTo$",
                r"^return_to$", r"^return_path$", r"^goto$", r"^go$",
                r"^checkout_url$", r"^checkout$", r"^continue$", r"^continueTo$",
                r"^forward$", r"^forward_url$", r"^from_url$",
                r"^logout$", r"^logout_url$", r"^success_url$", r"^failure_url$",
                r"^callback$", r"^callback_url$",
                # Additional from GF-Patterns
                r"^Open$", r"^Lmage_url$", r"^image_url$", r"^img_url$",
                r"^file_url$", r"^folder_url$", r"^load_file$", r"^load_url$",
                r"^login_url$", r"^next_page$", r"^page_url$",
                r"^redirect_to$", r"^reference$", r"^rt$",
                r"^uri$", r"^val$", r"^validate$", r"^window$",
                r"^host$", r"^domain$", r"^feed$", r"^data$",
                r"^dir$", r"^path$", r"^site$", r"^html$",
                r"^navigation$", r"^out$", r"^page$", r"^show$",
                r"^view$", r"^file$", r"^file_name$", r"^folder$",
            ],
            exclude_patterns=[
                r"\.(js|css|jpg|jpeg|png|gif|svg|ico)(\?|$)",
            ],
            require_params=True,
        )
        
        # Cross-Site Scripting (XSS) - Based on GF-Patterns XSS
        self.patterns["xss"] = VulnPattern(
            name="XSS",
            severity=Severity.MEDIUM,
            description="URLs with parameters that may be reflected and vulnerable to XSS",
            path_patterns=[
                r"/search\?", r"/find\?", r"/error\?", r"/404\?",
                r"/message\?", r"/feedback\?", r"/comment\?",
                r"/share\?", r"/preview\?",
            ],
            param_patterns=[
                # Core XSS parameters from GF-Patterns xss.json
                r"^q$", r"^s$", r"^search$", r"^query$", r"^keyword$",
                r"^term$", r"^text$", r"^input$", r"^keywords$",
                r"^message$", r"^msg$", r"^error$", r"^err$",
                r"^alert$", r"^notice$", r"^warning$",
                r"^callback$", r"^jsonp$", r"^cb$",
                r"^name$", r"^title$", r"^subject$",
                # Additional from GF-Patterns xss.json
                r"^lang$", r"^p$", r"^type$", r"^item$",
                r"^terms$", r"^year$", r"^month$", r"^view$",
                r"^page$", r"^page_id$", r"^categoryid$",
                r"^list_type$", r"^begindate$", r"^enddate$",
                r"^email$", r"^immagine$", r"^key$", r"^l$",
            ],
            exclude_patterns=[
                r"\.(js|css|jpg|jpeg|png|gif|svg|ico|woff|woff2)(\?|$)",
            ],
            require_params=True,
        )
        
        # Authentication/Session - Actual auth endpoints
        self.patterns["auth"] = VulnPattern(
            name="Authentication",
            severity=Severity.MEDIUM,
            description="Authentication and session management endpoints",
            path_patterns=[
                r"/login$", r"/signin$", r"/sign-in$", r"/logon$",
                r"/logout$", r"/signout$", r"/sign-out$",
                r"/register$", r"/signup$", r"/sign-up$",
                r"/auth/", r"/oauth/", r"/sso/", r"/saml/",
                r"/password[-_]?reset", r"/forgot[-_]?password",
                r"/reset[-_]?password", r"/change[-_]?password",
                r"/verify[-_]?email", r"/confirm[-_]?email",
                r"/activate", r"/2fa", r"/mfa", r"/otp",
                r"/token$", r"/jwt$", r"/refresh[-_]?token",
            ],
            param_patterns=[
                r"^token$", r"^auth_token$", r"^access_token$",
                r"^refresh_token$", r"^session$", r"^sessionid$",
                r"^jwt$", r"^code$", r"^otp$",
            ],
        )
        
        # File Upload - Actual upload endpoints
        self.patterns["upload"] = VulnPattern(
            name="File Upload",
            severity=Severity.MEDIUM,
            description="File upload endpoints that may allow malicious uploads",
            path_patterns=[
                r"/upload$", r"/upload/", r"/uploader",
                r"/file[-_]?upload", r"/image[-_]?upload",
                r"/attach$", r"/attachment/upload",
                r"/import$", r"/import/", r"/importer",
                r"/media/upload", r"/avatar/upload",
                r"/profile[-_]?pic", r"/profile/upload",
                r"/document/upload", r"/asset/upload",
            ],
            param_patterns=[
                r"^file$", r"^upload$", r"^attachment$",
                r"^document$", r"^image$", r"^photo$",
            ],
            exclude_patterns=[
                # Exclude static image paths
                r"/images/\w+\.(jpg|jpeg|png|gif|svg)$",
                r"/static/", r"/assets/", r"/media/\w+\.(jpg|jpeg|png|gif)$",
            ],
        )
        
        # Admin/Debug endpoints
        self.patterns["admin_debug"] = VulnPattern(
            name="Admin/Debug",
            severity=Severity.MEDIUM,
            description="Admin or debug endpoints",
            path_patterns=[
                r"/admin$", r"/admin/", r"/administrator/",
                r"/manage$", r"/management/", r"/manager/",
                r"/console$", r"/console/", r"/dashboard$",
                r"/portal$", r"/controlpanel", r"/cp/",
                r"/backend/", r"/backoffice/", r"/internal/",
                r"/debug$", r"/debug/", r"/_debug",
                r"/test$", r"/testing/", r"/dev/",
                r"/staging/", r"/qa/", r"/demo/",
                r"/trace$", r"/metrics$", r"/monitor$",
                r"/health$", r"/status$", r"/actuator/",
                r"/phpinfo\.php$", r"/info\.php$", r"/test\.php$",
                r"/server-status$", r"/server-info$",
                r"/__debug__/", r"/profiler/",
                r"/elmah\.axd", r"/trace\.axd",
            ],
            param_patterns=[
                r"^debug$", r"^test$", r"^admin$", r"^dev$",
                r"^trace$", r"^verbose$",
            ],
        )
        
        # Cloud/Storage - External cloud resources
        self.patterns["cloud"] = VulnPattern(
            name="Cloud/Storage",
            severity=Severity.MEDIUM,
            description="Cloud storage and service endpoints that may be misconfigured",
            path_patterns=[
                r"s3\.amazonaws\.com", r"\.s3\.", r"s3://",
                r"blob\.core\.windows\.net", r"storage\.googleapis\.com",
                r"digitaloceanspaces\.com", r"backblazeb2\.com",
                r"/storage/.*\?", r"/bucket/.*\?",
            ],
            param_patterns=[
                r"^bucket$", r"^key$", r"^blob$", r"^container$",
                r"^AWSAccessKeyId$", r"^X-Amz-", r"^Signature$",
            ],
        )
        
        # GraphQL - Introspection and mutations
        self.patterns["graphql"] = VulnPattern(
            name="GraphQL",
            severity=Severity.MEDIUM,
            description="GraphQL endpoints that may allow introspection",
            path_patterns=[
                r"/graphql$", r"/graphql/", r"/graphiql$",
                r"/gql$", r"/api/graphql$",
                r"/v\d+/graphql$", r"/playground$",
                r"/altair$", r"/voyager$",
            ],
            param_patterns=[
                r"^query$", r"^mutation$", r"^operationName$",
            ],
        )
        
        # ==================== LOW/INFO SEVERITY ====================
        
        # API Endpoints - For documentation/enumeration
        self.patterns["api"] = VulnPattern(
            name="API Endpoints",
            severity=Severity.LOW,
            description="API endpoints that may expose functionality or data",
            path_patterns=[
                r"/api/v\d+/", r"/api/\w+$",
                r"/rest/", r"/v1/", r"/v2/", r"/v3/",
                r"/swagger", r"/openapi", r"/api-docs",
                r"/redoc", r"/docs/api",
            ],
            exclude_patterns=[
                r"/static/", r"/assets/", r"/dist/",
                r"package\.json$", r"manifest\.json$",
                r"\.(js|css|jpg|jpeg|png|gif|svg|ico)(\?|$)",
            ],
        )
        
        # Information Disclosure - Sensitive info leaks
        self.patterns["info_disclosure"] = VulnPattern(
            name="Information Disclosure",
            severity=Severity.LOW,
            description="URLs that may disclose sensitive information",
            path_patterns=[
                r"/\.git/", r"/\.svn/", r"/\.hg/",
                r"/\.DS_Store$", r"/Thumbs\.db$",
                r"/crossdomain\.xml$", r"/clientaccesspolicy\.xml$",
                r"/robots\.txt$", r"/security\.txt$",
                r"/\.well-known/", r"/sitemap\.xml$",
                r"/CHANGELOG", r"/VERSION$", r"/README$",
                r"/composer\.json$", r"/package\.json$",
                r"/requirements\.txt$", r"/Gemfile$",
                r"/Dockerfile$", r"/docker-compose",
                r"/\.dockerignore$", r"/\.gitignore$",
                r"/phpinfo", r"/server-status",
            ],
        )
        
        # WebSocket - Real websocket endpoints only
        self.patterns["websocket"] = VulnPattern(
            name="WebSocket",
            severity=Severity.LOW,
            description="WebSocket endpoints",
            path_patterns=[
                r"/ws$", r"/wss$", r"/websocket$", r"/websocket/",
                r"/socket\.io/", r"/sockjs/", r"/hub$",
                r"/signalr/", r"/realtime$", r"/live$",
                r"/cable$",  # ActionCable
            ],
            exclude_patterns=[
                # Exclude product codes starting with WS
                r"/WS[A-Z0-9]{2,}", r"/ws[a-z]{2,}\d",
                r"\.html$", r"\.htm$", r"\.jpg", r"\.png", r"\.gif",
            ],
        )
    
    def get_pattern(self, name: str) -> Optional[VulnPattern]:
        """Get a specific pattern by name."""
        return self.patterns.get(name)
    
    def get_all_patterns(self) -> Dict[str, VulnPattern]:
        """Get all patterns."""
        return self.patterns
    
    def get_patterns_by_severity(self, severity: Severity) -> Dict[str, VulnPattern]:
        """Get patterns filtered by severity."""
        return {k: v for k, v in self.patterns.items() if v.severity == severity}
    
    def add_pattern(self, name: str, pattern: VulnPattern):
        """Add a custom pattern."""
        self.patterns[name] = pattern
    
    def get_category_names(self) -> List[str]:
        """Get list of all category names."""
        return list(self.patterns.keys())
