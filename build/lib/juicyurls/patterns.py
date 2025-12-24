"""
Pattern definitions for identifying potentially vulnerable URLs.

Each pattern category contains:
- name: Category name
- severity: high, medium, low
- description: What this category represents
- patterns: List of regex patterns or keywords to match
- param_patterns: Parameter names that indicate this vulnerability type
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
    compiled_path: List[Pattern] = field(default_factory=list, repr=False)
    compiled_param: List[Pattern] = field(default_factory=list, repr=False)
    compiled_ext: List[Pattern] = field(default_factory=list, repr=False)
    
    def __post_init__(self):
        """Compile regex patterns for better performance."""
        self.compiled_path = [re.compile(p, re.IGNORECASE) for p in self.path_patterns]
        self.compiled_param = [re.compile(p, re.IGNORECASE) for p in self.param_patterns]
        self.compiled_ext = [re.compile(p, re.IGNORECASE) for p in self.extension_patterns]


class PatternManager:
    """Manages all vulnerability patterns and matching logic."""
    
    def __init__(self):
        self.patterns: Dict[str, VulnPattern] = {}
        self._load_default_patterns()
    
    def _load_default_patterns(self):
        """Load all default vulnerability patterns."""
        
        # ==================== CRITICAL SEVERITY ====================
        
        # Remote Code Execution patterns
        self.patterns["rce"] = VulnPattern(
            name="Remote Code Execution",
            severity=Severity.CRITICAL,
            description="URLs that may allow command injection or code execution",
            path_patterns=[
                r"/exec", r"/execute", r"/run", r"/shell", r"/cmd",
                r"/command", r"/system", r"/eval", r"/ping",
                r"/cgi-bin/", r"\.cgi$", r"\.pl$", r"\.sh$",
            ],
            param_patterns=[
                r"^cmd$", r"^exec$", r"^command$", r"^execute$",
                r"^ping$", r"^query$", r"^jump$", r"^code$",
                r"^reg$", r"^do$", r"^func$", r"^arg$",
                r"^option$", r"^load$", r"^process$", r"^step$",
                r"^read$", r"^function$", r"^req$", r"^feature$",
                r"^exe$", r"^module$", r"^payload$", r"^run$",
                r"^daemon$", r"^upload$", r"^dir$", r"^download$",
                r"^log$", r"^ip$", r"^cli$", r"^hostname$",
            ],
        )
        
        # Server-Side Template Injection
        self.patterns["ssti"] = VulnPattern(
            name="Server-Side Template Injection",
            severity=Severity.CRITICAL,
            description="URLs that may be vulnerable to template injection",
            path_patterns=[
                r"/template", r"/render", r"/preview",
                r"/email[-_]?template", r"/mail[-_]?template",
            ],
            param_patterns=[
                r"^template$", r"^preview$", r"^render$",
                r"^content$", r"^markup$", r"^tpl$",
                r"^text$", r"^body$", r"^html$",
            ],
        )
        
        # ==================== HIGH SEVERITY ====================
        
        # SQL Injection patterns
        self.patterns["sqli"] = VulnPattern(
            name="SQL Injection",
            severity=Severity.HIGH,
            description="URLs with parameters that may be vulnerable to SQL injection",
            path_patterns=[
                r"/select", r"/report", r"/query",
                r"/fetch", r"/search",
            ],
            param_patterns=[
                r"^id$", r"^ID$", r"_id$", r"Id$",
                r"^user$", r"^username$", r"^login$",
                r"^query$", r"^q$", r"^search$", r"^keyword$",
                r"^sort$", r"^order$", r"^orderby$", r"^sortby$",
                r"^filter$", r"^where$", r"^column$", r"^field$",
                r"^table$", r"^from$", r"^select$", r"^limit$",
                r"^offset$", r"^page$", r"^num$", r"^number$",
                r"^count$", r"^category$", r"^cat$", r"^type$",
                r"^name$", r"^title$", r"^item$", r"^product$",
                r"^article$", r"^post$", r"^thread$", r"^message$",
                r"^report$", r"^view$", r"^show$", r"^list$",
            ],
        )
        
        # Local/Remote File Inclusion
        self.patterns["lfi_rfi"] = VulnPattern(
            name="File Inclusion (LFI/RFI)",
            severity=Severity.HIGH,
            description="URLs that may allow local or remote file inclusion",
            path_patterns=[
                r"/include", r"/require", r"/load",
                r"/read", r"/display", r"/show",
            ],
            param_patterns=[
                r"^file$", r"^filename$", r"^path$", r"^filepath$",
                r"^page$", r"^pg$", r"^include$", r"^require$",
                r"^folder$", r"^directory$", r"^dir$", r"^doc$",
                r"^document$", r"^root$", r"^location$", r"^conf$",
                r"^template$", r"^tpl$", r"^skin$", r"^theme$",
                r"^layout$", r"^style$", r"^css$", r"^view$",
                r"^content$", r"^cont$", r"^load$", r"^read$",
                r"^fetch$", r"^src$", r"^source$", r"^data$",
            ],
            extension_patterns=[
                r"\.php$", r"\.asp$", r"\.aspx$", r"\.jsp$",
                r"\.inc$", r"\.tpl$", r"\.phtml$",
            ],
        )
        
        # Server-Side Request Forgery
        self.patterns["ssrf"] = VulnPattern(
            name="Server-Side Request Forgery",
            severity=Severity.HIGH,
            description="URLs that may allow SSRF attacks",
            path_patterns=[
                r"/proxy", r"/fetch", r"/request", r"/curl",
                r"/grab", r"/retrieve", r"/connect", r"/forward",
                r"/webhook", r"/callback", r"/feed", r"/rss",
                r"/share", r"/preview", r"/screenshot", r"/snap",
                r"/pdf", r"/print", r"/export", r"/convert",
                r"/import", r"/load[-_]?url", r"/get[-_]?url",
            ],
            param_patterns=[
                r"^url$", r"^uri$", r"^link$", r"^href$",
                r"^src$", r"^source$", r"^target$", r"^dest$",
                r"^destination$", r"^redirect$", r"^redir$",
                r"^return$", r"^next$", r"^site$", r"^host$",
                r"^domain$", r"^callback$", r"^webhook$",
                r"^proxy$", r"^proxyurl$", r"^request$",
                r"^fetch$", r"^ping$", r"^img$", r"^image$",
                r"^imageurl$", r"^icon$", r"^iconurl$", r"^avatar$",
                r"^feed$", r"^rss$", r"^xml$", r"^api$",
                r"^endpoint$", r"^service$", r"^server$",
                r"^remote$", r"^external$", r"^load$", r"^get$",
            ],
        )
        
        # IDOR (Insecure Direct Object Reference)
        self.patterns["idor"] = VulnPattern(
            name="IDOR",
            severity=Severity.HIGH,
            description="URLs with object references that may be manipulated",
            path_patterns=[
                r"/user/\d+", r"/account/\d+", r"/profile/\d+",
                r"/order/\d+", r"/invoice/\d+", r"/document/\d+",
                r"/file/\d+", r"/download/\d+", r"/view/\d+",
                r"/edit/\d+", r"/delete/\d+", r"/update/\d+",
                r"/api/v\d+/\w+/\d+", r"/api/\w+/\d+",
            ],
            param_patterns=[
                r"^id$", r"_id$", r"Id$", r"ID$",
                r"^uid$", r"^userid$", r"^user_id$", r"^userId$",
                r"^accountid$", r"^account_id$", r"^accountId$",
                r"^profileid$", r"^profile_id$", r"^profileId$",
                r"^orderid$", r"^order_id$", r"^orderId$",
                r"^invoiceid$", r"^invoice_id$", r"^invoiceId$",
                r"^docid$", r"^doc_id$", r"^documentid$", r"^document_id$",
                r"^fileid$", r"^file_id$", r"^fileId$",
                r"^reportid$", r"^report_id$", r"^reportId$",
                r"^messageid$", r"^message_id$", r"^messageId$",
                r"^projectid$", r"^project_id$", r"^projectId$",
                r"^orgid$", r"^org_id$", r"^organizationid$",
                r"^teamid$", r"^team_id$", r"^teamId$",
                r"^groupid$", r"^group_id$", r"^groupId$",
                r"^no$", r"^number$", r"^num$", r"^idx$", r"^index$",
                r"^ref$", r"^reference$", r"^key$", r"^uuid$", r"^guid$",
            ],
        )
        
        # XML External Entity (XXE)
        self.patterns["xxe"] = VulnPattern(
            name="XXE Injection",
            severity=Severity.HIGH,
            description="URLs that process XML and may be vulnerable to XXE",
            path_patterns=[
                r"/xml", r"/soap", r"/wsdl", r"/parse",
                r"/import", r"/upload.*xml", r"/rss",
                r"/feed", r"/sitemap", r"/svg",
            ],
            param_patterns=[
                r"^xml$", r"^xmldata$", r"^soap$", r"^wsdl$",
                r"^rss$", r"^feed$", r"^svg$", r"^data$",
            ],
            extension_patterns=[
                r"\.xml$", r"\.soap$", r"\.wsdl$", r"\.svg$",
                r"\.rss$", r"\.atom$",
            ],
        )
        
        # ==================== MEDIUM SEVERITY ====================
        
        # Open Redirect
        self.patterns["redirect"] = VulnPattern(
            name="Open Redirect",
            severity=Severity.MEDIUM,
            description="URLs that may allow open redirect attacks",
            path_patterns=[
                r"/redirect", r"/redir", r"/go", r"/out",
                r"/away", r"/external", r"/link", r"/click",
                r"/track", r"/jump", r"/leave", r"/exit",
                r"/forward", r"/url", r"/continue", r"/proceed",
            ],
            param_patterns=[
                r"^next$", r"^url$", r"^target$", r"^rurl$",
                r"^dest$", r"^destination$", r"^redir$", r"^redirect$",
                r"^redirect_uri$", r"^redirect_url$", r"^redirectUrl$",
                r"^return$", r"^return_url$", r"^returnUrl$", r"^returnTo$",
                r"^return_to$", r"^returnurl$", r"^go$", r"^goto$",
                r"^checkout_url$", r"^continue$", r"^continueTo$",
                r"^exit$", r"^exit_url$", r"^exitUrl$",
                r"^forward$", r"^forward_url$", r"^forwardUrl$",
                r"^image_url$", r"^imageUrl$", r"^link$",
                r"^location$", r"^login_url$", r"^logout$",
                r"^logout_url$", r"^logoutUrl$", r"^out$",
                r"^path$", r"^r$", r"^r2$", r"^ref$",
                r"^referrer$", r"^service$", r"^site$",
                r"^success$", r"^success_url$", r"^to$",
                r"^u$", r"^uri$", r"^view$", r"^window$",
            ],
        )
        
        # Cross-Site Scripting (XSS)
        self.patterns["xss"] = VulnPattern(
            name="XSS",
            severity=Severity.MEDIUM,
            description="URLs with parameters that may be reflected and vulnerable to XSS",
            path_patterns=[
                r"/search", r"/find", r"/query", r"/error",
                r"/message", r"/comment", r"/feedback", r"/contact",
                r"/share", r"/post", r"/preview", r"/print",
            ],
            param_patterns=[
                r"^q$", r"^s$", r"^search$", r"^query$", r"^keyword$",
                r"^term$", r"^find$", r"^text$", r"^input$",
                r"^message$", r"^msg$", r"^comment$", r"^feedback$",
                r"^review$", r"^title$", r"^subject$", r"^body$",
                r"^content$", r"^description$", r"^desc$", r"^name$",
                r"^username$", r"^user$", r"^email$", r"^error$",
                r"^err$", r"^warning$", r"^alert$", r"^notice$",
                r"^info$", r"^status$", r"^callback$", r"^jsonp$",
                r"^redirect$", r"^return$", r"^next$", r"^url$",
                r"^lang$", r"^language$", r"^locale$", r"^class$",
                r"^style$", r"^color$", r"^font$", r"^size$",
                r"^width$", r"^height$", r"^src$", r"^href$",
                r"^value$", r"^label$", r"^data$", r"^html$",
            ],
        )
        
        # Authentication/Session
        self.patterns["auth"] = VulnPattern(
            name="Authentication",
            severity=Severity.MEDIUM,
            description="Authentication and session management endpoints",
            path_patterns=[
                r"/login", r"/signin", r"/sign-in", r"/logon",
                r"/logout", r"/signout", r"/sign-out", r"/logoff",
                r"/register", r"/signup", r"/sign-up", r"/join",
                r"/auth", r"/authenticate", r"/oauth", r"/sso",
                r"/saml", r"/callback", r"/token", r"/jwt",
                r"/session", r"/password", r"/reset", r"/forgot",
                r"/recover", r"/verify", r"/confirm", r"/activate",
                r"/2fa", r"/mfa", r"/otp", r"/totp",
            ],
            param_patterns=[
                r"^token$", r"^auth$", r"^key$", r"^apikey$",
                r"^api_key$", r"^access_token$", r"^accessToken$",
                r"^refresh_token$", r"^refreshToken$", r"^session$",
                r"^sessionid$", r"^session_id$", r"^sid$",
                r"^jwt$", r"^bearer$", r"^credential$",
                r"^password$", r"^passwd$", r"^pwd$", r"^pass$",
                r"^secret$", r"^code$", r"^otp$", r"^2fa$",
            ],
        )
        
        # File Upload
        self.patterns["upload"] = VulnPattern(
            name="File Upload",
            severity=Severity.MEDIUM,
            description="File upload endpoints that may allow malicious uploads",
            path_patterns=[
                r"/upload", r"/uploader", r"/file", r"/files",
                r"/attach", r"/attachment", r"/attachments",
                r"/import", r"/importer", r"/media", r"/image",
                r"/images", r"/photo", r"/photos", r"/avatar",
                r"/profile[-_]?pic", r"/cover", r"/banner",
                r"/document", r"/documents", r"/asset", r"/assets",
            ],
            param_patterns=[
                r"^file$", r"^upload$", r"^attachment$", r"^doc$",
                r"^document$", r"^image$", r"^img$", r"^photo$",
                r"^media$", r"^data$", r"^content$",
            ],
        )
        
        # ==================== LOW/INFO SEVERITY ====================
        
        # Sensitive Files
        self.patterns["sensitive_files"] = VulnPattern(
            name="Sensitive Files",
            severity=Severity.HIGH,
            description="URLs pointing to potentially sensitive files",
            path_patterns=[
                r"/\.env", r"/\.git", r"/\.svn", r"/\.hg",
                r"/\.htaccess", r"/\.htpasswd", r"/\.DS_Store",
                r"/web\.config", r"/config\.php", r"/config\.inc",
                r"/configuration\.php", r"/settings\.php", r"/database\.php",
                r"/db\.php", r"/conn\.php", r"/connection\.php",
                r"/wp-config\.php", r"/LocalSettings\.php",
                r"/config\.yml", r"/config\.yaml", r"/config\.json",
                r"/secrets\.yml", r"/secrets\.yaml", r"/secrets\.json",
                r"/credentials", r"/private", r"/secret",
                r"id_rsa", r"id_dsa", r"\.pem$", r"\.key$",
                r"\.ppk$", r"\.p12$", r"\.pfx$",
            ],
            extension_patterns=[
                r"\.env$", r"\.env\.\w+$", r"\.bak$", r"\.backup$",
                r"\.old$", r"\.orig$", r"\.save$", r"\.swp$",
                r"\.swo$", r"~$", r"\.copy$", r"\.tmp$",
                r"\.temp$", r"\.log$", r"\.logs$", r"\.sql$",
                r"\.sqlite$", r"\.sqlite3$", r"\.db$", r"\.mdb$",
                r"\.dump$", r"\.gz$", r"\.zip$", r"\.tar$",
                r"\.tgz$", r"\.rar$", r"\.7z$",
            ],
        )
        
        # Backup Files
        self.patterns["backup"] = VulnPattern(
            name="Backup Files",
            severity=Severity.MEDIUM,
            description="Backup files that may contain sensitive information",
            path_patterns=[
                r"/backup", r"/backups", r"/bak", r"/old",
                r"/archive", r"/archives", r"/dump", r"/export",
            ],
            extension_patterns=[
                r"\.bak$", r"\.backup$", r"\.old$", r"\.orig$",
                r"\.save$", r"\.copy$", r"\.1$", r"\.2$",
                r"~$", r"\.swp$", r"\.swo$", r"\.tmp$",
                r"\.sql$", r"\.sql\.gz$", r"\.sql\.zip$",
                r"\.dump$", r"\.tar$", r"\.tar\.gz$", r"\.tgz$",
                r"\.zip$", r"\.rar$", r"\.7z$",
            ],
        )
        
        # API Endpoints
        self.patterns["api"] = VulnPattern(
            name="API Endpoints",
            severity=Severity.LOW,
            description="API endpoints that may expose functionality or data",
            path_patterns=[
                r"/api", r"/api/v\d+", r"/rest", r"/graphql",
                r"/graphiql", r"/gql", r"/query", r"/mutation",
                r"/swagger", r"/openapi", r"/docs", r"/apidocs",
                r"/api-docs", r"/api[-_]?doc", r"/redoc",
                r"/v1/", r"/v2/", r"/v3/",
                r"\.json$", r"\.xml$",
            ],
            param_patterns=[
                r"^api$", r"^apikey$", r"^api_key$", r"^key$",
                r"^token$", r"^access_token$", r"^format$",
                r"^callback$", r"^jsonp$",
            ],
        )
        
        # Admin/Debug
        self.patterns["admin_debug"] = VulnPattern(
            name="Admin/Debug",
            severity=Severity.MEDIUM,
            description="Admin or debug endpoints",
            path_patterns=[
                r"/admin", r"/administrator", r"/manage", r"/management",
                r"/manager", r"/console", r"/dashboard", r"/portal",
                r"/control", r"/controlpanel", r"/cp", r"/panel",
                r"/backend", r"/backoffice", r"/internal", r"/staff",
                r"/debug", r"/debugging", r"/test", r"/testing",
                r"/dev", r"/devel", r"/development", r"/staging",
                r"/qa", r"/uat", r"/demo", r"/sandbox",
                r"/trace", r"/metrics", r"/monitor", r"/health",
                r"/status", r"/info", r"/actuator", r"/elmah",
                r"/phpinfo", r"/server-status", r"/server-info",
                r"/_debug", r"/__debug__", r"/profiler",
            ],
            param_patterns=[
                r"^debug$", r"^test$", r"^admin$", r"^dev$",
                r"^trace$", r"^verbose$", r"^log$",
            ],
        )
        
        # Information Disclosure
        self.patterns["info_disclosure"] = VulnPattern(
            name="Information Disclosure",
            severity=Severity.LOW,
            description="URLs that may disclose sensitive information",
            path_patterns=[
                r"/phpinfo", r"/info\.php", r"/test\.php",
                r"/server-status", r"/server-info",
                r"/\.git/", r"/\.svn/", r"/\.hg/",
                r"/\.DS_Store", r"/Thumbs\.db",
                r"/crossdomain\.xml", r"/clientaccesspolicy\.xml",
                r"/sitemap\.xml", r"/robots\.txt", r"/humans\.txt",
                r"/security\.txt", r"/\.well-known",
                r"/CHANGELOG", r"/CHANGES", r"/VERSION", r"/README",
                r"/LICENSE", r"/INSTALL", r"/TODO",
                r"/composer\.json", r"/package\.json", r"/bower\.json",
                r"/Gemfile", r"/requirements\.txt", r"/Pipfile",
                r"/yarn\.lock", r"/package-lock\.json",
                r"/Dockerfile", r"/docker-compose",
                r"/\.dockerignore", r"/\.gitignore",
                r"/Makefile", r"/Rakefile", r"/Gruntfile",
                r"/Gulpfile", r"/webpack\.config",
            ],
            extension_patterns=[
                r"\.log$", r"\.logs$", r"\.trace$",
                r"\.debug$", r"\.error$", r"\.err$",
            ],
        )
        
        # Dangerous Extensions
        self.patterns["dangerous_ext"] = VulnPattern(
            name="Dangerous Extensions",
            severity=Severity.INFO,
            description="URLs with potentially interesting file extensions",
            extension_patterns=[
                r"\.php$", r"\.asp$", r"\.aspx$", r"\.jsp$",
                r"\.jspx$", r"\.do$", r"\.action$", r"\.cgi$",
                r"\.pl$", r"\.py$", r"\.rb$", r"\.cfm$",
            ],
        )
        
        # Cloud/Storage
        self.patterns["cloud"] = VulnPattern(
            name="Cloud/Storage",
            severity=Severity.MEDIUM,
            description="Cloud storage and service endpoints",
            path_patterns=[
                r"s3\.amazonaws\.com", r"\.s3\.", r"s3://",
                r"blob\.core\.windows\.net", r"storage\.googleapis\.com",
                r"\.cloudfront\.net", r"\.akamaihd\.net",
                r"/storage/", r"/bucket/", r"/blob/",
            ],
            param_patterns=[
                r"^bucket$", r"^key$", r"^blob$", r"^container$",
                r"^storage$", r"^aws$", r"^s3$", r"^azure$", r"^gcp$",
            ],
        )
        
        # GraphQL specific
        self.patterns["graphql"] = VulnPattern(
            name="GraphQL",
            severity=Severity.MEDIUM,
            description="GraphQL endpoints that may allow introspection",
            path_patterns=[
                r"/graphql", r"/graphiql", r"/gql", r"/query",
                r"/api/graphql", r"/v1/graphql", r"/v2/graphql",
                r"/playground", r"/altair", r"/voyager",
            ],
            param_patterns=[
                r"^query$", r"^mutation$", r"^operationName$",
                r"^variables$",
            ],
        )
        
        # WebSocket
        self.patterns["websocket"] = VulnPattern(
            name="WebSocket",
            severity=Severity.LOW,
            description="WebSocket endpoints",
            path_patterns=[
                r"/ws", r"/wss", r"/websocket", r"/socket",
                r"/socket\.io", r"/sockjs", r"/hub",
                r"/signalr", r"/realtime", r"/live",
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
