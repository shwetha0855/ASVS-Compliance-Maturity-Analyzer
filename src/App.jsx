import { useState, useCallback, useRef, useEffect } from "react";
import { initAstEngine, runAstOnFiles } from "./astEngine";

const API = "http://localhost:3001/api";

const ASVS_DATA = {
  "Encoding and Sanitization": [
    { id: "1.1.1", area: "Encoding and Sanitization Architecture", level: "2", verificationMethod: "SAST", requirement: "Verify that input is decoded or unescaped into a canonical form only once, it is only decoded when encoded data in that form is expected, and that this is done before processing the input further, for example it is not performed after input validation or sanitization." },
    { id: "1.1.2", area: "Encoding and Sanitization Architecture", level: "2", verificationMethod: "SAST", requirement: "Verify that the application performs output encoding and escaping either as a final step before being used by the interpreter for which it is intended or by the interpreter itself." },
    { id: "1.2.1", area: "Injection Prevention", level: "1", verificationMethod: "DAST", requirement: "Verify that output encoding for an HTTP response, HTML document, or XML document is relevant for the context required, such as encoding the relevant characters for HTML elements, HTML attributes, HTML comments, CSS, or HTTP header fields, to avoid changing the message or document structure." },
    { id: "1.2.2", area: "Injection Prevention", level: "1", verificationMethod: "SAST", requirement: "Verify that when dynamically building URLs, untrusted data is encoded according to its context (e.g., URL encoding or base64url encoding for query or path parameters). Ensure that only safe URL protocols are permitted (e.g., disallow javascript: or data:)." },
    { id: "1.2.3", area: "Injection Prevention", level: "1", verificationMethod: "SAST", requirement: "Verify that output encoding or escaping is used when dynamically building JavaScript content (including JSON), to avoid changing the message or document structure (to avoid JavaScript and JSON injection)." },
    { id: "1.2.4", area: "Injection Prevention", level: "1", verificationMethod: "SAST", requirement: "Verify that data selection or database queries (e.g., SQL, HQL, NoSQL, Cypher) use parameterized queries, ORMs, entity frameworks, or are otherwise protected from SQL Injection and other database injection attacks. This is also relevant when writing stored procedures." },
    { id: "1.2.5", area: "Injection Prevention", level: "1", verificationMethod: "SAST", requirement: "Verify that the application protects against OS command injection and that operating system calls use parameterized OS queries or use contextual command line output encoding." },
    { id: "1.2.6", area: "Injection Prevention", level: "2", verificationMethod: "SAST", requirement: "Verify that the application protects against LDAP injection vulnerabilities, or that specific security controls to prevent LDAP injection have been implemented." },
    { id: "1.2.7", area: "Injection Prevention", level: "2", verificationMethod: "SAST", requirement: "Verify that the application is protected against XPath injection attacks by using query parameterization or precompiled queries." },
    { id: "1.2.8", area: "Injection Prevention", level: "2", verificationMethod: "SAST", requirement: "Verify that LaTeX processors are configured securely (such as not using the “- shell-escape”flag) and an allowlist of commands is used to prevent LaTeX injection attacks." },
    { id: "1.2.9", area: "Injection Prevention", level: "2", verificationMethod: "SAST", requirement: "Verify that the application escapes special characters in regular expressions (typically using a backslash) to prevent them from being misinterpreted as metacharacters." },
    { id: "1.2.10", area: "Injection Prevention", level: "3", verificationMethod: "SAST", requirement: "Verify that the application is protected against CSV and Formula Injection. The application must follow the escaping rules defined in RFC 4180 sections 2.6 and 2.7 when exporting CSV content. Additionally, when exporting to CSV or other spreadsheet formats (such as XLS, XLSX, or ODF), special characters (including ‘=’, ‘+’, ‘-’, ‘@’, ‘\\t’(tab), and ‘\\0’(null character)) must be escaped with a single quote if they appear as the first character in a field value." },
    { id: "1.3.1", area: "Sanitization", level: "1", verificationMethod: "SAST", requirement: "Verify that all untrusted HTML input from WYSIWYG editors or similar is sanitized using a well-known and secure HTML sanitization library or framework feature." },
    { id: "1.3.2", area: "Sanitization", level: "1", verificationMethod: "SAST", requirement: "Verify that the application avoids the use of eval() or other dynamic code execution features such as Spring Expression Language (SpEL). Where there is no alternative, any user input being included must be sanitized before being executed." },
    { id: "1.3.3", area: "Sanitization", level: "2", verificationMethod: "SAST", requirement: "Verify that data being passed to a potentially dangerous context is sanitized beforehand to enforce safety measures, such as only allowing characters which are safe for this context and trimming input which is too long." },
    { id: "1.3.4", area: "Sanitization", level: "2", verificationMethod: "SAST", requirement: "Verify that user-supplied Scalable Vector Graphics (SVG) scriptable content is validated or sanitized to contain only tags and attributes (such as draw graphics) that are safe for the application, e.g., do not contain scripts and foreignObject." },
    { id: "1.3.5", area: "Sanitization", level: "2", verificationMethod: "SAST", requirement: "Verify that the application sanitizes or disables user-supplied scriptable or expression template language content, such as Markdown, CSS or XSL stylesheets, BBCode, or similar." },
    { id: "1.3.6", area: "Sanitization", level: "2", verificationMethod: "SAST", requirement: "Verify that the application protects against Server-side Request Forgery (SSRF) attacks, by validating untrusted data against an allowlist of protocols, domains, paths and ports and sanitizing potentially dangerous characters before using the data to call another service." },
    { id: "1.3.7", area: "Sanitization", level: "2", verificationMethod: "SAST", requirement: "Verify that the application protects against template injection attacks by not allowing templates to be built based on untrusted input. Where there is no alternative, any untrusted input being included dynamically during template creation must be sanitized or strictly validated." },
    { id: "1.3.8", area: "Sanitization", level: "2", verificationMethod: "SAST", requirement: "Verify that the application appropriately sanitizes untrusted input before use in Java Naming and Directory Interface (JNDI) queries and that JNDI is configured securely to prevent JNDI injection attacks." },
    { id: "1.3.9", area: "Sanitization", level: "2", verificationMethod: "SAST", requirement: "Verify that the application sanitizes content before it is sent to memcache to prevent injection attacks." },
    { id: "1.3.10", area: "Sanitization", level: "2", verificationMethod: "SAST", requirement: "Verify that format strings which might resolve in an unexpected or malicious way when used are sanitized before being processed." },
    { id: "1.3.11", area: "Sanitization", level: "2", verificationMethod: "SAST", requirement: "Verify that the application sanitizes user input before passing to mail systems to protect against SMTP or IMAP injection." },
    { id: "1.3.12", area: "Sanitization", level: "3", verificationMethod: "SAST", requirement: "Verify that regular expressions are free from elements causing exponential backtracking, and ensure untrusted input is sanitized to mitigate ReDoS or Runaway Regex attacks." },
    { id: "1.4.1", area: "Memory, String, and Unmanaged Code", level: "2", verificationMethod: "SAST", requirement: "Verify that the application uses memory-safe string, safer memory copy and pointer arithmetic to detect or prevent stack, buffer, or heap overflows." },
    { id: "1.4.2", area: "Memory, String, and Unmanaged Code", level: "2", verificationMethod: "SAST", requirement: "Verify that sign, range, and input validation techniques are used to prevent integer overflows." },
    { id: "1.4.3", area: "Memory, String, and Unmanaged Code", level: "2", verificationMethod: "SAST", requirement: "Verify that dynamically allocated memory and resources are released, and that references or pointers to freed memory are removed or set to null to prevent dangling pointers and use-after-free vulnerabilities." },
    { id: "1.5.1", area: "Safe Deserialization", level: "1", verificationMethod: "SAST", requirement: "Verify that the application configures XML parsers to use a restrictive configuration and that unsafe features such as resolving external entities are disabled to prevent XML eXternal Entity (XXE) attacks." },
    { id: "1.5.2", area: "Safe Deserialization", level: "2", verificationMethod: "SAST", requirement: "Verify that deserialization of untrusted data enforces safe input handling, such as using an allowlist of object types or restricting client-defined object types, to prevent deserialization attacks. Deserialization mechanisms that are explicitly defined as insecure must not be used with untrusted input." },
    { id: "1.5.3", area: "Safe Deserialization", level: "3", verificationMethod: "SAST", requirement: "Verify that different parsers used in the application for the same data type (e.g., JSON parsers, XML parsers, URL parsers), perform parsing in a consistent way and use the same character encoding mechanism to avoid issues such as JSON Interoperability vulnerabilities or different URI or file parsing behavior being exploited in Remote File Inclusion (RFI) or Server-side Request Forgery (SSRF) attacks." },
  ],
  "Validation and Business Logic": [
    { id: "2.1.1", area: "Validation and Business Logic Documentation", level: "1", verificationMethod: "Manual", requirement: "Verify that the application’s documentation defines input validation rules for how to check the validity of data items against an expected structure. This could be common data formats such as credit card numbers, email addresses, telephone numbers, or it could be an internal data format." },
    { id: "2.1.2", area: "Validation and Business Logic Documentation", level: "2", verificationMethod: "Manual", requirement: "Verify that the application’s documentation defines how to validate the logical and contextual consistency of combined data items, such as checking that suburb and ZIP code match." },
    { id: "2.1.3", area: "Validation and Business Logic Documentation", level: "2", verificationMethod: "SAST", requirement: "Verify that expectations for business logic limits and validations are documented, including both per-user and globally across the application." },
    { id: "2.2.1", area: "Input Validation", level: "1", verificationMethod: "SAST", requirement: "Verify that input is validated to enforce business or functional expectations for that input. This should either use positive validation against an allow list of values, patterns, and ranges, or be based on comparing the input to an expected structure and logical limits according to predefined rules. For L1, this can focus on input which is used to make specific business or security decisions. For L2 and up, this should apply to all input." },
    { id: "2.2.2", area: "Input Validation", level: "1", verificationMethod: "SAST", requirement: "Verify that the application is designed to enforce input validation at a trusted service layer. While client-side validation improves usability and should be encouraged, it must not be relied upon as a security control." },
    { id: "2.2.3", area: "Input Validation", level: "2", verificationMethod: "SAST", requirement: "Verify that the application ensures that combinations of related data items are reasonable according to the pre-defined rules." },
    { id: "2.3.1", area: "Business Logic Security", level: "1", verificationMethod: "SAST", requirement: "Verify that the application will only process business logic flows for the same user in the expected sequential step order and without skipping steps." },
    { id: "2.3.2", area: "Business Logic Security", level: "2", verificationMethod: "Manual", requirement: "Verify that business logic limits are implemented per the application’s documentation to avoid business logic flaws being exploited." },
    { id: "2.3.3", area: "Business Logic Security", level: "2", verificationMethod: "SAST", requirement: "Verify that transactions are being used at the business logic level such that either a business logic operation succeeds in its entirety or it is rolled back to the previous correct state." },
    { id: "2.3.4", area: "Business Logic Security", level: "2", verificationMethod: "SAST", requirement: "Verify that business logic level locking mechanisms are used to ensure that limited quantity resources (such as theater seats or delivery slots) cannot be double-booked by manipulating the application’s logic." },
    { id: "2.3.5", area: "Business Logic Security", level: "3", verificationMethod: "Manual", requirement: "Verify that high-value business logic flows require multi-user approval to prevent unauthorized or accidental actions. This could include but is not limited to large monetary transfers, contract approvals, access to classified information, or safety overrides in manufacturing." },
    { id: "2.4.1", area: "Anti-automation", level: "2", verificationMethod: "SAST", requirement: "Verify that anti-automation controls are in place to protect against excessive calls to application functions that could lead to data exfiltration, garbage-data creation, quota exhaustion, rate-limit breaches, denial-of-service, or overuse of costly resources." },
    { id: "2.4.2", area: "Anti-automation", level: "3", verificationMethod: "SAST", requirement: "Verify that business logic flows require realistic human timing, preventing excessively rapid transaction submissions." },
  ],
  "Web Frontend Security": [
    { id: "3.1.1", area: "Web Frontend Security Documentation", level: "3", verificationMethod: "Manual", requirement: "Verify that application documentation states the expected security features that browsers using the application must support (such as HTTPS, HTTP Strict Transport Security (HSTS), Content Security Policy (CSP), and other relevant HTTP security mechanisms). It must also define how the application must behave when some of these features are not available (such as warning the user or blocking access)." },
    { id: "3.2.1", area: "Unintended Content Interpretation", level: "1", verificationMethod: "DAST", requirement: "Verify that security controls are in place to prevent browsers from rendering content or functionality in HTTP responses in an incorrect context (e.g., when an API, a user-uploaded file or other resource is requested directly). Possible controls could include: not serving the content unless HTTP request header fields (such as Sec-Fetch-*) indicate it is the correct context, using the sandbox directive of the Content-Security-Policy header field or using the attachment disposition type in the Content-Disposition header field." },
    { id: "3.2.2", area: "Unintended Content Interpretation", level: "1", verificationMethod: "SAST", requirement: "Verify that content intended to be displayed as text, rather than rendered as HTML, is handled using safe rendering functions (such as createTextNode or textContent) to prevent unintended execution of content such as HTML or JavaScript." },
    { id: "3.2.3", area: "Unintended Content Interpretation", level: "3", verificationMethod: "SAST", requirement: "Verify that the application avoids DOM clobbering when using client-side JavaScript by employing explicit variable declarations, performing strict type checking, avoiding storing global variables on the document object, and implementing namespace isolation." },
    { id: "3.3.1", area: "Cookie Setup", level: "1", verificationMethod: "SAST", requirement: "Verify that cookies have the ‘Secure’attribute set, and if the ’__Host-’prefix is not used for the cookie name, the ’__Secure-’prefix must be used for the cookie name." },
    { id: "3.3.2", area: "Cookie Setup", level: "2", verificationMethod: "SAST", requirement: "Verify that each cookie’s ‘SameSite’attribute value is set according to the purpose of the cookie, to limit exposure to user interface redress attacks and browser-based request forgery attacks, commonly known as cross-site request forgery (CSRF)." },
    { id: "3.3.3", area: "Cookie Setup", level: "2", verificationMethod: "SAST", requirement: "Verify that cookies have the ’__Host-’prefix for the cookie name unless they are explicitly designed to be shared with other hosts." },
    { id: "3.3.4", area: "Cookie Setup", level: "2", verificationMethod: "SAST", requirement: "Verify that if the value of a cookie is not meant to be accessible to client-side scripts (such as a session token), the cookie must have the ‘HttpOnly’ attribute set and the same value (e. g. session token) must only be transferred to the client via the ‘Set-Cookie’header field." },
    { id: "3.3.5", area: "Cookie Setup", level: "3", verificationMethod: "SAST", requirement: "Verify that when the application writes a cookie, the cookie name and value length combined are not over 4096 bytes. Overly large cookies will not be stored by the browser and therefore not sent with requests, preventing the user from using application functionality which relies on that cookie." },
    { id: "3.4.1", area: "Browser Security Mechanism Headers", level: "1", verificationMethod: "DAST", requirement: "Verify that a Strict-Transport-Security header field is included on all responses to enforce an HTTP Strict Transport Security (HSTS) policy. A maximum age of at least 1 year must be defined, and for L2 and up, the policy must apply to all subdomains as well." },
    { id: "3.4.2", area: "Browser Security Mechanism Headers", level: "1", verificationMethod: "DAST", requirement: "Verify that the Cross-Origin Resource Sharing (CORS) Access-Control-Allow-Origin header field is a fixed value by the application, or if the Origin HTTP request header field value is used, it is validated against an allowlist of trusted origins. When ’Access-Control-Allow-Origin: *’needs to be used, verify that the response does not include any sensitive information." },
    { id: "3.4.3", area: "Browser Security Mechanism Headers", level: "2", verificationMethod: "DAST", requirement: "Verify that HTTP responses include a Content-Security-Policy response header field which defines directives to ensure the browser only loads and executes trusted content or resources, in order to limit execution of malicious JavaScript. As a minimum, a global policy must be used which includes the directives object-src ‘none’and base-uri ‘none’and defines either an allowlist or uses nonces or hashes. For an L3 application, a per-response policy with nonces or hashes must be defined." },
    { id: "3.4.4", area: "Browser Security Mechanism Headers", level: "2", verificationMethod: "DAST", requirement: "Verify that all HTTP responses contain an ‘X-Content-Type-Options: nosniff’ header field. This instructs browsers not to use content sniffing and MIME type guessing for the given response, and to require the response’s Content-Type header field value to match the destination resource. For example, the response to a request for a style is only accepted if the response’s Content-Type is ‘text/css’. This also enables the use of the Cross-Origin Read Blocking (CORB) functionality by the browser." },
    { id: "3.4.5", area: "Browser Security Mechanism Headers", level: "2", verificationMethod: "Manual", requirement: "Verify that the application sets a referrer policy to prevent leakage of technically sensitive data to third-party services via the ‘Referer’HTTP request header field. This can be done using the Referrer-Policy HTTP response header field or via HTML element attributes. Sensitive data could include path and query data in the URL, and for internal non-public applications also the hostname." },
    { id: "3.4.6", area: "Browser Security Mechanism Headers", level: "2", verificationMethod: "DAST", requirement: "Verify that the web application uses the frame-ancestors directive of the Content-Security-Policy header field for every HTTP response to ensure that it cannot be embedded by default and that embedding of specific resources is allowed only when necessary. Note that the X-Frame-Options header field, although supported by browsers, is obsolete and may not be relied upon." },
    { id: "3.4.7", area: "Browser Security Mechanism Headers", level: "3", verificationMethod: "DAST", requirement: "Verify that the Content-Security-Policy header field specifies a location to report violations." },
    { id: "3.4.8", area: "Browser Security Mechanism Headers", level: "3", verificationMethod: "DAST", requirement: "Verify that all HTTP responses that initiate a document rendering (such as responses with Content-Type text/html), include the Cross-Origin-Opener-Policy header field with the same-origin directive or the same-origin-allow-popups directive as required. This prevents attacks that abuse shared access to Window objects, such as tabnabbing and frame counting." },
    { id: "3.5.1", area: "Browser Origin Separation", level: "1", verificationMethod: "DAST", requirement: "Verify that, if the application does not rely on the CORS preflight mechanism to prevent disallowed cross-origin requests to use sensitive functionality, these requests are validated to ensure they originate from the application itself. This may be done by using and validating anti-forgery tokens or requiring extra HTTP header fields that are not CORS-safelisted request-header fields. This is to defend against browser-based request forgery attacks, commonly known as cross-site request forgery (CSRF)." },
    { id: "3.5.2", area: "Browser Origin Separation", level: "1", verificationMethod: "DAST", requirement: "Verify that, if the application relies on the CORS preflight mechanism to prevent disallowed cross-origin use of sensitive functionality, it is not possible to call the functionality with a request which does not trigger a CORS-preflight request. This may require checking the values of the ‘Origin’ and ‘Content-Type’request header fields or using an extra header field that is not a CORS-safelisted header-field." },
    { id: "3.5.3", area: "Browser Origin Separation", level: "1", verificationMethod: "DAST", requirement: "Verify that HTTP requests to sensitive functionality use appropriate HTTP methods such as POST, PUT, PATCH, or DELETE, and not methods defined by the HTTP specification as “safe”such as HEAD, OPTIONS, or GET. Alternatively, strict validation of the Sec-Fetch-* request header fields can be used to ensure that the request did not originate from an inappropriate cross-origin call, a navigation request, or a resource load (such as an image source) where this is not expected." },
    { id: "3.5.4", area: "Browser Origin Separation", level: "2", verificationMethod: "DAST", requirement: "Verify that separate applications are hosted on different hostnames to leverage the restrictions provided by same-origin policy, including how documents or scripts loaded by one origin can interact with resources from another origin and hostname-based restrictions on cookies." },
    { id: "3.5.5", area: "Browser Origin Separation", level: "2", verificationMethod: "SAST", requirement: "Verify that messages received by the postMessage interface are discarded if the origin of the message is not trusted, or if the syntax of the message is invalid." },
    { id: "3.5.6", area: "Browser Origin Separation", level: "3", verificationMethod: "SAST", requirement: "Verify that JSONP functionality is not enabled anywhere across the application to avoid Cross-Site Script Inclusion (XSSI) attacks." },
    { id: "3.5.7", area: "Browser Origin Separation", level: "3", verificationMethod: "SAST", requirement: "Verify that data requiring authorization is not included in script resource responses, like JavaScript files, to prevent Cross-Site Script Inclusion (XSSI) attacks." },
    { id: "3.5.8", area: "Browser Origin Separation", level: "3", verificationMethod: "DAST", requirement: "Verify that authenticated resources (such as images, videos, scripts, and other documents) can be loaded or embedded on behalf of the user only when intended. This can be accomplished by strict validation of the Sec-Fetch-* HTTP request header fields to ensure that the request did not originate from an inappropriate cross-origin call, or by setting a restrictive Cross-Origin-Resource-Policy HTTP response header field to instruct the browser to block returned content." },
    { id: "3.6.1", area: "External Resource Integrity", level: "3", verificationMethod: "DAST", requirement: "Verify that client-side assets, such as JavaScript libraries, CSS, or web fonts, are only hosted externally (e.g., on a Content Delivery Network) if the resource is static and versioned and Subresource Integrity (SRI) is used to validate the integrity of the asset. If this is not possible, there should be a documented security decision to justify this for each resource." },
    { id: "3.7.1", area: "Other Browser Security Considerations", level: "2", verificationMethod: "SAST", requirement: "Verify that the application only uses client-side technologies which are still supported and considered secure. Examples of technologies which do not meet this requirement include NSAPI plugins, Flash, Shockwave, ActiveX, Silverlight, NACL, or client-side Java applets." },
    { id: "3.7.2", area: "Other Browser Security Considerations", level: "2", verificationMethod: "DAST", requirement: "Verify that the application will only automatically redirect the user to a different hostname or domain (which is not controlled by the application) where the destination appears on an allowlist." },
    { id: "3.7.3", area: "Other Browser Security Considerations", level: "3", verificationMethod: "DAST", requirement: "Verify that the application shows a notification when the user is being redirected to a URL outside of the application’s control, with an option to cancel the navigation." },
    { id: "3.7.4", area: "Other Browser Security Considerations", level: "3", verificationMethod: "DAST", requirement: "Verify that the application’s top-level domain (e.g., site.tld) is added to the public preload list for HTTP Strict Transport Security (HSTS). This ensures that the use of TLS for the application is built directly into the main browsers, rather than relying only on the Strict-Transport-Security response header field." },
    { id: "3.7.5", area: "Other Browser Security Considerations", level: "3", verificationMethod: "SAST", requirement: "Verify that the application behaves as documented (such as warning the user or blocking access) if the browser used to access the application does not support the expected security features." },
  ],
  "API and Web Service": [
    { id: "4.1.1", area: "Generic Web Service Security", level: "1", verificationMethod: "DAST", requirement: "Verify that every HTTP response with a message body contains a Content-Type header field that matches the actual content of the response, including the charset parameter to specify safe character encoding (e.g., UTF-8, ISO-8859-1) according to IANA Media Types, such as “text/”, “/+xml” and “/xml”." },
    { id: "4.1.2", area: "Generic Web Service Security", level: "2", verificationMethod: "DAST", requirement: "Verify that only user-facing endpoints (intended for manual web-browser access) automatically redirect from HTTP to HTTPS, while other services or endpoints do not implement transparent redirects. This is to avoid a situation where a client is erroneously sending unencrypted HTTP requests, but since the requests are being automatically redirected to HTTPS, the leakage of sensitive data goes undiscovered." },
    { id: "4.1.3", area: "Generic Web Service Security", level: "2", verificationMethod: "SAST", requirement: "Verify that any HTTP header field used by the application and set by an intermediary layer, such as a load balancer, a web proxy, or a backend-for-frontend service, cannot be overridden by the end-user. Example headers might include X-Real-IP, X-Forwarded-*, or X-User-ID." },
    { id: "4.1.4", area: "Generic Web Service Security", level: "3", verificationMethod: "SAST", requirement: "Verify that only HTTP methods that are explicitly supported by the application or its API (including OPTIONS during preflight requests) can be used and that unused methods are blocked." },
    { id: "4.1.5", area: "Generic Web Service Security", level: "3", verificationMethod: "SAST", requirement: "Verify that per-message digital signatures are used to provide additional assurance on top of transport protections for requests or transactions which are highly sensitive or which traverse a number of systems." },
    { id: "4.2.1", area: "HTTP Message Structure Validation", level: "2", verificationMethod: "SAST", requirement: "Verify that all application components (including load balancers, firewalls, and application servers) determine boundaries of incoming HTTP messages using the appropriate mechanism for the HTTP version to prevent HTTP request smuggling. In HTTP/1.x, if a Transfer-Encoding header field is present, the Content-Length header must be ignored per RFC 2616. When using HTTP/2 or HTTP/3, if a Content-Length header field is present, the receiver must ensure that it is consistent with the length of the DATA frames." },
    { id: "4.2.2", area: "HTTP Message Structure Validation", level: "3", verificationMethod: "SAST", requirement: "Verify that when generating HTTP messages, the Content-Length header field does not conflict with the length of the content as determined by the framing of the HTTP protocol, in order to prevent request smuggling attacks." },
    { id: "4.2.3", area: "HTTP Message Structure Validation", level: "3", verificationMethod: "SAST", requirement: "Verify that the application does not send nor accept HTTP/2 or HTTP/3 messages with connection-specific header fields such as Transfer-Encoding to prevent response splitting and header injection attacks." },
    { id: "4.2.4", area: "HTTP Message Structure Validation", level: "3", verificationMethod: "SAST", requirement: "Verify that the application only accepts HTTP/2 and HTTP/3 requests where the header fields and values do not contain any CR (\\r), LF (\\n), or CRLF (\\r\\n) sequences, to prevent header injection attacks." },
    { id: "4.2.5", area: "HTTP Message Structure Validation", level: "3", verificationMethod: "SAST", requirement: "Verify that, if the application (backend or frontend) builds and sends requests, it uses validation, sanitization, or other mechanisms to avoid creating URIs (such as for API calls) or HTTP request header fields (such as Authorization or Cookie), which are too long to be accepted by the receiving component. This could cause a denial of service, such as when sending an overly long request (e.g., a long cookie header field), which results in the server always responding with an error status." },
    { id: "4.3.1", area: "GraphQL", level: "2", verificationMethod: "SAST", requirement: "Verify that a query allowlist, depth limiting, amount limiting, or query cost analysis is used to prevent GraphQL or data layer expression Denial of Service (DoS) as a result of expensive, nested queries." },
    { id: "4.3.2", area: "GraphQL", level: "2", verificationMethod: "SAST", requirement: "Verify that GraphQL introspection queries are disabled in the production environment unless the GraphQL API is meant to be used by other parties." },
    { id: "4.4.1", area: "WebSocket", level: "1", verificationMethod: "DAST", requirement: "Verify that WebSocket over TLS (WSS) is used for all WebSocket connections." },
    { id: "4.4.2", area: "WebSocket", level: "2", verificationMethod: "DAST", requirement: "Verify that, during the initial HTTP WebSocket handshake, the Origin header field is checked against a list of origins allowed for the application." },
    { id: "4.4.3", area: "WebSocket", level: "2", verificationMethod: "SAST", requirement: "Verify that, if the application’s standard session management cannot be used, dedicated tokens are being used for this, which comply with the relevant Session Management security requirements." },
    { id: "4.4.4", area: "WebSocket", level: "2", verificationMethod: "DAST", requirement: "Verify that dedicated WebSocket session management tokens are initially obtained or validated through the previously authenticated HTTPS session when transitioning an existing HTTPS session to a WebSocket channel." },
  ],
  "File Handling": [
    { id: "5.1.1", area: "File Handling Documentation", level: "2", verificationMethod: "Manual", requirement: "Verify that the documentation defines the permitted file types, expected file extensions, and maximum size (including unpacked size) for each upload feature. Additionally, ensure that the documentation specifies how files are made safe for end-users to download and process, such as how the application behaves when a malicious file is detected." },
    { id: "5.2.1", area: "File Upload and Content", level: "1", verificationMethod: "SAST", requirement: "Verify that the application will only accept files of a size which it can process without causing a loss of performance or a denial of service attack." },
    { id: "5.2.2", area: "File Upload and Content", level: "1", verificationMethod: "SAST", requirement: "Verify that when the application accepts a file, either on its own or within an archive such as a zip file, it checks if the file extension matches an expected file extension and validates that the contents correspond to the type represented by the extension. This includes, but is not limited to, checking the initial ‘magic bytes’, performing image re-writing, and using specialized libraries for file content validation. For L1, this can focus just on files which are used to make specific business or security decisions. For L2 and up, this must apply to all files being accepted." },
    { id: "5.2.3", area: "File Upload and Content", level: "2", verificationMethod: "SAST", requirement: "Verify that the application checks compressed files (e.g., zip, gz, docx, odt) against maximum allowed uncompressed size and against maximum number of files before uncompressing the file." },
    { id: "5.2.4", area: "File Upload and Content", level: "3", verificationMethod: "SAST", requirement: "Verify that a file size quota and maximum number of files per user are enforced to ensure that a single user cannot fill up the storage with too many files, or excessively large files." },
    { id: "5.2.5", area: "File Upload and Content", level: "3", verificationMethod: "SAST", requirement: "Verify that the application does not allow uploading compressed files containing symlinks unless this is specifically required (in which case it will be necessary to enforce an allowlist of the files that can be symlinked to)." },
    { id: "5.2.6", area: "File Upload and Content", level: "3", verificationMethod: "SAST", requirement: "Verify that the application rejects uploaded images with a pixel size larger than the maximum allowed, to prevent pixel flood attacks." },
    { id: "5.3.1", area: "File Storage", level: "1", verificationMethod: "SAST", requirement: "Verify that files uploaded or generated by untrusted input and stored in a public folder, are not executed as server-side program code when accessed directly with an HTTP request." },
    { id: "5.3.2", area: "File Storage", level: "1", verificationMethod: "SAST", requirement: "Verify that when the application creates file paths for file operations, instead of user-submitted filenames, it uses internally generated or trusted data, or if user-submitted filenames or file metadata must be used, strict validation and sanitization must be applied. This is to protect against path traversal, local or remote file inclusion (LFI, RFI), and server-side request forgery (SSRF) attacks." },
    { id: "5.3.3", area: "File Storage", level: "3", verificationMethod: "SAST", requirement: "Verify that server-side file processing, such as file decompression, ignores user-provided path information to prevent vulnerabilities such as zip slip." },
    { id: "5.4.1", area: "File Download", level: "2", verificationMethod: "SAST", requirement: "Verify that the application validates or ignores user-submitted filenames, including in a JSON, JSONP, or URL parameter and specifies a filename in the Content-Disposition header field in the response." },
    { id: "5.4.2", area: "File Download", level: "2", verificationMethod: "DAST", requirement: "Verify that file names served (e.g., in HTTP response header fields or email attachments) are encoded or sanitized (e.g., following RFC 6266) to preserve document structure and prevent injection attacks." },
    { id: "5.4.3", area: "File Download", level: "2", verificationMethod: "SAST", requirement: "Verify that files obtained from untrusted sources are scanned by antivirus scanners to prevent serving of known malicious content." },
  ],
  "Authentication": [
    { id: "6.1.1", area: "Authentication Documentation", level: "1", verificationMethod: "Manual", requirement: "Verify that application documentation defines how controls such as rate limiting, anti-automation, and adaptive response, are used to defend against attacks such as credential stuffing and password brute force. The documentation must make clear how these controls are configured and prevent malicious account lockout." },
    { id: "6.1.2", area: "Authentication Documentation", level: "2", verificationMethod: "SAST", requirement: "Verify that a list of context-specific words is documented in order to prevent their use in passwords. The list could include permutations of organization names, product names, system identifiers, project codenames, department or role names, and similar." },
    { id: "6.1.3", area: "Authentication Documentation", level: "2", verificationMethod: "SAST", requirement: "Verify that, if the application includes multiple authentication pathways, these are all documented together with the security controls and authentication strength which must be consistently enforced across them." },
    { id: "6.2.1", area: "Password Security", level: "1", verificationMethod: "SAST", requirement: "Verify that user set passwords are at least 8 characters in length although a minimum of 15 characters is strongly recommended." },
    { id: "6.2.2", area: "Password Security", level: "1", verificationMethod: "SAST", requirement: "Verify that users can change their password." },
    { id: "6.2.3", area: "Password Security", level: "1", verificationMethod: "SAST", requirement: "Verify that password change functionality requires the user’s current and new password." },
    { id: "6.2.4", area: "Password Security", level: "1", verificationMethod: "SAST", requirement: "Verify that passwords submitted during account registration or password change are checked against an available set of, at least, the top 3000 passwords which match the application’s password policy, e.g. minimum length." },
    { id: "6.2.5", area: "Password Security", level: "1", verificationMethod: "SAST", requirement: "Verify that passwords of any composition can be used, without rules limiting the type of characters permitted. There must be no requirement for a minimum number of upper or lower case characters, numbers, or special characters." },
    { id: "6.2.6", area: "Password Security", level: "1", verificationMethod: "SAST", requirement: "Verify that password input fields use type=password to mask the entry. Applications may allow the user to temporarily view the entire masked password, or the last typed character of the password." },
    { id: "6.2.7", area: "Password Security", level: "1", verificationMethod: "SAST", requirement: "Verify that “paste”functionality, browser password helpers, and external password managers are permitted." },
    { id: "6.2.8", area: "Password Security", level: "1", verificationMethod: "SAST", requirement: "Verify that the application verifies the user’s password exactly as received from the user, without any modifications such as truncation or case transformation." },
    { id: "6.2.9", area: "Password Security", level: "2", verificationMethod: "SAST", requirement: "Verify that passwords of at least 64 characters are permitted." },
    { id: "6.2.10", area: "Password Security", level: "2", verificationMethod: "SAST", requirement: "Verify that a user’s password stays valid until it is discovered to be compromised or the user rotates it. The application must not require periodic credential rotation." },
    { id: "6.2.11", area: "Password Security", level: "2", verificationMethod: "SAST", requirement: "Verify that the documented list of context specific words is used to prevent easy to guess passwords being created." },
    { id: "6.2.12", area: "Password Security", level: "2", verificationMethod: "SAST", requirement: "Verify that passwords submitted during account registration or password changes are checked against a set of breached passwords." },
    { id: "6.3.1", area: "General Authentication Security", level: "1", verificationMethod: "Manual", requirement: "Verify that controls to prevent attacks such as credential stuffing and password brute force are implemented according to the application’s security documentation." },
    { id: "6.3.2", area: "General Authentication Security", level: "1", verificationMethod: "SAST", requirement: "Verify that default user accounts (e.g., “root”, “admin”, or “sa”) are not present in the application or are disabled." },
    { id: "6.3.3", area: "General Authentication Security", level: "2", verificationMethod: "SAST", requirement: "Verify that either a multi-factor authentication mechanism or a combination of single-factor authentication mechanisms, must be used in order to access the application. For L3, one of the factors must be a hardware-based authentication mechanism which provides compromise and impersonation resistance against phishing attacks while verifying the intent to authenticate by requiring a user-initiated action (such as a button press on a FIDO hardware key or a mobile phone). Relaxing any of the considerations in this requirement requires a fully documented rationale and a comprehensive set of mitigating controls." },
    { id: "6.3.4", area: "General Authentication Security", level: "2", verificationMethod: "SAST", requirement: "Verify that, if the application includes multiple authentication pathways, there are no undocumented pathways and that security controls and authentication strength are enforced consistently." },
    { id: "6.3.5", area: "General Authentication Security", level: "3", verificationMethod: "SAST", requirement: "Verify that users are notified of suspicious authentication attempts (successful or unsuccessful). This may include authentication attempts from an unusual location or client, partially successful authentication (only one of multiple factors), an authentication attempt after a long period of inactivity or a successful authentication after several unsuccessful attempts." },
    { id: "6.3.6", area: "General Authentication Security", level: "3", verificationMethod: "SAST", requirement: "Verify that email is not used as either a single-factor or multi-factor authentication mechanism." },
    { id: "6.3.7", area: "General Authentication Security", level: "3", verificationMethod: "SAST", requirement: "Verify that users are notified after updates to authentication details, such as credential resets or modification of the username or email address." },
    { id: "6.3.8", area: "General Authentication Security", level: "3", verificationMethod: "DAST", requirement: "Verify that valid users cannot be deduced from failed authentication challenges, such as by basing on error messages, HTTP response codes, or different response times. Registration and forgot password functionality must also have this protection." },
    { id: "6.4.1", area: "Authentication Factor Lifecycle and Recovery", level: "1", verificationMethod: "SAST", requirement: "Verify that system generated initial passwords or activation codes are securely randomly generated, follow the existing password policy, and expire after a short period of time or after they are initially used. These initial secrets must not be permitted to become the long term password." },
    { id: "6.4.2", area: "Authentication Factor Lifecycle and Recovery", level: "1", verificationMethod: "SAST", requirement: "Verify that password hints or knowledge-based authentication (so-called “secret questions”) are not present." },
    { id: "6.4.3", area: "Authentication Factor Lifecycle and Recovery", level: "2", verificationMethod: "Manual", requirement: "Verify that a secure process for resetting a forgotten password is implemented, that does not bypass any enabled multi-factor authentication mechanisms." },
    { id: "6.4.4", area: "Authentication Factor Lifecycle and Recovery", level: "2", verificationMethod: "SAST", requirement: "Verify that if a multi-factor authentication factor is lost, evidence of identity proofing is performed at the same level as during enrollment." },
    { id: "6.4.5", area: "Authentication Factor Lifecycle and Recovery", level: "3", verificationMethod: "SAST", requirement: "Verify that renewal instructions for authentication mechanisms which expire are sent with enough time to be carried out before the old authentication mechanism expires, configuring automated reminders if necessary." },
    { id: "6.4.6", area: "Authentication Factor Lifecycle and Recovery", level: "3", verificationMethod: "Manual", requirement: "Verify that administrative users can initiate the password reset process for the user, but that this does not allow them to change or choose the user’s password. This prevents a situation where they know the user’s password." },
    { id: "6.5.1", area: "General Multi-factor authentication requirements", level: "2", verificationMethod: "SAST", requirement: "Verify that lookup secrets, out-of-band authentication requests or codes, and time-based one-time passwords (TOTPs) are only successfully usable once." },
    { id: "6.5.2", area: "General Multi-factor authentication requirements", level: "2", verificationMethod: "SAST", requirement: "Verify that, when being stored in the application’s backend, lookup secrets with less than 112 bits of entropy (19 random alphanumeric characters or 34 random digits) are hashed with an approved password storage hashing algorithm that incorporates a 32-bit random salt. A standard hash function can be used if the secret has 112 bits of entropy or more." },
    { id: "6.5.3", area: "General Multi-factor authentication requirements", level: "2", verificationMethod: "SAST", requirement: "Verify that lookup secrets, out-of-band authentication code, and time-based one-time password seeds, are generated using a Cryptographically Secure Pseudorandom Number Generator (CSPRNG) to avoid predictable values." },
    { id: "6.5.4", area: "General Multi-factor authentication requirements", level: "2", verificationMethod: "SAST", requirement: "Verify that lookup secrets and out-of-band authentication codes have a minimum of 20 bits of entropy (typically 4 random alphanumeric characters or 6 random digits is sufficient)." },
    { id: "6.5.5", area: "General Multi-factor authentication requirements", level: "2", verificationMethod: "SAST", requirement: "Verify that out-of-band authentication requests, codes, or tokens, as well as time-based one-time passwords (TOTPs) have a defined lifetime. Out of band requests must have a maximum lifetime of 10 minutes and for TOTP a maximum lifetime of 30 seconds." },
    { id: "6.5.6", area: "General Multi-factor authentication requirements", level: "3", verificationMethod: "SAST", requirement: "Verify that any authentication factor (including physical devices) can be revoked in case of theft or other loss." },
    { id: "6.5.7", area: "General Multi-factor authentication requirements", level: "3", verificationMethod: "SAST", requirement: "Verify that biometric authentication mechanisms are only used as secondary factors together with either something you have or something you know." },
    { id: "6.5.8", area: "General Multi-factor authentication requirements", level: "3", verificationMethod: "SAST", requirement: "Verify that time-based one-time passwords (TOTPs) are checked based on a time source from a trusted service and not from an untrusted or client provided time." },
    { id: "6.6.1", area: "Out-of-Band authentication mechanisms", level: "2", verificationMethod: "SAST", requirement: "Verify that authentication mechanisms using the Public Switched Telephone Network (PSTN) to deliver One-time Passwords (OTPs) via phone or SMS are offered only when the phone number has previously been validated, alternate stronger methods (such as Time based One-time Passwords) are also offered, and the service provides information on their security risks to users. For L3 applications, phone and SMS must not be available as options." },
    { id: "6.6.2", area: "Out-of-Band authentication mechanisms", level: "2", verificationMethod: "SAST", requirement: "Verify that out-of-band authentication requests, codes, or tokens are bound to the original authentication request for which they were generated and are not usable for a previous or subsequent one." },
    { id: "6.6.3", area: "Out-of-Band authentication mechanisms", level: "2", verificationMethod: "DAST", requirement: "Verify that a code based out-of-band authentication mechanism is protected against brute force attacks by using rate limiting. Consider also using a code with at least 64 bits of entropy." },
    { id: "6.6.4", area: "Out-of-Band authentication mechanisms", level: "3", verificationMethod: "DAST", requirement: "Verify that, where push notifications are used for multi-factor authentication, rate limiting is used to prevent push bombing attacks. Number matching may also mitigate this risk." },
    { id: "6.7.1", area: "Cryptographic authentication mechanism", level: "3", verificationMethod: "DAST", requirement: "Verify that the certificates used to verify cryptographic authentication assertions are stored in a way protects them from modification." },
    { id: "6.7.2", area: "Cryptographic authentication mechanism", level: "3", verificationMethod: "SAST", requirement: "Verify that the challenge nonce is at least 64 bits in length, and statistically unique or unique over the lifetime of the cryptographic device." },
    { id: "6.8.1", area: "Authentication with an Identity Provider", level: "2", verificationMethod: "SAST", requirement: "Verify that, if the application supports multiple identity providers (IdPs), the user’s identity cannot be spoofed via another supported identity provider (eg. by using the same user identifier). The standard mitigation would be for the application to register and identify the user using a combination of the IdP ID (serving as a namespace) and the user’s ID in the IdP." },
    { id: "6.8.2", area: "Authentication with an Identity Provider", level: "2", verificationMethod: "SAST", requirement: "Verify that the presence and integrity of digital signatures on authentication assertions (for example on JWTs or SAML assertions) are always validated, rejecting any assertions that are unsigned or have invalid signatures." },
    { id: "6.8.3", area: "Authentication with an Identity Provider", level: "2", verificationMethod: "SAST", requirement: "Verify that SAML assertions are uniquely processed and used only once within the validity period to prevent replay attacks." },
    { id: "6.8.4", area: "Authentication with an Identity Provider", level: "2", verificationMethod: "SAST", requirement: "Verify that, if an application uses a separate Identity Provider (IdP) and expects specific authentication strength, methods, or recentness for specific functions, the application verifies this using the information returned by the IdP. For example, if OIDC is used, this might be achieved by validating ID Token claims such as ‘acr’, ‘amr’, and ‘auth_time’(if present). If the IdP does not provide this information, the application must have a documented fallback approach that assumes that the minimum strength authentication mechanism was used (for example, single-factor authentication using username and password)." },
  ],
  "Session Management": [
    { id: "7.1.1", area: "Session Management Documentation", level: "2", verificationMethod: "Manual", requirement: "Verify that the user’s session inactivity timeout and absolute maximum session lifetime are documented, are appropriate in combination with other controls, and that the documentation includes justification for any deviations from NIST SP 800-63B re-authentication requirements." },
    { id: "7.1.2", area: "Session Management Documentation", level: "2", verificationMethod: "Manual", requirement: "Verify that the documentation defines how many concurrent (parallel) sessions are allowed for one account as well as the intended behaviors and actions to be taken when the maximum number of active sessions is reached." },
    { id: "7.1.3", area: "Session Management Documentation", level: "2", verificationMethod: "SAST", requirement: "Verify that all systems that create and manage user sessions as part of a federated identity management ecosystem (such as SSO systems) are documented along with controls to coordinate session lifetimes, termination, and any other conditions that require re-authentication." },
    { id: "7.2.1", area: "Fundamental Session Management Security", level: "1", verificationMethod: "SAST", requirement: "Verify that the application performs all session token verification using a trusted, backend service." },
    { id: "7.2.2", area: "Fundamental Session Management Security", level: "1", verificationMethod: "SAST", requirement: "Verify that the application uses either self-contained or reference tokens that are dynamically generated for session management, i.e. not using static API secrets and keys." },
    { id: "7.2.3", area: "Fundamental Session Management Security", level: "1", verificationMethod: "SAST", requirement: "Verify that if reference tokens are used to represent user sessions, they are unique and generated using a cryptographically secure pseudo-random number generator (CSPRNG) and possess at least 128 bits of entropy." },
    { id: "7.2.4", area: "Fundamental Session Management Security", level: "1", verificationMethod: "SAST", requirement: "Verify that the application generates a new session token on user authentication, including re-authentication, and terminates the current session token." },
    { id: "7.3.1", area: "Session Timeout", level: "2", verificationMethod: "DAST", requirement: "Verify that there is an inactivity timeout such that re-authentication is enforced according to risk analysis and documented security decisions." },
    { id: "7.3.2", area: "Session Timeout", level: "2", verificationMethod: "SAST", requirement: "Verify that there is an absolute maximum session lifetime such that re-authentication is enforced according to risk analysis and documented security decisions." },
    { id: "7.4.1", area: "Session Termination", level: "1", verificationMethod: "SAST", requirement: "Verify that when session termination is triggered (such as logout or expiration), the application disallows any further use of the session. For reference tokens or stateful sessions, this means invalidating the session data at the application backend. Applications using self-contained tokens will need a solution such as maintaining a list of terminated tokens, disallowing tokens produced before a per-user date and time or rotating a per-user signing key." },
    { id: "7.4.2", area: "Session Termination", level: "1", verificationMethod: "SAST", requirement: "Verify that the application terminates all active sessions when a user account is disabled or deleted (such as an employee leaving the company)." },
    { id: "7.4.3", area: "Session Termination", level: "2", verificationMethod: "SAST", requirement: "Verify that the application gives the option to terminate all other active sessions after a successful change or removal of any authentication factor (including password change via reset or recovery and, if present, an MFA settings update)." },
    { id: "7.4.4", area: "Session Termination", level: "2", verificationMethod: "SAST", requirement: "Verify that all pages that require authentication have easy and visible access to logout functionality." },
    { id: "7.4.5", area: "Session Termination", level: "2", verificationMethod: "SAST", requirement: "Verify that application administrators are able to terminate active sessions for an individual user or for all users." },
    { id: "7.5.1", area: "Defenses Against Session Abuse", level: "2", verificationMethod: "SAST", requirement: "Verify that the application requires full re-authentication before allowing modifications to sensitive account attributes which may affect authentication such as email address, phone number, MFA configuration, or other information used in account recovery." },
    { id: "7.5.2", area: "Defenses Against Session Abuse", level: "2", verificationMethod: "SAST", requirement: "Verify that users are able to view and (having authenticated again with at least one factor) terminate any or all currently active sessions." },
    { id: "7.5.3", area: "Defenses Against Session Abuse", level: "3", verificationMethod: "SAST", requirement: "Verify that the application requires further authentication with at least one factor or secondary verification before performing highly sensitive transactions or operations." },
    { id: "7.6.1", area: "Federated Re-authentication", level: "2", verificationMethod: "SAST", requirement: "Verify that session lifetime and termination between Relying Parties (RPs) and Identity Providers (IdPs) behave as documented, requiring re-authentication as necessary such as when the maximum time between IdP authentication events is reached." },
    { id: "7.6.2", area: "Federated Re-authentication", level: "2", verificationMethod: "SAST", requirement: "Verify that creation of a session requires either the user’s consent or an explicit action, preventing the creation of new application sessions without user interaction." },
  ],
  "Authorization": [
    { id: "8.1.1", area: "Authorization Documentation", level: "1", verificationMethod: "Manual", requirement: "Verify that authorization documentation defines rules for restricting function-level and data-specific access based on consumer permissions and resource attributes." },
    { id: "8.1.2", area: "Authorization Documentation", level: "2", verificationMethod: "Manual", requirement: "Verify that authorization documentation defines rules for field-level access restrictions (both read and write) based on consumer permissions and resource attributes. Note that these rules might depend on other attribute values of the relevant data object, such as state or status." },
    { id: "8.1.3", area: "Authorization Documentation", level: "3", verificationMethod: "Manual", requirement: "Verify that the application’s documentation defines the environmental and contextual attributes (including but not limited to, time of day, user location, IP address, or device) that are used in the application to make security decisions, including those pertaining to authentication and authorization." },
    { id: "8.1.4", area: "Authorization Documentation", level: "3", verificationMethod: "Manual", requirement: "Verify that authentication and authorization documentation defines how environmental and contextual factors are used in decision-making, in addition to function-level, data-specific, and field-level authorization. This should include the attributes evaluated, thresholds for risk, and actions taken (e.g., allow, challenge, deny, step-up authentication)." },
    { id: "8.2.1", area: "General Authorization Design", level: "1", verificationMethod: "SAST", requirement: "Verify that the application ensures that function-level access is restricted to consumers with explicit permissions." },
    { id: "8.2.2", area: "General Authorization Design", level: "1", verificationMethod: "SAST", requirement: "Verify that the application ensures that data-specific access is restricted to consumers with explicit permissions to specific data items to mitigate insecure direct object reference (IDOR) and broken object level authorization (BOLA)." },
    { id: "8.2.3", area: "General Authorization Design", level: "2", verificationMethod: "SAST", requirement: "Verify that the application ensures that field-level access is restricted to consumers with explicit permissions to specific fields to mitigate broken object property level authorization (BOPLA)." },
    { id: "8.2.4", area: "General Authorization Design", level: "3", verificationMethod: "Manual", requirement: "Verify that adaptive security controls based on a consumer’s environmental and contextual attributes (such as time of day, location, IP address, or device) are implemented for authentication and authorization decisions, as defined in the application’s documentation. These controls must be applied when the consumer tries to start a new session and also during an existing session." },
    { id: "8.3.1", area: "Operation Level Authorization", level: "1", verificationMethod: "SAST", requirement: "Verify that the application enforces authorization rules at a trusted service layer and doesn’t rely on controls that an untrusted consumer could manipulate, such as client-side JavaScript." },
    { id: "8.3.2", area: "Operation Level Authorization", level: "3", verificationMethod: "SAST", requirement: "Verify that changes to values on which authorization decisions are made are applied immediately. Where changes cannot be applied immediately, (such as when relying on data in self-contained tokens), there must be mitigating controls to alert when a consumer performs an action when they are no longer authorized to do so and revert the change. Note that this alternative would not mitigate information leakage." },
    { id: "8.3.3", area: "Operation Level Authorization", level: "3", verificationMethod: "SAST", requirement: "Verify that access to an object is based on the originating subject’s (e.g. consumer’s) permissions, not on the permissions of any intermediary or service acting on their behalf. For example, if a consumer calls a web service using a self-contained token for authentication, and the service then requests data from a different service, the second service will use the consumer’s token, rather than a machine-to-machine token from the first service, to make permission decisions." },
    { id: "8.4.1", area: "Other Authorization Considerations", level: "2", verificationMethod: "SAST", requirement: "Verify that multi-tenant applications use cross-tenant controls to ensure consumer operations will never affect tenants with which they do not have permissions to interact." },
    { id: "8.4.2", area: "Other Authorization Considerations", level: "3", verificationMethod: "SAST", requirement: "Verify that access to administrative interfaces incorporates multiple layers of security, including continuous consumer identity verification, device security posture assessment, and contextual risk analysis, ensuring that network location or trusted endpoints are not the sole factors for authorization even though they may reduce the likelihood of unauthorized access." },
  ],
  "Self-contained Tokens": [
    { id: "9.1.1", area: "Token source and integrity", level: "1", verificationMethod: "SAST", requirement: "Verify that self-contained tokens are validated using their digital signature or MAC to protect against tampering before accepting the token’s contents." },
    { id: "9.1.2", area: "Token source and integrity", level: "1", verificationMethod: "SAST", requirement: "Verify that only algorithms on an allowlist can be used to create and verify self-contained tokens, for a given context. The allowlist must include the permitted algorithms, ideally only either symmetric or asymmetric algorithms, and must not include the ‘None’algorithm. If both symmetric and asymmetric must be supported, additional controls will be needed to prevent key confusion." },
    { id: "9.1.3", area: "Token source and integrity", level: "1", verificationMethod: "SAST", requirement: "Verify that key material that is used to validate self-contained tokens is from trusted pre-configured sources for the token issuer, preventing attackers from specifying untrusted sources and keys. For JWTs and other JWS structures, headers such as ‘jku’, ‘x5u’, and ‘jwk’must be validated against an allowlist of trusted sources." },
    { id: "9.2.1", area: "Token content", level: "1", verificationMethod: "SAST", requirement: "Verify that, if a validity time span is present in the token data, the token and its content are accepted only if the verification time is within this validity time span. For example, for JWTs, the claims ‘nbf’and ‘exp’must be verified." },
    { id: "9.2.2", area: "Token content", level: "2", verificationMethod: "SAST", requirement: "Verify that the service receiving a token validates the token to be the correct type and is meant for the intended purpose before accepting the token’s contents. For example, only access tokens can be accepted for authorization decisions and only ID Tokens can be used for proving user authentication." },
    { id: "9.2.3", area: "Token content", level: "2", verificationMethod: "SAST", requirement: "Verify that the service only accepts tokens which are intended for use with that service (audience). For JWTs, this can be achieved by validating the ‘aud’ claim against an allowlist defined in the service." },
    { id: "9.2.4", area: "Token content", level: "2", verificationMethod: "SAST", requirement: "Verify that, if a token issuer uses the same private key for issuing tokens to different audiences, the issued tokens contain an audience restriction that uniquely identifies the intended audiences. This will prevent a token from being reused with an unintended audience. If the audience identifier is dynamically provisioned, the token issuer must validate these audiences in order to make sure that they do not result in audience impersonation." },
  ],
  "OAuth and OIDC": [
    { id: "10.1.1", area: "Generic OAuth and OIDC Security", level: "2", verificationMethod: "SAST", requirement: "Verify that tokens are only sent to components that strictly need them. For example, when using a backend-for-frontend pattern for browser-based JavaScript applications, access and refresh tokens shall only be accessible for the backend." },
    { id: "10.1.2", area: "Generic OAuth and OIDC Security", level: "2", verificationMethod: "SAST", requirement: "Verify that the client only accepts values from the authorization server (such as the authorization code or ID Token) if these values result from an authorization flow that was initiated by the same user agent session and transaction. This requires that client-generated secrets, such as the proof key for code exchange (PKCE) ‘code_verifier’, ‘state’or OIDC ‘nonce’, are not guessable, are specific to the transaction, and are securely bound to both the client and the user agent session in which the transaction was started." },
    { id: "10.2.1", area: "OAuth Client", level: "2", verificationMethod: "SAST", requirement: "Verify that, if the code flow is used, the OAuth client has protection against browser-based request forgery attacks, commonly known as cross-site request forgery (CSRF), which trigger token requests, either by using proof key for code exchange (PKCE) functionality or checking the ‘state’parameter that was sent in the authorization request." },
    { id: "10.2.2", area: "OAuth Client", level: "2", verificationMethod: "SAST", requirement: "Verify that, if the OAuth client can interact with more than one authorization server, it has a defense against mix-up attacks. For example, it could require that the authorization server return the ‘iss’parameter value and validate it in the authorization response and the token response." },
    { id: "10.2.3", area: "OAuth Client", level: "3", verificationMethod: "SAST", requirement: "Verify that the OAuth client only requests the required scopes (or other authorization parameters) in requests to the authorization server." },
    { id: "10.3.1", area: "OAuth Resource Server", level: "2", verificationMethod: "SAST", requirement: "Verify that the resource server only accepts access tokens that are intended for use with that service (audience). The audience may be included in a structured access token (such as the ‘aud’claim in JWT), or it can be checked using the token introspection endpoint." },
    { id: "10.3.2", area: "OAuth Resource Server", level: "2", verificationMethod: "SAST", requirement: "Verify that the resource server enforces authorization decisions based on claims from the access token that define delegated authorization. If claims such as ‘sub’, ‘scope’, and ‘authorization_details’are present, they must be part of the decision." },
    { id: "10.3.3", area: "OAuth Resource Server", level: "2", verificationMethod: "SAST", requirement: "Verify that if an access control decision requires identifying a unique user from an access token (JWT or related token introspection response), the resource server identifies the user from claims that cannot be reassigned to other users. Typically, it means using a combination of ‘iss’and ‘sub’claims." },
    { id: "10.3.4", area: "OAuth Resource Server", level: "2", verificationMethod: "SAST", requirement: "Verify that, if the resource server requires specific authentication strength, methods, or recentness, it verifies that the presented access token satisfies these constraints. For example, if present, using the OIDC ‘acr’, ‘amr’and ‘auth_time’claims respectively." },
    { id: "10.3.5", area: "OAuth Resource Server", level: "3", verificationMethod: "DAST", requirement: "Verify that the resource server prevents the use of stolen access tokens or replay of access tokens (from unauthorized parties) by requiring sender-constrained access tokens, either Mutual TLS for OAuth 2 or OAuth 2 Demonstration of Proof of Possession (DPoP)." },
    { id: "10.4.1", area: "OAuth Authorization Server", level: "1", verificationMethod: "DAST", requirement: "Verify that the authorization server validates redirect URIs based on a client-specific allowlist of pre-registered URIs using exact string comparison." },
    { id: "10.4.2", area: "OAuth Authorization Server", level: "1", verificationMethod: "SAST", requirement: "Verify that, if the authorization server returns the authorization code in the authorization response, it can be used only once for a token request. For the second valid request with an authorization code that has already been used to issue an access token, the authorization server must reject a token request and revoke any issued tokens related to the authorization code." },
    { id: "10.4.3", area: "OAuth Authorization Server", level: "1", verificationMethod: "SAST", requirement: "Verify that the authorization code is short-lived. The maximum lifetime can be up to 10 minutes for L1 and L2 applications and up to 1 minute for L3 applications." },
    { id: "10.4.4", area: "OAuth Authorization Server", level: "1", verificationMethod: "SAST", requirement: "Verify that for a given client, the authorization server only allows the usage of grants that this client needs to use. Note that the grants ‘token’(Implicit flow) and ‘password’(Resource Owner Password Credentials flow) must no longer be used." },
    { id: "10.4.5", area: "OAuth Authorization Server", level: "1", verificationMethod: "DAST", requirement: "Verify that the authorization server mitigates refresh token replay attacks for public clients, preferably using sender-constrained refresh tokens, i.e., Demonstrating Proof of Possession (DPoP) or Certificate-Bound Access Tokens using mutual TLS (mTLS). For L1 and L2 applications, refresh token rotation may be used. If refresh token rotation is used, the authorization server must invalidate the refresh token after usage, and revoke all refresh tokens for that authorization if an already used and invalidated refresh token is provided." },
    { id: "10.4.6", area: "OAuth Authorization Server", level: "2", verificationMethod: "SAST", requirement: "Verify that, if the code grant is used, the authorization server mitigates authorization code interception attacks by requiring proof key for code exchange (PKCE). For authorization requests, the authorization server must require a valid ‘code_challenge’value and must not accept a ‘code_challenge_method’value of ‘plain’. For a token request, it must require validation of the ‘code_verifier’parameter." },
    { id: "10.4.7", area: "OAuth Authorization Server", level: "2", verificationMethod: "SAST", requirement: "Verify that if the authorization server supports unauthenticated dynamic client registration, it mitigates the risk of malicious client applications. It must validate client metadata such as any registered URIs, ensure the user’s consent, and warn the user before processing an authorization request with an untrusted client application." },
    { id: "10.4.8", area: "OAuth Authorization Server", level: "2", verificationMethod: "SAST", requirement: "Verify that refresh tokens have an absolute expiration, including if sliding refresh token expiration is applied." },
    { id: "10.4.9", area: "OAuth Authorization Server", level: "2", verificationMethod: "SAST", requirement: "Verify that refresh tokens and reference access tokens can be revoked by an authorized user using the authorization server user interface, to mitigate the risk of malicious clients or stolen tokens." },
    { id: "10.4.10", area: "OAuth Authorization Server", level: "2", verificationMethod: "SAST", requirement: "Verify that confidential client is authenticated for client-to-authorized server backchannel requests such as token requests, pushed authorization requests (PAR), and token revocation requests." },
    { id: "10.4.11", area: "OAuth Authorization Server", level: "2", verificationMethod: "SAST", requirement: "Verify that the authorization server configuration only assigns the required scopes to the OAuth client." },
    { id: "10.4.12", area: "OAuth Authorization Server", level: "3", verificationMethod: "SAST", requirement: "Verify that for a given client, the authorization server only allows the ‘response_mode’value that this client needs to use. For example, by having the authorization server validate this value against the expected values or by using pushed authorization request (PAR) or JWT-secured Authorization Request (JAR)." },
    { id: "10.4.13", area: "OAuth Authorization Server", level: "3", verificationMethod: "SAST", requirement: "Verify that grant type ‘code’is always used together with pushed authorization requests (PAR)." },
    { id: "10.4.14", area: "OAuth Authorization Server", level: "3", verificationMethod: "DAST", requirement: "Verify that the authorization server issues only sender-constrained (Proof-of-Possession) access tokens, either with certificate-bound access tokens using mutual TLS (mTLS) or DPoP-bound access tokens (Demonstration of Proof of Possession)." },
    { id: "10.4.15", area: "OAuth Authorization Server", level: "3", verificationMethod: "SAST", requirement: "Verify that, for a server-side client (which is not executed on the end-user device), the authorization server ensures that the ‘authorization_details’ parameter value is from the client backend and that the user has not tampered with it. For example, by requiring the usage of pushed authorization request (PAR) or JWT-secured Authorization Request (JAR)." },
    { id: "10.4.16", area: "OAuth Authorization Server", level: "3", verificationMethod: "DAST", requirement: "Verify that the client is confidential and the authorization server requires the use of strong client authentication methods (based on public-key cryptography and resistant to replay attacks), such as mutual TLS ( ‘tls_client_auth’, ‘self_signed_tls_client_auth’) or private key JWT ( ‘private_key_jwt’)." },
    { id: "10.5.1", area: "OIDC Client", level: "2", verificationMethod: "SAST", requirement: "Verify that the client (as the relying party) mitigates ID Token replay attacks. For example, by ensuring that the ‘nonce’claim in the ID Token matches the ‘nonce’value sent in the authentication request to the OpenID Provider (in OAuth2 refereed to as the authorization request sent to the authorization server)." },
    { id: "10.5.2", area: "OIDC Client", level: "2", verificationMethod: "SAST", requirement: "Verify that the client uniquely identifies the user from ID Token claims, usually the ‘sub’claim, which cannot be reassigned to other users (for the scope of an identity provider)." },
    { id: "10.5.3", area: "OIDC Client", level: "2", verificationMethod: "SAST", requirement: "Verify that the client rejects attempts by a malicious authorization server to impersonate another authorization server through authorization server metadata. The client must reject authorization server metadata if the issuer URL in the authorization server metadata does not exactly match the pre-configured issuer URL expected by the client." },
    { id: "10.5.4", area: "OIDC Client", level: "2", verificationMethod: "SAST", requirement: "Verify that the client validates that the ID Token is intended to be used for that client (audience) by checking that the ‘aud’claim from the token is equal to the ‘client_id’value for the client." },
    { id: "10.5.5", area: "OIDC Client", level: "2", verificationMethod: "SAST", requirement: "Verify that, when using OIDC back-channel logout, the relying party mitigates denial of service through forced logout and cross-JWT confusion in the logout flow. The client must verify that the logout token is correctly typed with a value of ‘logout+jwt’, contains the ‘event’claim with the correct member name, and does not contain a ‘nonce’claim. Note that it is also recommended to have a short expiration (e.g., 2 minutes)." },
    { id: "10.6.1", area: "OpenID Provider", level: "2", verificationMethod: "SAST", requirement: "Verify that the OpenID Provider only allows values ‘code’, ‘ciba’, ‘id_token’, or ‘id_token code’for response mode. Note that ‘code’is preferred over ‘id_token code’(the OIDC Hybrid flow), and ‘token’(any Implicit flow) must not be used." },
    { id: "10.6.2", area: "OpenID Provider", level: "2", verificationMethod: "SAST", requirement: "Verify that the OpenID Provider mitigates denial of service through forced logout. By obtaining explicit confirmation from the end-user or, if present, validating parameters in the logout request (initiated by the relying party), such as the ‘id_token_hint’." },
    { id: "10.7.1", area: "Consent Management", level: "2", verificationMethod: "SAST", requirement: "Verify that the authorization server ensures that the user consents to each authorization request. If the identity of the client cannot be assured, the authorization server must always explicitly prompt the user for consent." },
    { id: "10.7.2", area: "Consent Management", level: "2", verificationMethod: "SAST", requirement: "Verify that when the authorization server prompts for user consent, it presents sufficient and clear information about what is being consented to. When applicable, this should include the nature of the requested authorizations (typically based on scope, resource server, Rich Authorization Requests (RAR) authorization details), the identity of the authorized application, and the lifetime of these authorizations." },
    { id: "10.7.3", area: "Consent Management", level: "2", verificationMethod: "SAST", requirement: "Verify that the user can review, modify, and revoke consents which the user has granted through the authorization server." },
  ],
  "Cryptography": [
    { id: "11.1.1", area: "Cryptographic Inventory and Documentation", level: "2", verificationMethod: "SAST", requirement: "Verify that there is a documented policy for management of cryptographic keys and a cryptographic key lifecycle that follows a key management standard such as NIST SP 800-57. This should include ensuring that keys are not overshared (for example, with more than two entities for shared secrets and more than one entity for private keys)." },
    { id: "11.1.2", area: "Cryptographic Inventory and Documentation", level: "2", verificationMethod: "Manual", requirement: "Verify that a cryptographic inventory is performed, maintained, regularly updated, and includes all cryptographic keys, algorithms, and certificates used by the application. It must also document where keys can and cannot be used in the system, and the types of data that can and cannot be protected using the keys." },
    { id: "11.1.3", area: "Cryptographic Inventory and Documentation", level: "3", verificationMethod: "SAST", requirement: "Verify that cryptographic discovery mechanisms are employed to identify all instances of cryptography in the system, including encryption, hashing, and signing operations." },
    { id: "11.1.4", area: "Cryptographic Inventory and Documentation", level: "3", verificationMethod: "Manual", requirement: "Verify that a cryptographic inventory is maintained. This must include a documented plan that outlines the migration path to new cryptographic standards, such as post-quantum cryptography, in order to react to future threats." },
    { id: "11.2.1", area: "Secure Cryptography Implementation", level: "2", verificationMethod: "SAST", requirement: "Verify that industry-validated implementations (including libraries and hardware-accelerated implementations) are used for cryptographic operations." },
    { id: "11.2.2", area: "Secure Cryptography Implementation", level: "2", verificationMethod: "SAST", requirement: "Verify that the application is designed with crypto agility such that random number, authenticated encryption, MAC, or hashing algorithms, key lengths, rounds, ciphers and modes can be reconfigured, upgraded, or swapped at any time, to protect against cryptographic breaks. Similarly, it must also be possible to replace keys and passwords and re-encrypt data. This will allow for seamless upgrades to post-quantum cryptography (PQC), once high-assurance implementations of approved PQC schemes or standards are widely available." },
    { id: "11.2.3", area: "Secure Cryptography Implementation", level: "2", verificationMethod: "SAST", requirement: "Verify that all cryptographic primitives utilize a minimum of 128-bits of security based on the algorithm, key size, and configuration. For example, a 256-bit ECC key provides roughly 128 bits of security where RSA requires a 3072-bit key to achieve 128 bits of security." },
    { id: "11.2.4", area: "Secure Cryptography Implementation", level: "3", verificationMethod: "SAST", requirement: "Verify that all cryptographic operations are constant-time, with no ‘short-circuit’operations in comparisons, calculations, or returns, to avoid leaking information." },
    { id: "11.2.5", area: "Secure Cryptography Implementation", level: "3", verificationMethod: "SAST", requirement: "Verify that all cryptographic modules fail securely, and errors are handled in a way that does not enable vulnerabilities, such as Padding Oracle attacks." },
    { id: "11.3.1", area: "Encryption Algorithms", level: "1", verificationMethod: "SAST", requirement: "Verify that insecure block modes (e.g., ECB) and weak padding schemes (e.g., PKCS#1 v1.5) are not used." },
    { id: "11.3.2", area: "Encryption Algorithms", level: "1", verificationMethod: "SAST", requirement: "Verify that only approved ciphers and modes such as AES with GCM are used." },
    { id: "11.3.3", area: "Encryption Algorithms", level: "2", verificationMethod: "SAST", requirement: "Verify that encrypted data is protected against unauthorized modification preferably by using an approved authenticated encryption method or by combining an approved encryption method with an approved MAC algorithm." },
    { id: "11.3.4", area: "Encryption Algorithms", level: "3", verificationMethod: "SAST", requirement: "Verify that nonces, initialization vectors, and other single-use numbers are not used for more than one encryption key and data-element pair. The method of generation must be appropriate for the algorithm being used." },
    { id: "11.3.5", area: "Encryption Algorithms", level: "3", verificationMethod: "SAST", requirement: "Verify that any combination of an encryption algorithm and a MAC algorithm is operating in encrypt-then-MAC mode." },
    { id: "11.4.1", area: "Hashing and Hash-based Functions", level: "1", verificationMethod: "SAST", requirement: "Verify that only approved hash functions are used for general cryptographic use cases, including digital signatures, HMAC, KDF, and random bit generation. Disallowed hash functions, such as MD5, must not be used for any cryptographic purpose." },
    { id: "11.4.2", area: "Hashing and Hash-based Functions", level: "2", verificationMethod: "SAST", requirement: "Verify that passwords are stored using an approved, computationally intensive, key derivation function (also known as a “password hashing function”), with parameter settings configured based on current guidance. The settings should balance security and performance to make brute-force attacks sufficiently challenging for the required level of security." },
    { id: "11.4.3", area: "Hashing and Hash-based Functions", level: "2", verificationMethod: "SAST", requirement: "Verify that hash functions used in digital signatures, as part of data authentication or data integrity are collision resistant and have appropriate bit-lengths. If collision resistance is required, the output length must be at least 256 bits. If only resistance to second pre-image attacks is required, the output length must be at least 128 bits." },
    { id: "11.4.4", area: "Hashing and Hash-based Functions", level: "2", verificationMethod: "SAST", requirement: "Verify that the application uses approved key derivation functions with key stretching parameters when deriving secret keys from passwords. The parameters in use must balance security and performance to prevent brute-force attacks from compromising the resulting cryptographic key." },
    { id: "11.5.1", area: "Random Values", level: "2", verificationMethod: "SAST", requirement: "Verify that all random numbers and strings which are intended to be non-guessable must be generated using a cryptographically secure pseudo-random number generator (CSPRNG) and have at least 128 bits of entropy. Note that UUIDs do not respect this condition." },
    { id: "11.5.2", area: "Random Values", level: "3", verificationMethod: "SAST", requirement: "Verify that the random number generation mechanism in use is designed to work securely, even under heavy demand." },
    { id: "11.6.1", area: "Public Key Cryptography", level: "2", verificationMethod: "SAST", requirement: "Verify that only approved cryptographic algorithms and modes of operation are used for key generation and seeding, and digital signature generation and verification. Key generation algorithms must not generate insecure keys vulnerable to known attacks, for example, RSA keys which are vulnerable to Fermat factorization." },
    { id: "11.6.2", area: "Public Key Cryptography", level: "3", verificationMethod: "SAST", requirement: "Verify that approved cryptographic algorithms are used for key exchange (such as Diffie-Hellman) with a focus on ensuring that key exchange mechanisms use secure parameters. This will prevent attacks on the key establishment process which could lead to adversary-in-the-middle attacks or cryptographic breaks." },
    { id: "11.7.1", area: "In-Use Data Cryptography", level: "3", verificationMethod: "SAST", requirement: "Verify that full memory encryption is in use that protects sensitive data while it is in use, preventing access by unauthorized users or processes." },
    { id: "11.7.2", area: "In-Use Data Cryptography", level: "3", verificationMethod: "SAST", requirement: "Verify that data minimization ensures the minimal amount of data is exposed during processing, and ensure that data is encrypted immediately after use or as soon as feasible." },
  ],
  "Secure Communication": [
    { id: "12.1.1", area: "General TLS Security Guidance", level: "1", verificationMethod: "DAST", requirement: "Verify that only the latest recommended versions of the TLS protocol are enabled, such as TLS 1.2 and TLS 1.3. The latest version of the TLS protocol must be the preferred option." },
    { id: "12.1.2", area: "General TLS Security Guidance", level: "2", verificationMethod: "SAST", requirement: "Verify that only recommended cipher suites are enabled, with the strongest cipher suites set as preferred. L3 applications must only support cipher suites which provide forward secrecy." },
    { id: "12.1.3", area: "General TLS Security Guidance", level: "2", verificationMethod: "DAST", requirement: "Verify that the application validates that mTLS client certificates are trusted before using the certificate identity for authentication or authorization." },
    { id: "12.1.4", area: "General TLS Security Guidance", level: "3", verificationMethod: "DAST", requirement: "Verify that proper certification revocation, such as Online Certificate Status Protocol (OCSP) Stapling, is enabled and configured." },
    { id: "12.1.5", area: "General TLS Security Guidance", level: "3", verificationMethod: "DAST", requirement: "Verify that Encrypted Client Hello (ECH) is enabled in the application’s TLS settings to prevent exposure of sensitive metadata, such as the Server Name Indication (SNI), during TLS handshake processes." },
    { id: "12.2.1", area: "HTTPS Communication with External Facing Services", level: "1", verificationMethod: "DAST", requirement: "Verify that TLS is used for all connectivity between a client and external facing, HTTP-based services, and does not fall back to insecure or unencrypted communications." },
    { id: "12.2.2", area: "HTTPS Communication with External Facing Services", level: "1", verificationMethod: "DAST", requirement: "Verify that external facing services use publicly trusted TLS certificates." },
    { id: "12.3.1", area: "General Service to Service Communication Security", level: "2", verificationMethod: "DAST", requirement: "Verify that an encrypted protocol such as TLS is used for all inbound and outbound connections to and from the application, including monitoring systems, management tools, remote access and SSH, middleware, databases, mainframes, partner systems, or external APIs. The server must not fall back to insecure or unencrypted protocols." },
    { id: "12.3.2", area: "General Service to Service Communication Security", level: "2", verificationMethod: "DAST", requirement: "Verify that TLS clients validate certificates received before communicating with a TLS server." },
    { id: "12.3.3", area: "General Service to Service Communication Security", level: "2", verificationMethod: "DAST", requirement: "Verify that TLS or another appropriate transport encryption mechanism used for all connectivity between internal, HTTP-based services within the application, and does not fall back to insecure or unencrypted communications." },
    { id: "12.3.4", area: "General Service to Service Communication Security", level: "2", verificationMethod: "DAST", requirement: "Verify that TLS connections between internal services use trusted certificates. Where internally generated or self-signed certificates are used, the consuming service must be configured to only trust specific internal CAs and specific self-signed certificates." },
    { id: "12.3.5", area: "General Service to Service Communication Security", level: "3", verificationMethod: "DAST", requirement: "Verify that services communicating internally within a system (intra-service communications) use strong authentication to ensure that each endpoint is verified. Strong authentication methods, such as TLS client authentication, must be employed to ensure identity, using public-key infrastructure and mechanisms that are resistant to replay attacks. For microservice architectures, consider using a service mesh to simplify certificate management and enhance security." },
  ],
  "Configuration": [
    { id: "13.1.1", area: "Configuration Documentation", level: "2", verificationMethod: "SAST", requirement: "Verify that all communication needs for the application are documented. This must include external services which the application relies upon and cases where an end user might be able to provide an external location to which the application will then connect." },
    { id: "13.1.2", area: "Configuration Documentation", level: "3", verificationMethod: "Manual", requirement: "Verify that for each service the application uses, the documentation defines the maximum number of concurrent connections (e.g., connection pool limits) and how the application behaves when that limit is reached, including any fallback or recovery mechanisms, to prevent denial of service conditions." },
    { id: "13.1.3", area: "Configuration Documentation", level: "3", verificationMethod: "Manual", requirement: "Verify that the application documentation defines resource-management strategies for every external system or service it uses (e.g., databases, file handles, threads, HTTP connections). This should include resource-release procedures, timeout settings, failure handling, and where retry logic is implemented, specifying retry limits, delays, and back-off algorithms. For synchronous HTTP request-response operations it should mandate short timeouts and either disable retries or strictly limit retries to prevent cascading delays and resource exhaustion." },
    { id: "13.1.4", area: "Configuration Documentation", level: "3", verificationMethod: "Manual", requirement: "Verify that the application’s documentation defines the secrets that are critical for the security of the application and a schedule for rotating them, based on the organization’s threat model and business requirements." },
    { id: "13.2.1", area: "Backend Communication Configuration", level: "2", verificationMethod: "DAST", requirement: "Verify that communications between backend application components that don’t support the application’s standard user session mechanism, including APIs, middleware, and data layers, are authenticated. Authentication must use individual service accounts, short-term tokens, or certificate-based authentication and not unchanging credentials such as passwords, API keys, or shared accounts with privileged access." },
    { id: "13.2.2", area: "Backend Communication Configuration", level: "2", verificationMethod: "SAST", requirement: "Verify that communications between backend application components, including local or operating system services, APIs, middleware, and data layers, are performed with accounts assigned the least necessary privileges." },
    { id: "13.2.3", area: "Backend Communication Configuration", level: "2", verificationMethod: "SAST", requirement: "Verify that if a credential has to be used for service authentication, the credential being used by the consumer is not a default credential (e.g., root/root or admin/admin)." },
    { id: "13.2.4", area: "Backend Communication Configuration", level: "2", verificationMethod: "SAST", requirement: "Verify that an allowlist is used to define the external resources or systems with which the application is permitted to communicate (e.g., for outbound requests, data loads, or file access). This allowlist can be implemented at the application layer, web server, firewall, or a combination of different layers." },
    { id: "13.2.5", area: "Backend Communication Configuration", level: "2", verificationMethod: "SAST", requirement: "Verify that the web or application server is configured with an allowlist of resources or systems to which the server can send requests or load data or files from." },
    { id: "13.2.6", area: "Backend Communication Configuration", level: "3", verificationMethod: "SAST", requirement: "Verify that where the application connects to separate services, it follows the documented configuration for each connection, such as maximum parallel connections, behavior when maximum allowed connections is reached, connection timeouts, and retry strategies." },
    { id: "13.3.1", area: "Secret Management", level: "2", verificationMethod: "Manual", requirement: "Verify that a secrets management solution, such as a key vault, is used to securely create, store, control access to, and destroy backend secrets. These could include passwords, key material, integrations with databases and third-party systems, keys and seeds for time-based tokens, other internal secrets, and API keys. Secrets must not be included in application source code or included in build artifacts. For an L3 application, this must involve a hardware-backed solution such as an HSM." },
    { id: "13.3.2", area: "Secret Management", level: "2", verificationMethod: "SAST", requirement: "Verify that access to secret assets adheres to the principle of least privilege." },
    { id: "13.3.3", area: "Secret Management", level: "3", verificationMethod: "SAST", requirement: "Verify that all cryptographic operations are performed using an isolated security module (such as a vault or hardware security module) to securely manage and protect key material from exposure outside of the security module." },
    { id: "13.3.4", area: "Secret Management", level: "3", verificationMethod: "Manual", requirement: "Verify that secrets are configured to expire and be rotated based on the application’s documentation." },
    { id: "13.4.1", area: "Unintended Information Leakage", level: "1", verificationMethod: "SAST", requirement: "Verify that the application is deployed either without any source control metadata, including the .git or .svn folders, or in a way that these folders are inaccessible both externally and to the application itself." },
    { id: "13.4.2", area: "Unintended Information Leakage", level: "2", verificationMethod: "SAST", requirement: "Verify that debug modes are disabled for all components in production environments to prevent exposure of debugging features and information leakage." },
    { id: "13.4.3", area: "Unintended Information Leakage", level: "2", verificationMethod: "SAST", requirement: "Verify that web servers do not expose directory listings to clients unless explicitly intended." },
    { id: "13.4.4", area: "Unintended Information Leakage", level: "2", verificationMethod: "SAST", requirement: "Verify that using the HTTP TRACE method is not supported in production environments, to avoid potential information leakage." },
    { id: "13.4.5", area: "Unintended Information Leakage", level: "2", verificationMethod: "Manual", requirement: "Verify that documentation (such as for internal APIs) and monitoring endpoints are not exposed unless explicitly intended." },
    { id: "13.4.6", area: "Unintended Information Leakage", level: "3", verificationMethod: "SAST", requirement: "Verify that the application does not expose detailed version information of backend components." },
    { id: "13.4.7", area: "Unintended Information Leakage", level: "3", verificationMethod: "SAST", requirement: "Verify that the web tier is configured to only serve files with specific file extensions to prevent unintentional information, configuration, and source code leakage." },
  ],
  "Data Protection": [
    { id: "14.1.1", area: "Data Protection Documentation", level: "2", verificationMethod: "SAST", requirement: "Verify that all sensitive data created and processed by the application has been identified and classified into protection levels. This includes data that is only encoded and therefore easily decoded, such as Base64 strings or the plaintext payload inside a JWT. Protection levels need to take into account any data protection and privacy regulations and standards which the application is required to comply with." },
    { id: "14.1.2", area: "Data Protection Documentation", level: "2", verificationMethod: "SAST", requirement: "Verify that all sensitive data protection levels have a documented set of protection requirements. This must include (but not be limited to) requirements related to general encryption, integrity verification, retention, how the data is to be logged, access controls around sensitive data in logs, database-level encryption, privacy and privacy-enhancing technologies to be used, and other confidentiality requirements." },
    { id: "14.2.1", area: "General Data Protection", level: "1", verificationMethod: "SAST", requirement: "Verify that sensitive data is only sent to the server in the HTTP message body or header fields, and that the URL and query string do not contain sensitive information, such as an API key or session token." },
    { id: "14.2.2", area: "General Data Protection", level: "2", verificationMethod: "SAST", requirement: "Verify that the application prevents sensitive data from being cached in server components, such as load balancers and application caches, or ensures that the data is securely purged after use." },
    { id: "14.2.3", area: "General Data Protection", level: "2", verificationMethod: "SAST", requirement: "Verify that defined sensitive data is not sent to untrusted parties (e.g., user trackers) to prevent unwanted collection of data outside of the application’s control." },
    { id: "14.2.4", area: "General Data Protection", level: "2", verificationMethod: "Manual", requirement: "Verify that controls around sensitive data related to encryption, integrity verification, retention, how the data is to be logged, access controls around sensitive data in logs, privacy and privacy-enhancing technologies, are implemented as defined in the documentation for the specific data’s protection level." },
    { id: "14.2.5", area: "General Data Protection", level: "3", verificationMethod: "SAST", requirement: "Verify that caching mechanisms are configured to only cache responses which have the expected content type for that resource and do not contain sensitive, dynamic content. The web server should return a 404 or 302 response when a non-existent file is accessed rather than returning a different, valid file. This should prevent Web Cache Deception attacks." },
    { id: "14.2.6", area: "General Data Protection", level: "3", verificationMethod: "SAST", requirement: "Verify that the application only returns the minimum required sensitive data for the application’s functionality. For example, only returning some of the digits of a credit card number and not the full number. If the complete data is required, it should be masked in the user interface unless the user specifically views it." },
    { id: "14.2.7", area: "General Data Protection", level: "3", verificationMethod: "SAST", requirement: "Verify that sensitive information is subject to data retention classification, ensuring that outdated or unnecessary data is deleted automatically, on a defined schedule, or as the situation requires." },
    { id: "14.2.8", area: "General Data Protection", level: "3", verificationMethod: "SAST", requirement: "Verify that sensitive information is removed from the metadata of user-submitted files unless storage is consented to by the user." },
    { id: "14.3.1", area: "Client-side Data Protection", level: "1", verificationMethod: "DAST", requirement: "Verify that authenticated data is cleared from client storage, such as the browser DOM, after the client or session is terminated. The ‘Clear-Site-Data’ HTTP response header field may be able to help with this but the client-side should also be able to clear up if the server connection is not available when the session is terminated." },
    { id: "14.3.2", area: "Client-side Data Protection", level: "2", verificationMethod: "DAST", requirement: "Verify that the application sets sufficient anti-caching HTTP response header fields (i.e., Cache-Control: no-store) so that sensitive data is not cached in browsers." },
    { id: "14.3.3", area: "Client-side Data Protection", level: "2", verificationMethod: "SAST", requirement: "Verify that data stored in browser storage (such as localStorage, sessionStorage, IndexedDB, or cookies) does not contain sensitive data, with the exception of session tokens." },
  ],
  "Secure Coding and Architecture": [
    { id: "15.1.1", area: "Secure Coding and Architecture Documentation", level: "1", verificationMethod: "Manual", requirement: "Verify that application documentation defines risk based remediation time frames for 3rd party component versions with vulnerabilities and for updating libraries in general, to minimize the risk from these components." },
    { id: "15.1.2", area: "Secure Coding and Architecture Documentation", level: "2", verificationMethod: "Manual", requirement: "Verify that an inventory catalog, such as software bill of materials (SBOM), is maintained of all third-party libraries in use, including verifying that components come from pre-defined, trusted, and continually maintained repositories." },
    { id: "15.1.3", area: "Secure Coding and Architecture Documentation", level: "2", verificationMethod: "Manual", requirement: "Verify that the application documentation identifies functionality which is time-consuming or resource-demanding. This must include how to prevent a loss of availability due to overusing this functionality and how to avoid a situation where building a response takes longer than the consumer’s timeout. Potential defenses may include asynchronous processing, using queues, and limiting parallel processes per user and per application." },
    { id: "15.1.4", area: "Secure Coding and Architecture Documentation", level: "3", verificationMethod: "Manual", requirement: "Verify that application documentation highlights third-party libraries which are considered to be “risky components”." },
    { id: "15.1.5", area: "Secure Coding and Architecture Documentation", level: "3", verificationMethod: "Manual", requirement: "Verify that application documentation highlights parts of the application where “dangerous functionality”is being used." },
    { id: "15.2.1", area: "Security Architecture and Dependencies", level: "1", verificationMethod: "SAST", requirement: "Verify that the application only contains components which have not breached the documented update and remediation time frames." },
    { id: "15.2.2", area: "Security Architecture and Dependencies", level: "2", verificationMethod: "SAST", requirement: "Verify that the application has implemented defenses against loss of availability due to functionality which is time-consuming or resource-demanding, based on the documented security decisions and strategies for this." },
    { id: "15.2.3", area: "Security Architecture and Dependencies", level: "2", verificationMethod: "SAST", requirement: "Verify that the production environment only includes functionality that is required for the application to function, and does not expose extraneous functionality such as test code, sample snippets, and development functionality." },
    { id: "15.2.4", area: "Security Architecture and Dependencies", level: "3", verificationMethod: "Manual", requirement: "Verify that third-party components and all of their transitive dependencies are included from the expected repository, whether internally owned or an external source, and that there is no risk of a dependency confusion attack." },
    { id: "15.2.5", area: "Security Architecture and Dependencies", level: "3", verificationMethod: "Manual", requirement: "Verify that the application implements additional protections around parts of the application which are documented as containing “dangerous functionality”or using third-party libraries considered to be “risky components”. This could include techniques such as sandboxing, encapsulation, containerization or network level isolation to delay and deter attackers who compromise one part of an application from pivoting elsewhere in the application." },
    { id: "15.3.1", area: "Defensive Coding", level: "1", verificationMethod: "SAST", requirement: "Verify that the application only returns the required subset of fields from a data object. For example, it should not return an entire data object, as some individual fields should not be accessible to users." },
    { id: "15.3.2", area: "Defensive Coding", level: "2", verificationMethod: "DAST", requirement: "Verify that where the application backend makes calls to external URLs, it is configured to not follow redirects unless it is intended functionality." },
    { id: "15.3.3", area: "Defensive Coding", level: "2", verificationMethod: "SAST", requirement: "Verify that the application has countermeasures to protect against mass assignment attacks by limiting allowed fields per controller and action, e.g., it is not possible to insert or update a field value when it was not intended to be part of that action." },
    { id: "15.3.4", area: "Defensive Coding", level: "2", verificationMethod: "DAST", requirement: "Verify that all proxying and middleware components transfer the user’s original IP address correctly using trusted data fields that cannot be manipulated by the end user, and the application and web server use this correct value for logging and security decisions such as rate limiting, taking into account that even the original IP address may not be reliable due to dynamic IPs, VPNs, or corporate firewalls." },
    { id: "15.3.5", area: "Defensive Coding", level: "2", verificationMethod: "SAST", requirement: "Verify that the application explicitly ensures that variables are of the correct type and performs strict equality and comparator operations. This is to avoid type juggling or type confusion vulnerabilities caused by the application code making an assumption about a variable type." },
    { id: "15.3.6", area: "Defensive Coding", level: "2", verificationMethod: "SAST", requirement: "Verify that JavaScript code is written in a way that prevents prototype pollution, for example, by using Set() or Map() instead of object literals." },
    { id: "15.3.7", area: "Defensive Coding", level: "2", verificationMethod: "SAST", requirement: "Verify that the application has defenses against HTTP parameter pollution attacks, particularly if the application framework makes no distinction about the source of request parameters (query string, body parameters, cookies, or header fields)." },
    { id: "15.4.1", area: "Safe Concurrency", level: "3", verificationMethod: "SAST", requirement: "Verify that shared objects in multi-threaded code (such as caches, files, or in-memory objects accessed by multiple threads) are accessed safely by using thread-safe types and synchronization mechanisms like locks or semaphores to avoid race conditions and data corruption." },
    { id: "15.4.2", area: "Safe Concurrency", level: "3", verificationMethod: "SAST", requirement: "Verify that checks on a resource’s state, such as its existence or permissions, and the actions that depend on them are performed as a single atomic operation to prevent time-of-check to time-of-use (TOCTOU) race conditions. For example, checking if a file exists before opening it, or verifying a user’s access before granting it." },
    { id: "15.4.3", area: "Safe Concurrency", level: "3", verificationMethod: "SAST", requirement: "Verify that locks are used consistently to avoid threads getting stuck, whether by waiting on each other or retrying endlessly, and that locking logic stays within the code responsible for managing the resource to ensure locks cannot be inadvertently or maliciously modified by external classes or code." },
    { id: "15.4.4", area: "Safe Concurrency", level: "3", verificationMethod: "SAST", requirement: "Verify that resource allocation policies prevent thread starvation by ensuring fair access to resources, such as by leveraging thread pools, allowing lower-priority threads to proceed within a reasonable timeframe." },
  ],
  "Security Logging and Error Handling": [
    { id: "16.1.1", area: "Security Logging Documentation", level: "2", verificationMethod: "Manual", requirement: "Verify that an inventory exists documenting the logging performed at each layer of the application’s technology stack, what events are being logged, log formats, where that logging is stored, how it is used, how access to it is controlled, and for how long logs are kept." },
    { id: "16.2.1", area: "General Logging", level: "2", verificationMethod: "SAST", requirement: "Verify that each log entry includes necessary metadata (such as when, where, who, what) that would allow for a detailed investigation of the timeline when an event happens." },
    { id: "16.2.2", area: "General Logging", level: "2", verificationMethod: "SAST", requirement: "Verify that time sources for all logging components are synchronized, and that timestamps in security event metadata use UTC or include an explicit time zone offset. UTC is recommended to ensure consistency across distributed systems and to prevent confusion during daylight saving time transitions." },
    { id: "16.2.3", area: "General Logging", level: "2", verificationMethod: "Manual", requirement: "Verify that the application only stores or broadcasts logs to the files and services that are documented in the log inventory." },
    { id: "16.2.4", area: "General Logging", level: "2", verificationMethod: "SAST", requirement: "Verify that logs can be read and correlated by the log processor that is in use, preferably by using a common logging format." },
    { id: "16.2.5", area: "General Logging", level: "2", verificationMethod: "SAST", requirement: "Verify that when logging sensitive data, the application enforces logging based on the data’s protection level. For example, it may not be allowed to log certain data, such as credentials or payment details. Other data, such as session tokens, may only be logged by being hashed or masked, either in full or partially." },
    { id: "16.3.1", area: "Security Events", level: "2", verificationMethod: "SAST", requirement: "Verify that all authentication operations are logged, including successful and unsuccessful attempts. Additional metadata, such as the type of authentication or factors used, should also be collected." },
    { id: "16.3.2", area: "Security Events", level: "2", verificationMethod: "SAST", requirement: "Verify that failed authorization attempts are logged. For L3, this must include logging all authorization decisions, including logging when sensitive data is accessed (without logging the sensitive data itself)." },
    { id: "16.3.3", area: "Security Events", level: "2", verificationMethod: "Manual", requirement: "Verify that the application logs the security events that are defined in the documentation and also logs attempts to bypass the security controls, such as input validation, business logic, and anti-automation." },
    { id: "16.3.4", area: "Security Events", level: "2", verificationMethod: "DAST", requirement: "Verify that the application logs unexpected errors and security control failures such as backend TLS failures." },
    { id: "16.4.1", area: "Log Protection", level: "2", verificationMethod: "SAST", requirement: "Verify that all logging components appropriately encode data to prevent log injection." },
    { id: "16.4.2", area: "Log Protection", level: "2", verificationMethod: "SAST", requirement: "Verify that logs are protected from unauthorized access and cannot be modified." },
    { id: "16.4.3", area: "Log Protection", level: "2", verificationMethod: "SAST", requirement: "Verify that logs are securely transmitted to a logically separate system for analysis, detection, alerting, and escalation. The aim is to ensure that if the application is breached, the logs are not compromised." },
    { id: "16.5.1", area: "Error Handling", level: "2", verificationMethod: "SAST", requirement: "Verify that a generic message is returned to the consumer when an unexpected or security-sensitive error occurs, ensuring no exposure of sensitive internal system data such as stack traces, queries, secret keys, and tokens." },
    { id: "16.5.2", area: "Error Handling", level: "2", verificationMethod: "SAST", requirement: "Verify that the application continues to operate securely when external resource access fails, for example, by using patterns such as circuit breakers or graceful degradation." },
    { id: "16.5.3", area: "Error Handling", level: "2", verificationMethod: "SAST", requirement: "Verify that the application fails gracefully and securely, including when an exception occurs, preventing fail-open conditions such as processing a transaction despite errors resulting from validation logic." },
    { id: "16.5.4", area: "Error Handling", level: "3", verificationMethod: "SAST", requirement: "Verify that a “last resort”error handler is defined which will catch all unhandled exceptions. This is both to avoid losing error details that must go to log files and to ensure that an error does not take down the entire application process, leading to a loss of availability." },
  ],
  "WebRTC": [
    { id: "17.1.1", area: "TURN Server", level: "2", verificationMethod: "SAST", requirement: "Verify that the Traversal Using Relays around NAT (TURN) service only allows access to IP addresses that are not reserved for special purposes (e.g., internal networks, broadcast, loopback). Note that this applies to both IPv4 and IPv6 addresses." },
    { id: "17.1.2", area: "TURN Server", level: "3", verificationMethod: "DAST", requirement: "Verify that the Traversal Using Relays around NAT (TURN) service is not susceptible to resource exhaustion when legitimate users attempt to open a large number of ports on the TURN server." },
    { id: "17.2.1", area: "Media", level: "2", verificationMethod: "DAST", requirement: "Verify that the key for the Datagram Transport Layer Security (DTLS) certificate is managed and protected based on the documented policy for management of cryptographic keys." },
    { id: "17.2.2", area: "Media", level: "2", verificationMethod: "DAST", requirement: "Verify that the media server is configured to use and support approved Datagram Transport Layer Security (DTLS) cipher suites and a secure protection profile for the DTLS Extension for establishing keys for the Secure Real-time Transport Protocol (DTLS-SRTP)." },
    { id: "17.2.3", area: "Media", level: "2", verificationMethod: "DAST", requirement: "Verify that Secure Real-time Transport Protocol (SRTP) authentication is checked at the media server to prevent Real-time Transport Protocol (RTP) injection attacks from leading to either a Denial of Service condition or audio or video media insertion into media streams." },
    { id: "17.2.4", area: "Media", level: "2", verificationMethod: "DAST", requirement: "Verify that the media server is able to continue processing incoming media traffic when encountering malformed Secure Real-time Transport Protocol (SRTP) packets." },
    { id: "17.2.5", area: "Media", level: "3", verificationMethod: "DAST", requirement: "Verify that the media server is able to continue processing incoming media traffic during a flood of Secure Real-time Transport Protocol (SRTP) packets from legitimate users." },
    { id: "17.2.6", area: "Media", level: "3", verificationMethod: "DAST", requirement: "Verify that the media server is not susceptible to the “ClientHello”Race Condition vulnerability in Datagram Transport Layer Security (DTLS) by checking if the media server is publicly known to be vulnerable or by performing the race condition test." },
    { id: "17.2.7", area: "Media", level: "3", verificationMethod: "DAST", requirement: "Verify that any audio or video recording mechanisms associated with the media server are able to continue processing incoming media traffic during a flood of Secure Real-time Transport Protocol (SRTP) packets from legitimate users." },
    { id: "17.2.8", area: "Media", level: "3", verificationMethod: "DAST", requirement: "Verify that the Datagram Transport Layer Security (DTLS) certificate is checked against the Session Protocol (SDP) fingerprint attribute, terminating the media stream if the check fails, to ensure the authenticity of the media stream." },
    { id: "17.3.1", area: "Signaling", level: "2", verificationMethod: "DAST", requirement: "Verify that the signaling server is able to continue processing legitimate incoming signaling messages during a flood attack. This should be achieved by implementing rate limiting at the signaling level." },
    { id: "17.3.2", area: "Signaling", level: "2", verificationMethod: "SAST", requirement: "Verify that the signaling server is able to continue processing legitimate signaling messages when encountering malformed signaling message that could cause a denial of service condition. This could include implementing input validation, safely handling integer overflows, preventing buffer overflows, and employing other robust error-handling techniques." },
  ],
};

const SOLIDITY_PATTERNS = [
  { id:"4.1.3", regex:/onlyOwner|onlyAdmin|onlyRole|hasRole|AccessControl|Ownable/i, confidence:"high", note:"Access control modifier detected" },
  { id:"4.2.1", regex:/require\(msg\.sender|require\(owner|modifier.*only/i, confidence:"high", note:"Ownership/IDOR check detected" },
  { id:"5.1.3", regex:/require\(|revert\(|assert\(/i, confidence:"high", note:"Input validation via require/revert detected" },
  { id:"6.2.2", regex:/keccak256|sha256|sha3|AES|encrypt/i, confidence:"high", note:"Cryptographic hash function detected" },
  { id:"6.3.2", regex:/bytes32|bytes16|uint256.*random|block\.timestamp/i, confidence:"medium", note:"Unique identifier generation detected" },
  { id:"5.3.4", regex:/mapping\(|SafeMath|unchecked\s*{/i, confidence:"medium", note:"Safe math or mapping used" },
  { id:"7.4.1", regex:/emit\s+\w+Event|event\s+\w+|Error\(/i, confidence:"medium", note:"Event logging detected" },
  { id:"7.4.2", regex:/try\s*{|catch\s*\(|revert\s*\(/i, confidence:"medium", note:"Error handling detected" },
  { id:"4.3.1", regex:/Pausable|whenNotPaused|pause\(\)|unpause\(\)/i, confidence:"high", note:"Pausable/emergency stop detected" },
  { id:"8.1.4", regex:/ReentrancyGuard|nonReentrant|mutex|locked/i, confidence:"high", note:"Reentrancy protection detected" },
  { id:"14.2.1", regex:/import.*OpenZeppelin|@openzeppelin|SafeERC20/i, confidence:"high", note:"OpenZeppelin security library detected" },
  { id:"9.1.1", regex:/https:\/\/|IPFS|ipfs\./i, confidence:"low", note:"Secure external reference detected" },
  { id:"2.1.1", regex:/password.*length|minLength|maxLength/i, confidence:"medium", note:"Password length validation detected" },
  { id:"6.4.1", regex:/private\s+\w+.*key|privateKey|secretKey/i, confidence:"medium", note:"Private key storage pattern detected" },
  { id:"13.2.2", regex:/ABI\.decode|abi\.decode|JSON\.parse/i, confidence:"medium", note:"Input schema validation detected" },
];

// Corrected against the actual finalized OWASP ASVS 5.0.0 spec.
// Old IDs were based on an earlier/different numbering scheme.
import { PATTERNS } from "./patterns.js";

function getLineInfo(code, pattern) {
  const lines = code.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (pattern.test(lines[i])) {
      return {
        lineNumber: i + 1,
        lineContent: lines[i].trim().substring(0, 150),
      };
    }
  }
  return null;
}

// Remapped to ASVS 5.0.0 IDs to match the corrected PATTERNS/ASVS_DATA (was: old 4.x-style IDs).
// Dropped entries with no live equivalent: old "4.2.2" (CSRF disabled — no dedicated CSRF
// requirement in 5.0.0), old "9.2.3"/"9.1.3" (Secure Communication is DAST-only now, unreachable
// via this SAST loop). Fixed a corrupted regex literal on the weak-cipher entry (was missing its
// opening "/", inherited from the original file).
const INSECURE_PATTERNS = {
  "11.4.2": { pattern: /NoOpPasswordEncoder|MessageDigest.*MD5|new MD5|md5\(password/i, msg: "Insecure password storage — NoOpPasswordEncoder or MD5 detected" },
  "11.4.4": { pattern: /gensalt\(\s*\)|rounds\s*=\s*[1-9](?!0)|saltRounds\s*=\s*[1-9](?!0)/i, msg: "bcrypt work factor too low — minimum 10 required" },
  "3.3.1": { pattern: /secure\s*:\s*false|setSecure\(false\)|Secure=false/i, msg: "Secure flag disabled on cookie" },
  "3.3.4": { pattern: /httpOnly\s*:\s*false|setHttpOnly\(false\)|HttpOnly=false/i, msg: "HttpOnly flag disabled on cookie" },
  "9.1.1": { pattern: /algorithm.*none|alg.*none|HS256|HMAC.*SHA256/i, msg: "Weak JWT algorithm — use RS256 or ES256" },
  "1.2.4": { pattern: /createStatement\(\)|Statement\(\)|executeQuery\(.*\+|query.*\+.*req|sql\s*\+=|sql\s*=.*\+/i, msg: "SQL injection risk — string concatenation in query detected" },
  "11.3.2": { pattern: /ECB|Cipher\.getInstance\(.*ECB|AES\/ECB/i, msg: "Weak cipher detected — use AES-256-GCM" },
  "11.3.1": { pattern: /MD5|SHA-?1|DigestUtils\.md5|MessageDigest.*SHA.?1/i, msg: "Weak hash algorithm — never use MD5 or SHA1" },
  "11.5.1": { pattern: /Math\.random\(\)|new Random\(\)|rand\(\)|mt_rand\(/i, msg: "Insecure random number generator — use SecureRandom or secrets" },
  "13.3.2": { pattern: /api_key\s*=\s*["'][a-zA-Z0-9]{8,}|secret\s*=\s*["'][a-zA-Z0-9]{8,}|password\s*=\s*["'][a-zA-Z0-9]{6,}/i, msg: "Hardcoded secret or API key detected in source" },
  "1.2.1": { pattern: /innerHTML\s*=|document\.write\(|\.html\(.*req/i, msg: "XSS risk — unsafe HTML output method detected" },
  "1.3.2": { pattern: /eval\(.*req|eval\(.*input|exec\(.*request/i, msg: "Code injection risk — eval() with user input" },
  "13.4.2": { pattern: /DEBUG\s*=\s*True|debug\s*=\s*true|app\.run.*debug.*True/i, msg: "Debug mode enabled — must be disabled in production" },
  "1.2.5": { pattern: /Runtime\.exec\(|ProcessBuilder.*input|shell\s*=\s*True/i, msg: "Command injection risk — user input passed to shell" },
  "14.3.3": { pattern: /localStorage\.setItem.*password|sessionStorage\.setItem.*token/i, msg: "Sensitive data stored in browser storage" },
};

function getInsecureLineInfo(code, reqId) {
  const insecure = INSECURE_PATTERNS[reqId];
  if (!insecure) return null;
  const lines = code.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (insecure.pattern.test(lines[i])) {
      return {
        lineNumber: i + 1,
        lineContent: lines[i].trim().substring(0, 150),
        msg: insecure.msg,
        isWrong: true
      };
    }
  }
  return null;
}

const CONF_COLOR = { high: "#2ea043", medium: "#c99a06", low: "#c0392b" };

const CAT_META = {
  "Encoding and Sanitization":            { icon:"🧼", color:"#4a9eff" },
  "Validation and Business Logic":        { icon:"✅", color:"#ffd44a" },
  "Web Frontend Security":                { icon:"🖥️", color:"#d44aff" },
  "API and Web Service":                  { icon:"🌐", color:"#4ad4ff" },
  "File Handling":                        { icon:"📁", color:"#ff884a" },
  "Authentication":                       { icon:"🔐", color:"#4a9eff" },
  "Session Management":                   { icon:"🔄", color:"#4affd4" },
  "Authorization":                        { icon:"🛡️", color:"#d44aff" },
  "Self-contained Tokens":                { icon:"🎫", color:"#c44aff" },
  "OAuth and OIDC":                       { icon:"🔑", color:"#8a4aff" },
  "Cryptography":                         { icon:"🔒", color:"#4aff4a" },
  "Secure Communication":                 { icon:"🔗", color:"#4a4aff" },
  "Configuration":                        { icon:"⚙️", color:"#aaaaaa" },
  "Data Protection":                      { icon:"💾", color:"#ffaa4a" },
  "Secure Coding and Architecture":       { icon:"🏗️", color:"#ffa04a" },
  "Security Logging and Error Handling":  { icon:"📋", color:"#ff4a4a" },
  "WebRTC":                               { icon:"📡", color:"#4affa0" },
};

function analyzeCode(code, category) {
  const findings = [];
  const matched = new Set();
  for (const p of (PATTERNS[category] || [])) {
    if (!matched.has(p.id) && p.regex.test(code)) {
      matched.add(p.id);
      const lineInfo = getLineInfo(code, p.regex);
      findings.push({
        reqId: p.id,
        confidence: p.confidence,
        note: p.note,
        lineNumber: lineInfo ? lineInfo.lineNumber : null,
        lineContent: lineInfo ? lineInfo.lineContent : null,
        isWrong: false,
      });
    }
  }
  // Case 2: Wrong implementations
  for (const p of (PATTERNS[category] || [])) {
    if (!matched.has(p.id)) {
      const wrongInfo = getInsecureLineInfo(code, p.id);
      if (wrongInfo) {
        findings.push({
          reqId: p.id,
          confidence: "low",
          note: wrongInfo.msg,
          lineNumber: wrongInfo.lineNumber,
          lineContent: wrongInfo.lineContent,
          isWrong: true,
        });
        matched.add(p.id);
      }
    }
  }
  return findings;
}

// ASVS Level-weighted severity scoring — mirrors server.py's compute_weighted_score().
// Since ASVS 5.0.0 discontinued CWE mappings, Level is the severity signal instead:
// Level 1 = baseline hygiene (weight 3), Level 2 = most apps (weight 2), Level 3 =
// high-assurance/advanced (weight 1). Missing a Level 1 control counts more than a Level 3 gap.
// Maturity classification is cumulative, matching how ASVS actually works: "Level 2" requires
// near-complete Level 1 coverage PLUS solid combined L1+L2 coverage, not just a blended percentage.
const LEVEL_WEIGHTS = { "1": 3, "2": 2, "3": 1 };

function computeWeightedScore(reqs) {
  if (!reqs || !reqs.length) return { pct: 0, level: "Not Assessed" };
  let totalWeight = 0, earnedWeight = 0;
  let l1Total = 0, l1Done = 0, l12Total = 0, l12Done = 0;
  for (const r of reqs) {
    const lvl = String(r.level || "1");
    const w = LEVEL_WEIGHTS[lvl] || 1;
    const done = !!r.implemented;
    totalWeight += w;
    if (done) earnedWeight += w;
    if (lvl === "1") { l1Total++; if (done) l1Done++; }
    if (lvl === "1" || lvl === "2") { l12Total++; if (done) l12Done++; }
  }
  const pct = totalWeight ? Math.round((earnedWeight / totalWeight) * 100) : 0;
  const l1Pct = l1Total ? (l1Done / l1Total) * 100 : 100;
  const l12Pct = l12Total ? (l12Done / l12Total) * 100 : 100;
  let level;
  if (l1Pct >= 90 && l12Pct >= 70) level = "Level 2";
  else if (l1Pct >= 70) level = "Level 1";
  else level = "Below Level 1";
  return { pct, level };
}

async function runAnalysis(files, astFindings = []) {
  const isSolidity = files.some(f => f.name && f.name.endsWith('.sol'));
  const combined = files.map(f => f.content).join("\n");
  
  // Handle Solidity files separately
  if (isSolidity) {
    const findings = [];
    const matched = new Set();
    for (const p of SOLIDITY_PATTERNS) {
      if (!matched.has(p.id) && p.regex.test(combined)) {
        matched.add(p.id);
        const lineInfo = getLineInfo(combined, p.regex);
        findings.push({
          reqId: p.id,
          confidence: p.confidence,
          note: p.note,
          lineNumber: lineInfo ? lineInfo.lineNumber : null,
          lineContent: lineInfo ? lineInfo.lineContent : null,
          isWrong: false,
        });
      }
    }
    // Build results for Solidity
    const categoryResults = {};
    let totalFindings = 0, totalReqs = 0;
    for (const [cat, allReqs] of Object.entries(ASVS_DATA)) {
      const reqs = allReqs.filter(r => r.verificationMethod === "SAST");
      const notTestable = allReqs.filter(r => r.verificationMethod !== "SAST");
      const foundIds = new Set(findings.map(f => f.reqId));
      const reqResults = reqs.map(req => {
        const finding = findings.find(f => f.reqId === req.id) || null;
        return { ...req, finding, implemented: foundIds.has(req.id), wrongImplementation: false };
      });
      const implemented = reqResults.filter(r => r.implemented).length;
      const pct = reqs.length ? Math.round((implemented / reqs.length) * 100) : 0;
      categoryResults[cat] = { reqs: reqResults, notTestable, implemented, total: reqs.length, pct };
      totalFindings += implemented;
      totalReqs += reqs.length;
    }
    return { categoryResults, totalFindings, totalReqs, overallPct: totalReqs ? Math.round((totalFindings/totalReqs)*100) : 0, fileCount: files.length, language: 'Solidity' };
  }
  const categoryResults = {};
  let totalFindings = 0, totalReqs = 0;
  for (const [cat, allReqs] of Object.entries(ASVS_DATA)) {
    const reqs = allReqs.filter(r => r.verificationMethod === "SAST");
    const notTestable = allReqs.filter(r => r.verificationMethod !== "SAST");
    const regexFindings = analyzeCode(combined, cat);
    // AST findings take priority over regex for the same requirement (more precise —
    // verified against actual code structure, not just text). Regex fills in the rest.
    const catReqIds = new Set(reqs.map(r => r.id));
    const astForCat = astFindings.filter(af => catReqIds.has(af.reqId));
    const astIds = new Set(astForCat.map(f => f.reqId));
    const findings = [...astForCat, ...regexFindings.filter(f => !astIds.has(f.reqId))];
    const foundIds = new Set(findings.map(f => f.reqId));
    const reqResults = reqs.map(req => {
      const finding = findings.find(f => f.reqId === req.id) || null;
      const isWrongImpl = finding && finding.isWrong === true;
      return {
        ...req,
        finding,
        implemented: foundIds.has(req.id) && !isWrongImpl,
        wrongImplementation: isWrongImpl,
      };
    });
    const implemented = reqResults.filter(r => r.implemented).length;
    const { pct: catPct } = computeWeightedScore(reqResults);
    categoryResults[cat] = { reqs: reqResults, notTestable, implemented, total: reqs.length, pct: catPct, findings };
    totalFindings += implemented;
    totalReqs += reqs.length;
  }
  const allReqsFlat = Object.values(categoryResults).flatMap(c => c.reqs);
  const { pct: overallPct, level } = computeWeightedScore(allReqsFlat);
  return { categoryResults, totalFindings, totalReqs, overallPct, level };
}

// ─── Mini Chart ───────────────────────────────────────────────
function BarChart({ data, categoryResults }) {
  return (
    <div style={{ display:"flex", flexDirection:"column", gap:8 }}>
      {data.map(d => {
        const catData = categoryResults ? categoryResults[d.cat] : null;
        const notTestableCount = catData?.notTestable?.length || 0;
        const color = CAT_META[d.cat]?.color || "#1F3864";
        return (
          <div key={d.cat} style={{ display:"flex", alignItems:"center", gap:8 }}>
            <div style={{ width:150, fontSize:11, color:"#555555", textAlign:"right", flexShrink:0, whiteSpace:"normal", lineHeight:1.3 }}>
              {CAT_META[d.cat]?.icon} {d.cat}
            </div>
            <div style={{ flex:1, height:20, background:"#f0f2f5", borderRadius:4, overflow:"hidden", position:"relative" }}>
              <div style={{ width:`${d.pct}%`, height:"100%", background:color, borderRadius:4, transition:"width 0.6s ease", minWidth: d.pct>0?4:0 }}/>
            </div>
            <div style={{ width:36, fontSize:11, color:"#333333", fontWeight:700 }}>{d.pct}%</div>
            <div style={{ width:70, fontSize:9, color:"#9C6500", flexShrink:0 }}>
              {notTestableCount > 0 ? `+${notTestableCount} untested` : ""}
            </div>
          </div>
        );
      })}
    </div>
  );
}

function TrendChart({ scans }) {
  if (!scans || scans.length < 2) {
    return (
      <div style={{ padding:24, textAlign:"center", color:"#666666", fontSize:12 }}>
        Run at least 2 scans to see your coverage trend over time.
      </div>
    );
  }
  // scans arrive newest-first from the API; chart reads left-to-right chronologically
  const chronological = [...scans].reverse();
  const W = 900, H = 200, padL = 40, padR = 20, padT = 20, padB = 30;
  const plotW = W - padL - padR, plotH = H - padT - padB;
  const maxPct = 100;
  const points = chronological.map((s, i) => {
    const x = padL + (i / (chronological.length - 1)) * plotW;
    const y = padT + plotH - (s.overall_pct / maxPct) * plotH;
    return { x, y, s };
  });
  const pathD = points.map((p, i) => `${i === 0 ? "M" : "L"} ${p.x} ${p.y}`).join(" ");
  const levelColor = (lvl) => lvl === "Level 2" ? "#2ea043" : lvl === "Level 1" ? "#c99a06" : "#c0392b";

  return (
    <svg viewBox={`0 0 ${W} ${H}`} style={{ width: "100%", height: "auto" }}>
      {[0, 25, 50, 75, 100].map(v => {
        const y = padT + plotH - (v / maxPct) * plotH;
        return (
          <g key={v}>
            <line x1={padL} y1={y} x2={W - padR} y2={y} stroke="#f0f2f5" strokeWidth="1" />
            <text x={padL - 8} y={y + 4} fontSize="10" fill="#999999" textAnchor="end">{v}%</text>
          </g>
        );
      })}
      <path d={pathD} fill="none" stroke="#1F3864" strokeWidth="2" />
      {points.map((p, i) => (
        <g key={i}>
          <circle cx={p.x} cy={p.y} r="5" fill={levelColor(p.s.asvs_level)} stroke="#ffffff" strokeWidth="1.5">
            <title>{`${p.s.created_at} — ${p.s.overall_pct}% (${p.s.asvs_level})`}</title>
          </circle>
        </g>
      ))}
      <text x={padL} y={H - 6} fontSize="10" fill="#999999">{chronological[0].created_at}</text>
      <text x={W - padR} y={H - 6} fontSize="10" fill="#999999" textAnchor="end">{chronological[chronological.length - 1].created_at}</text>
    </svg>
  );
}

function RadialScore({ pct, level }) {
  const r = 54; const circ = 2 * Math.PI * r;
  const dash = (pct / 100) * circ;
  const color = pct >= 70 ? "#4aff4a" : pct >= 40 ? "#ffd44a" : "#ff4a4a";
  return (
    <div style={{ display:"flex", flexDirection:"column", alignItems:"center", gap:8 }}>
      <svg width={130} height={130} viewBox="0 0 130 130">
        <circle cx={65} cy={65} r={r} fill="none" stroke="#f0f2f5" strokeWidth={10}/>
        <circle cx={65} cy={65} r={r} fill="none" stroke={color} strokeWidth={10}
          strokeDasharray={`${dash} ${circ - dash}`} strokeLinecap="round"
          transform="rotate(-90 65 65)" style={{ transition:"stroke-dasharray 0.8s ease" }}/>
        <text x={65} y={60} textAnchor="middle" fill={color} fontSize={22} fontWeight={700}>{pct}%</text>
        <text x={65} y={80} textAnchor="middle" fill="#555555" fontSize={11}>{level}</text>
        <text x={65} y={96} textAnchor="middle" fill="#555555" fontSize={10}>Overall Coverage</text>
      </svg>
    </div>
  );
}

// ─── Auth Pages ───────────────────────────────────────────────
function AuthPage({ onLogin }) {
  const [mode, setMode] = useState("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const submit = async () => {
    if (!username || !password) return setError("Fill in all fields");
    setLoading(true); setError("");
    try {
      const res = await fetch(`${API}/${mode}`, {
        method:"POST", headers:{"Content-Type":"application/json"},
        body: JSON.stringify({ username, password })
      });
      const data = await res.json();
      if (data.ok) onLogin(data.user);
      else setError(data.error || "Failed");
    } catch { setError("Cannot reach server — is backend running?"); }
    setLoading(false);
  };

  return (
    <div style={{ minHeight:"100vh", background:"#f5f6fa", display:"flex", alignItems:"center", justifyContent:"center" }}>
      <div style={{ background:"#ffffff", border:"1px solid #30363d", borderRadius:16, padding:40, width:360 }}>
        <div style={{ textAlign:"center", marginBottom:28 }}>
          <div style={{ fontSize:36, marginBottom:8 }}>🛡️</div>
          <div style={{ fontSize:20, fontWeight:700, color:"#1a1a2e" }}>ASVS Compliance & Maturity Analyzer</div>
          <div style={{ fontSize:12, color:"#555555", marginTop:4 }}>OWASP Application Security Verification Standard</div>
        </div>
        <div style={{ display:"flex", gap:8, marginBottom:24 }}>
          {["login","register"].map(m => (
            <button key={m} onClick={() => { setMode(m); setError(""); }} style={{
              flex:1, padding:"8px 0", borderRadius:8, border:"1px solid",
              borderColor: mode===m ? "#2E75B6" : "#d0d7de",
              background: mode===m ? "#1f3a5c" : "transparent",
              color: mode===m ? "#1F3864" : "#555555",
              cursor:"pointer", fontWeight:600, fontSize:13, textTransform:"capitalize"
            }}>{m}</button>
          ))}
        </div>
        <div style={{ display:"flex", flexDirection:"column", gap:12 }}>
          <input value={username} onChange={e => setUsername(e.target.value)}
            placeholder="Username" onKeyDown={e => e.key==="Enter" && submit()}
            style={{ padding:"10px 14px", borderRadius:8, border:"1px solid #30363d", background:"#f5f6fa", color:"#1a1a2e", fontSize:14, outline:"none" }}/>
          <input type="password" value={password} onChange={e => setPassword(e.target.value)}
            placeholder="Password" onKeyDown={e => e.key==="Enter" && submit()}
            style={{ padding:"10px 14px", borderRadius:8, border:"1px solid #30363d", background:"#f5f6fa", color:"#1a1a2e", fontSize:14, outline:"none" }}/>
          {error && <div style={{ color:"#ff4a4a", fontSize:12, textAlign:"center" }}>{error}</div>}
          <button onClick={submit} disabled={loading} style={{
            padding:"11px", borderRadius:8, border:"none",
            background: loading ? "#f0f2f5" : "linear-gradient(135deg,#1f6feb,#388bfd)",
            color: loading ? "#666666" : "#fff", fontWeight:700, fontSize:14, cursor: loading?"not-allowed":"pointer"
          }}>{loading ? "Please wait..." : mode==="login" ? "Sign In" : "Create Account"}</button>
        </div>
      </div>
    </div>
  );
}

// ─── Main App ─────────────────────────────────────────────────
export default function App() {
  const [user, setUser] = useState(() => { try { return JSON.parse(localStorage.getItem("asvs_user")); } catch { return null; } });
  const [tab, setTab] = useState("analyze");
  const [files, setFiles] = useState([]);
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiInsights, setAiInsights] = useState(null);
  const [aiRemediations, setAiRemediations] = useState({});
  const [remediationsReady, setRemediationsReady] = useState(true);
  const [selectedCat, setSelectedCat] = useState(null);
  const [filterLevel, setFilterLevel] = useState("all");
  const [expanded, setExpanded] = useState({});
  const [showNotTestable, setShowNotTestable] = useState({});
  const [scans, setScans] = useState([]);
  const [projectName, setProjectName] = useState("My Project");
  const [dragOver, setDragOver] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);
  const [astReady, setAstReady] = useState(false);
  useEffect(() => {
    initAstEngine()
      .then(() => setAstReady(true))
      .catch(err => console.error('AST engine failed to initialize, falling back to regex only:', err));
  }, []);
  const fileRef = useRef();
  const folderRef = useRef();

  const login = (u) => { setUser(u); localStorage.setItem("asvs_user", JSON.stringify(u)); };
  const logout = () => { setUser(null); localStorage.removeItem("asvs_user"); setResults(null); setFiles([]); };

  useEffect(() => {
    if (user && tab === "history") fetchScans();
  }, [tab, user]);

  const fetchScans = async () => {
    try {
      const res = await fetch(`${API}/scans/${user.id}`);
      const data = await res.json();
      setScans(data);
    } catch {}
  };

  const loadHistoryScan = async (scanId) => {
    try {
      const res = await fetch(`${API}/scans/detail/${scanId}`);
      const data = await res.json();
      const categoryResults = data.results;
      const totalFindings = data.total_findings;
      const totalReqs = data.total_reqs;
      const overallPct = data.overall_pct;
      const level = data.asvs_level;
      setResults({ categoryResults, totalFindings, totalReqs, overallPct, level });
      setSelectedCat(Object.keys(categoryResults)[0]);
      setProjectName(data.project_name);
      setAiInsights(null);
      setTab("results");
    } catch(e) { alert("Failed to load scan: " + e.message); }
  };

  const handleFiles = (fileList) => {
    const readers = Array.from(fileList).map(file => new Promise(res => {
      const reader = new FileReader();
      reader.onload = e => res({ name: file.name, content: e.target.result, size: file.size });
      reader.readAsText(file);
    }));
    Promise.all(readers).then(loaded => setFiles(prev => [...prev, ...loaded]));
  };

  const handleDrop = (e) => {
    e.preventDefault(); setDragOver(false);
    handleFiles(e.dataTransfer.files);
  };

  const analyze = useCallback(async () => {
    if (!files.length) return;
    setLoading(true); setResults(null); setAiInsights(null);
    await new Promise(r => setTimeout(r, 400));
    let astFindings = [];
    if (astReady) {
      try {
        const astResult = await runAstOnFiles(files);
        astFindings = astResult.findings;
      } catch (err) {
        console.error('AST analysis failed, continuing with regex only:', err);
      }
    }
    const res = await runAnalysis(files, astFindings);
    setResults(res);
    setSelectedCat(Object.keys(res.categoryResults)[0]);
    setLoading(false);
    setTab("results");

    // Save scan
    try {
      await fetch(`${API}/scans`, {
        method:"POST", headers:{"Content-Type":"application/json"},
        body: JSON.stringify({
          user_id: user.id, project_name: projectName,
          files_count: files.length, total_findings: res.totalFindings,
          total_reqs: res.totalReqs, overall_pct: res.overallPct,
          asvs_level: res.level, results: res.categoryResults
        })
      });
    } catch {}

    // Real AI Analysis via the Claude API (backend proxies the call)
    setAiLoading(true);
    try {
      const combinedCode = files.map(f => f.content).join("\n");
      const categorySummary = Object.fromEntries(
        Object.entries(res.categoryResults).map(([cat, d]) => [cat, { implemented: d.implemented, total: d.total, pct: d.pct }])
      );
      const language = res.language
        || (files.some(f => f.name?.endsWith('.py')) ? 'python'
          : files.some(f => f.name?.endsWith('.jsx') || f.name?.endsWith('.tsx')) ? 'jsx'
          : files.some(f => f.name?.endsWith('.js') || f.name?.endsWith('.ts')) ? 'javascript'
          : files.some(f => f.name?.endsWith('.java')) ? 'java'
          : files.some(f => f.name?.endsWith('.go')) ? 'go'
          : 'source');

      const aiRes = await fetch(`${API}/ai/analyze`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          project_name: projectName,
          language,
          code: combinedCode,
          category_results: categorySummary
        })
      });
      const aiData = await aiRes.json();
      if (aiData.ok) {
        setAiInsights({
          summary: aiData.summary,
          strengths: aiData.strengths,
          risks: aiData.risks,
          topRecommendations: aiData.topRecommendations,
          securityScore: aiData.securityScore
        });
      } else {
        setAiInsights({ error: aiData.error || "AI analysis unavailable" });
      }
    } catch(e) {
      setAiInsights({ error: "Could not reach the AI analysis service — is the backend running?" });
    }
    setAiLoading(false);

    // Fetch specific, AI-generated remediation for each gap (SAST-verifiable, not implemented)
    setRemediationsReady(false);
    try {
      const gaps = Object.values(res.categoryResults)
        .flatMap(d => d.reqs)
        .filter(r => !r.implemented)
        .map(r => ({ id: r.id, requirement: r.requirement }));
      const gapLanguage = res.language
        || (files.some(f => f.name?.endsWith('.py')) ? 'python'
          : files.some(f => f.name?.endsWith('.js') || f.name?.endsWith('.jsx')) ? 'javascript'
          : 'source');
      if (gaps.length) {
        const remRes = await fetch(`${API}/ai/remediate`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ gaps, language: gapLanguage })
        });
        const remData = await remRes.json();
        if (remData.ok && remData.remediations) {
          const map = {};
          for (const r of remData.remediations) map[r.reqId] = r;
          setAiRemediations(map);
        }
      }
    } catch (e) {
      console.error("AI remediation fetch failed, falling back to static guidance:", e);
    }
    setRemediationsReady(true);
  }, [files, user, projectName]);

  const exportExcel = async () => {
    if (!results) return;
    try {
      const res = await fetch(`${API}/export/excel`, {
        method:"POST", headers:{"Content-Type":"application/json"},
        body: JSON.stringify({ categoryResults: results.categoryResults, project_name: projectName, aiRemediations })
      });
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a"); a.href=url; a.download="ASVS-Compliance-Maturity-Report.xlsx"; a.click();
      URL.revokeObjectURL(url);
    } catch(e) { alert("Export failed: " + e.message); }
  };

  const exportPDF = async () => {
    if (!results) return;
    try {
      const res = await fetch(`${API}/export/pdf`, {
        method:"POST", headers:{"Content-Type":"application/json"},
        body: JSON.stringify({
          categoryResults: results.categoryResults,
          project_name: projectName,
          ai_insights: (aiInsights && !aiInsights.error) ? aiInsights : null
        })
      });
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a"); a.href=url; a.download="ASVS-Compliance-Maturity-Report.pdf"; a.click();
      URL.revokeObjectURL(url);
    } catch(e) { alert("Export failed: " + e.message); }
  };

  if (!user) return <AuthPage onLogin={login} />;

  const filteredReqs = results && selectedCat
    ? results.categoryResults[selectedCat].reqs.filter(r => filterLevel==="all" || r.level===filterLevel)
    : [];

  const chartData = results
    ? Object.entries(results.categoryResults).sort(([a],[b]) => { const order = ["Encoding and Sanitization","Validation and Business Logic","Web Frontend Security","API and Web Service","File Handling","Authentication","Session Management","Authorization","Self-contained Tokens","OAuth and OIDC","Cryptography","Secure Communication","Configuration","Data Protection","Secure Coding and Architecture","Security Logging and Error Handling","WebRTC"]; return order.indexOf(a) - order.indexOf(b); }).map(([cat, d]) => ({ cat, pct: d.pct }))
    : [];

  return (
    <div style={{ minHeight:"100vh", background:"#f5f6fa", color:"#1a1a2e", fontFamily:"Segoe UI,system-ui,sans-serif" }}>
      {/* Header */}
      <div style={{ background:"#ffffff", borderBottom:"1px solid #30363d", padding:"12px 24px", display:"flex", alignItems:"center", gap:12, position:"sticky", top:0, zIndex:100 }}>
        <div style={{ width:32, height:32, borderRadius:8, background:"linear-gradient(135deg,#1f6feb,#388bfd)", display:"flex", alignItems:"center", justifyContent:"center", fontSize:16 }}>🛡️</div>
        <div>
          <div style={{ fontWeight:700, fontSize:15 }}>ASVS Compliance & Maturity Analyzer</div>
          <div style={{ fontSize:10, color:"#555555" }}>OWASP ASVS 5.0 · AI-Powered</div>
        </div>
        <div style={{ marginLeft:"auto", display:"flex", gap:6, alignItems:"center" }}>
          {["analyze","results","history","reference"].map(t => (
            <button key={t} onClick={() => setTab(t)} style={{
              padding:"5px 12px", borderRadius:6, border:"1px solid",
              borderColor: tab===t ? "#1F3864" : "#d0d7de",
              background: tab===t ? "#1F3864" : "transparent",
              color: tab===t ? "#ffffff" : "#555555",
              cursor:"pointer", fontSize:11, fontWeight:600, textTransform:"capitalize"
            }}>{t}</button>
          ))}
          <div style={{ marginLeft:8, position:"relative" }}>
            <button onClick={() => setProfileOpen(p => !p)} style={{
              display:"flex", alignItems:"center", gap:8, padding:"5px 12px 5px 6px",
              borderRadius:20, background:"#f0f2f5", border:"1px solid #30363d",
              cursor:"pointer", transition:"border-color 0.2s"
            }}
              onMouseEnter={e => e.currentTarget.style.borderColor="#2E75B6"}
              onMouseLeave={e => e.currentTarget.style.borderColor="#d0d7de"}>
              <div style={{ width:26, height:26, borderRadius:"50%", background:"linear-gradient(135deg,#388bfd,#4affd4)", display:"flex", alignItems:"center", justifyContent:"center", fontSize:11, fontWeight:700, color:"#f5f6fa" }}>{user.username[0].toUpperCase()}</div>
              <span style={{ fontSize:12, color:"#333333", fontWeight:600 }}>{user.username}</span>
              <span style={{ fontSize:10, color:"#555555" }}>{profileOpen?"▲":"▼"}</span>
            </button>
            {profileOpen && (
              <div style={{ position:"absolute", right:0, top:"calc(100% + 8px)", background:"#ffffff", border:"1px solid #d0d7de", borderRadius:10, width:200, boxShadow:"0 4px 16px rgba(0,0,0,0.15)", zIndex:200, overflow:"hidden" }}>
                <div style={{ padding:"12px 16px", borderBottom:"1px solid #d0d7de", background:"#f5f6fa", display:"flex", alignItems:"center", gap:10 }}>
                  <div style={{ width:36, height:36, borderRadius:"50%", background:"linear-gradient(135deg,#388bfd,#4affd4)", display:"flex", alignItems:"center", justifyContent:"center", fontSize:14, fontWeight:700, color:"#f5f6fa" }}>{user.username[0].toUpperCase()}</div>
                  <div>
                    <div style={{ fontWeight:700, fontSize:13, color:"#1a1a2e" }}>{user.username}</div>
                    <div style={{ fontSize:11, color:"#555555" }}>ASVS Compliance & Maturity Analyzer User</div>
                  </div>
                </div>
                <div style={{ padding:8 }}>
                  <button onClick={() => { setTab("history"); setProfileOpen(false); fetchScans(); }} style={{ width:"100%", padding:"8px 12px", background:"transparent", border:"none", color:"#333333", cursor:"pointer", textAlign:"left", borderRadius:6, fontSize:13, display:"flex", alignItems:"center", gap:8 }}
                    onMouseEnter={e => e.currentTarget.style.background="#f0f2f5"}
                    onMouseLeave={e => e.currentTarget.style.background="transparent"}>
                    🕐 Scan History
                  </button>
                  <button onClick={() => { setTab("reference"); setProfileOpen(false); }} style={{ width:"100%", padding:"8px 12px", background:"transparent", border:"none", color:"#333333", cursor:"pointer", textAlign:"left", borderRadius:6, fontSize:13, display:"flex", alignItems:"center", gap:8 }}
                    onMouseEnter={e => e.currentTarget.style.background="#f0f2f5"}
                    onMouseLeave={e => e.currentTarget.style.background="transparent"}>
                    📖 ASVS Reference
                  </button>
                  <div style={{ borderTop:"1px solid #30363d", margin:"6px 0" }}/>
                  <button onClick={() => { logout(); setProfileOpen(false); }} style={{ width:"100%", padding:"8px 12px", background:"transparent", border:"none", color:"#ff4a4a", cursor:"pointer", textAlign:"left", borderRadius:6, fontSize:13, display:"flex", alignItems:"center", gap:8 }}
                    onMouseEnter={e => e.currentTarget.style.background="#ff4a4a22"}
                    onMouseLeave={e => e.currentTarget.style.background="transparent"}>
                    🚪 Sign Out
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      <div style={{ maxWidth:1280, margin:"0 auto", padding:"20px 24px" }}>

        {/* ANALYZE TAB */}
        {tab==="analyze" && (
          <div style={{ display:"flex", flexDirection:"column", gap:16 }}>
            <div style={{ display:"flex", gap:12, alignItems:"center" }}>
              <input value={projectName} onChange={e => setProjectName(e.target.value)}
                placeholder="Project name..."
                style={{ padding:"8px 14px", borderRadius:8, border:"1px solid #30363d", background:"#ffffff", color:"#1a1a2e", fontSize:13, outline:"none", width:260 }}/>
              <div style={{ fontSize:12, color:"#555555" }}>Name your project before scanning</div>
            </div>

            {/* Drop zone */}
            <div onDrop={handleDrop} onDragOver={e => { e.preventDefault(); setDragOver(true); }} onDragLeave={() => setDragOver(false)}
              onClick={() => fileRef.current.click()}
              style={{ border:`2px dashed ${dragOver ? "#2E75B6" : "#d0d7de"}`, borderRadius:12, padding:40, textAlign:"center", cursor:"pointer", background: dragOver ? "#1f3a5c22" : "#ffffff", transition:"all 0.2s" }}>
              <div style={{ fontSize:36, marginBottom:10 }}>📂</div>
              <div style={{ fontWeight:600, marginBottom:4 }}>Drop files here or click to upload</div>
              <div style={{ fontSize:12, color:"#555555" }}>JS, Python, Java, Go, PHP, Ruby, C#, TypeScript, Solidity — multiple files supported</div>
              <input ref={fileRef} type="file" multiple accept=".js,.py,.java,.go,.php,.rb,.ts,.cs,.cpp,.c,.rs,.kt,.swift,.sol,.xml,.json,.yaml,.yml" onChange={e => handleFiles(e.target.files)} style={{ display:"none" }}/>
          <input ref={folderRef} type="file" webkitdirectory="" directory="" multiple onChange={e => handleFiles(e.target.files)} style={{ display:"none" }}/>
            </div>

            {/* File list */}
            {files.length > 0 && (
              <div style={{ background:"#ffffff", border:"1px solid #30363d", borderRadius:10, overflow:"hidden" }}>
                <div style={{ padding:"10px 16px", borderBottom:"1px solid #30363d", display:"flex", justifyContent:"space-between", alignItems:"center" }}>
                  <span style={{ fontWeight:600, fontSize:13 }}>{files.length} file{files.length>1?"s":""} loaded</span>
                  <button onClick={() => setFiles([])} style={{ background:"none", border:"none", color:"#ff4a4a", cursor:"pointer", fontSize:12 }}>Clear all</button> <button
                onClick={() => folderRef.current.click()}
                onClick={() => folderRef.current.click()}
                style={{ marginLeft:'8px', padding:'10px 20px', borderRadius:8, border:'1px dashed #2E75B6', background:'transparent', color:'#1F3864', fontWeight:700, fontSize:13, cursor:'pointer' }}>
                📁 Upload Folder
              </button>
                </div>
                {files.map((f, i) => (
                  <div key={i} style={{ padding:"8px 16px", borderBottom:"1px solid #21262d", display:"flex", justifyContent:"space-between", alignItems:"center" }}>
                    <span style={{ fontSize:12, color:"#333333" }}>📄 {f.name}</span>
                    <div style={{ display:"flex", gap:12, alignItems:"center" }}>
                      <span style={{ fontSize:11, color:"#555555" }}>{Math.round(f.size/1024)} KB · {f.content.split("\n").length} lines</span>
                      <button onClick={() => setFiles(prev => prev.filter((_,j)=>j!==i))} style={{ background:"none", border:"none", color:"#666666", cursor:"pointer", fontSize:12 }}>✕</button>
                    </div>
                  </div>
                ))}
              </div>
            )}

            <button onClick={analyze} disabled={!files.length || loading} style={{
              padding:"12px", borderRadius:10, border:"none", alignSelf:"flex-end", width:220,
              background: files.length && !loading ? "linear-gradient(135deg,#1f6feb,#388bfd)" : "#f0f2f5",
              color: files.length && !loading ? "#fff" : "#666666",
              fontWeight:700, fontSize:14, cursor: files.length && !loading ? "pointer" : "not-allowed"
            }}>{loading ? "⟳ Scanning..." : "🔍 Run ASVS Analysis"}</button>
          </div>
        )}

        {/* RESULTS TAB */}
        {tab==="results" && results && (
          <div style={{ display:"flex", flexDirection:"column", gap:16 }}>
            {(() => {
              const allNotTestable = Object.values(results.categoryResults).flatMap(c => c.notTestable || []);
              const dastCount = allNotTestable.filter(r => r.verificationMethod === "DAST").length;
              const manualCount = allNotTestable.filter(r => r.verificationMethod === "Manual").length;
              const sastTotal = results.totalReqs;
              const grandTotal = sastTotal + dastCount + manualCount;
              const activeCats = Object.keys(results.categoryResults).filter(c=>results.categoryResults[c].implemented>0).length;
              const stats = [
                { label:"Controls Found", value:results.totalFindings, color:"#1F3864", icon:"✅" },
                { label:"SAST Requirements", value:sastTotal, color:"#4a9eff", icon:"🧪" },
                { label:"Coverage", value:`${results.overallPct}%`, color: results.overallPct>=70?"#2ea043":results.overallPct>=40?"#c99a06":"#c0392b", icon:"📊" },
                { label:"Not Testable", value:dastCount+manualCount, color:"#9C6500", icon:"⚠️" },
                { label:"Files Analyzed", value:files.length, color:"#8a4aff", icon:"📄" },
                { label:"Active Categories", value:`${activeCats}/${Object.keys(results.categoryResults).length}`, color:"#4ad4ff", icon:"🗂️" },
              ];
              return (
                <>
                  <div style={{ display:"grid", gridTemplateColumns:"repeat(6,1fr)", gap:12 }}>
                    {stats.map(s => (
                      <div key={s.label} style={{ background:"#ffffff", border:"1px solid #e1e4e8", borderLeft:`4px solid ${s.color}`, borderRadius:10, padding:"14px 16px", boxShadow:"0 1px 3px rgba(0,0,0,0.06)" }}>
                        <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", marginBottom:8 }}>
                          <div style={{ fontSize:10, color:"#666666", textTransform:"uppercase", letterSpacing:"0.5px", fontWeight:600 }}>{s.label}</div>
                          <span style={{ fontSize:14 }}>{s.icon}</span>
                        </div>
                        <div style={{ fontSize:26, fontWeight:800, color:s.color }}>{s.value}</div>
                      </div>
                    ))}
                  </div>

                  {/* Verification method breakdown */}
                  <div style={{ background:"#ffffff", border:"1px solid #e1e4e8", borderRadius:10, padding:20 }}>
                    <div style={{ display:"flex", justifyContent:"space-between", alignItems:"baseline", marginBottom:10 }}>
                      <div style={{ fontWeight:700, fontSize:13 }}>Verification Coverage — ASVS 5.0.0 ({grandTotal} requirements)</div>
                      <div style={{ fontSize:11, color:"#666666" }}>This tool statically tests SAST-verifiable requirements only</div>
                    </div>
                    <div style={{ display:"flex", height:26, borderRadius:6, overflow:"hidden", border:"1px solid #e1e4e8" }}>
                      <div title={`${results.totalFindings} implemented`} style={{ width:`${(results.totalFindings/grandTotal)*100}%`, background:"#2ea043", display:"flex", alignItems:"center", justifyContent:"center" }}>
                        {results.totalFindings > 0 && <span style={{fontSize:10, color:"#fff", fontWeight:700}}>{results.totalFindings}</span>}
                      </div>
                      <div title={`${sastTotal-results.totalFindings} SAST gaps`} style={{ width:`${((sastTotal-results.totalFindings)/grandTotal)*100}%`, background:"#d0d7de" }}/>
                      <div title={`${dastCount} require DAST`} style={{ width:`${(dastCount/grandTotal)*100}%`, background:"#4a9eff" }}/>
                      <div title={`${manualCount} require manual review`} style={{ width:`${(manualCount/grandTotal)*100}%`, background:"#8a4aff" }}/>
                    </div>
                    <div style={{ display:"flex", gap:18, marginTop:10, flexWrap:"wrap" }}>
                      {[
                        {label:`Implemented (${results.totalFindings})`, color:"#2ea043"},
                        {label:`SAST gaps (${sastTotal-results.totalFindings})`, color:"#d0d7de"},
                        {label:`Requires DAST (${dastCount})`, color:"#4a9eff"},
                        {label:`Requires manual review (${manualCount})`, color:"#8a4aff"},
                      ].map(l => (
                        <div key={l.label} style={{ display:"flex", alignItems:"center", gap:6, fontSize:11, color:"#555555" }}>
                          <span style={{ width:10, height:10, borderRadius:3, background:l.color, display:"inline-block" }}/>{l.label}
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Chart + Radial */}
                  <div style={{ display:"grid", gridTemplateColumns:"1fr auto", gap:16 }}>
                    <div style={{ background:"#ffffff", border:"1px solid #e1e4e8", borderRadius:10, padding:20 }}>
                      <div style={{ fontWeight:700, marginBottom:14, fontSize:13 }}>Category Coverage</div>
                      <BarChart data={chartData} categoryResults={results.categoryResults} />
                    </div>
                    <div style={{ background:"#ffffff", border:"1px solid #e1e4e8", borderRadius:10, padding:20, display:"flex", alignItems:"center", justifyContent:"center" }}>
                      <RadialScore pct={results.overallPct} level={results.level} />
                    </div>
                  </div>
                </>
              );
            })()}

            {/* Export buttons */}
            <div style={{ display:"flex", gap:10, justifyContent:"flex-end" }}>
              <button onClick={exportExcel} disabled={!remediationsReady} style={{ padding:"9px 18px", borderRadius:8, border:"none", background: remediationsReady ? "linear-gradient(135deg,#1a6b3a,#2ea043)" : "#a0a0a0", color:"#fff", fontWeight:700, fontSize:12, cursor: remediationsReady ? "pointer" : "not-allowed" }}>{remediationsReady ? "📥 Export Excel" : "⏳ Preparing remediation..."}</button>
              <button onClick={exportPDF} style={{ padding:"9px 18px", borderRadius:8, border:"none", background:"linear-gradient(135deg,#6b1a1a,#c0392b)", color:"#fff", fontWeight:700, fontSize:12, cursor:"pointer" }}>📄 Export PDF</button>
            </div>

            {/* AI Insights */}
            {aiLoading && (
              <div style={{ background:"#ffffff", border:"1px solid #1f6feb", borderRadius:10, padding:20, textAlign:"center", color:"#555555" }}>
                🤖 Claude AI is analyzing your code...
              </div>
            )}
            {!aiLoading && !aiInsights && results && (
              <div style={{ background:"#ffffff", border:"1px solid #30363d", borderRadius:10, padding:20 }}>
                <div style={{ display:"flex", gap:8, alignItems:"center", marginBottom:10 }}>
                  <span style={{ fontSize:16 }}>🤖</span>
                  <span style={{ fontWeight:700, color:"#1F3864", fontSize:13 }}>Claude AI Security Assessment</span>
                  
                </div>
                <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr 1fr", gap:12 }}>
                  <div style={{ background:"#f5f6fa", borderRadius:8, padding:12, border:"1px solid #4aff4a22" }}>
                    <div style={{ fontSize:11, fontWeight:700, color:"#4aff4a", marginBottom:8 }}>✅ Likely Strengths</div>
                    <div style={{ fontSize:12, color:"#333333" }}>Based on pattern detection, {results.totalFindings} security controls were detected including authentication, session management, and configuration controls.</div>
                  </div>
                  <div style={{ background:"#f5f6fa", borderRadius:8, padding:12, border:"1px solid #ff884a22" }}>
                    <div style={{ fontSize:11, fontWeight:700, color:"#ff884a", marginBottom:8 }}>⚠️ Key Gaps</div>
                    <div style={{ fontSize:12, color:"#333333" }}>{results.totalReqs - results.totalFindings} ASVS requirements undetected. Check gap analysis in each category for specific remediation guidance.</div>
                  </div>
                  <div style={{ background:"#f5f6fa", borderRadius:8, padding:12, border:"1px solid #ffd44a22" }}>
                    <div style={{ fontSize:11, fontWeight:700, color:"#ffd44a", marginBottom:8 }}>💡 Recommendation</div>
                    <div style={{ fontSize:12, color:"#333333" }}>Focus on categories with 0% coverage first.  API credits at console.anthropic.com for full AI-powered analysis.</div>
                  </div>
                </div>
              </div>
            )}
            {aiInsights?.error && (
              <div style={{ background:"#fff5f5", border:"1px solid #ff4a4a", borderRadius:10, padding:20, color:"#9C0006" }}>
                <div style={{ display:"flex", gap:8, alignItems:"center", marginBottom:6 }}>
                  <span style={{ fontSize:16 }}>🤖</span>
                  <span style={{ fontWeight:700, fontSize:13 }}>Claude AI Security Assessment failed</span>
                </div>
                <div style={{ fontSize:12 }}>{aiInsights.error}</div>
              </div>
            )}
            {aiInsights && !aiInsights.error && (
              <div style={{ background:"linear-gradient(135deg,#EEF4FF,#D6E4F0)", border:"1px solid #2E75B6", borderRadius:10, padding:20 }}>
                <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:14 }}>
                  <div style={{ display:"flex", gap:8, alignItems:"center" }}>
                    <span style={{ fontSize:16 }}>🤖</span>
                    <span style={{ fontWeight:700, color:"#1F3864", fontSize:13 }}>Claude AI Security Assessment</span>
                  </div>
                  {aiInsights.securityScore !== undefined && (
                    <div style={{ padding:"4px 12px", borderRadius:20, background: aiInsights.securityScore>=70?"#4aff4a22":aiInsights.securityScore>=40?"#ffd44a22":"#ff4a4a22", color: aiInsights.securityScore>=70?"#4aff4a":aiInsights.securityScore>=40?"#ffd44a":"#ff4a4a", fontSize:12, fontWeight:700 }}>
                      AI Score: {aiInsights.securityScore}/100
                    </div>
                  )}
                </div>
                <p style={{ margin:"0 0 14px", color:"#333333", fontSize:13, lineHeight:1.7 }}>{aiInsights.summary}</p>
                <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr 1fr", gap:12 }}>
                  {[
                    { title:"✅ Strengths", items:aiInsights.strengths, color:"#375623" },
                    { title:"⚠️ Risks", items:aiInsights.risks, color:"#9C0006" },
                    { title:"💡 Recommendations", items:aiInsights.topRecommendations, color:"#9C6500" },
                  ].map(s => (
                    <div key={s.title} style={{ background:"#f5f6fa", borderRadius:8, padding:12, border:`1px solid ${s.color}22` }}>
                      <div style={{ fontSize:11, fontWeight:700, color:s.color, marginBottom:8 }}>{s.title}</div>
                      {(s.items||[]).map((item,i) => (
                        <div key={i} style={{ fontSize:12, color:"#333333", marginBottom:6, lineHeight:1.5, display:"flex", gap:6 }}>
                          <span style={{ color:s.color, flexShrink:0 }}>›</span>{item}
                        </div>
                      ))}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Category sidebar + detail */}
            <div style={{ display:"grid", gridTemplateColumns:"220px 1fr", gap:16 }}>
              <div style={{ display:"flex", flexDirection:"column", gap:5 }}>
                {Object.entries(results.categoryResults).sort(([a],[b]) => { const order = ["Encoding and Sanitization","Validation and Business Logic","Web Frontend Security","API and Web Service","File Handling","Authentication","Session Management","Authorization","Self-contained Tokens","OAuth and OIDC","Cryptography","Secure Communication","Configuration","Data Protection","Secure Coding and Architecture","Security Logging and Error Handling","WebRTC"]; return order.indexOf(a) - order.indexOf(b); }).map(([cat, d]) => {
                  const meta = CAT_META[cat] || { color:"#1F3864", icon:"🔷" };
                  const active = selectedCat===cat;
                  return (
                    <button key={cat} onClick={() => setSelectedCat(cat)} style={{
                      background: active?"#ffffff":"transparent",
                      border:`1px solid ${active?meta.color+"60":"#d0d7de"}`,
                      borderLeft:`3px solid ${active?meta.color:"transparent"}`,
                      borderRadius:8, padding:"8px 10px", cursor:"pointer", textAlign:"left"
                    }}>
                      <div style={{ display:"flex", justifyContent:"space-between", marginBottom:4 }}>
                        <span style={{ fontSize:11, fontWeight:600, color:active?meta.color:"#333333" }}>{meta.icon} {cat.split(" ").slice(0,2).join(" ")}</span>
                        <span style={{ fontSize:11, color:meta.color, fontWeight:700 }}>{d.pct}%</span>
                      </div>
                      <div style={{ height:3, background:"#f0f2f5", borderRadius:2 }}>
                        <div style={{ width:`${d.pct}%`, height:"100%", background:meta.color, borderRadius:2 }}/>
                      </div>
                      <div style={{ fontSize:10, color:"#666666", marginTop:3 }}>{d.implemented}/{d.total}</div>
                    </button>
                  );
                })}
              </div>

              {selectedCat && (
                <div style={{ background:"#ffffff", border:"1px solid #30363d", borderRadius:10, padding:16, maxHeight:580, overflowY:"auto" }}>
                  <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:14 }}>
                    <div>
                      <div style={{ fontWeight:700, fontSize:14 }}>{CAT_META[selectedCat]?.icon} {selectedCat}</div>
                      <div style={{ fontSize:12, color:"#555555" }}>{results.categoryResults[selectedCat].implemented}/{results.categoryResults[selectedCat].total} requirements detected</div>
                    </div>
                    <div style={{ display:"flex", gap:5 }}>
                      {["all","1","2","3"].map(l => (
                        <button key={l} onClick={() => setFilterLevel(l)} style={{
                          padding:"3px 9px", borderRadius:5, border:`1px solid ${filterLevel===l?"#1F3864":"#d0d7de"}`,
                          background: filterLevel===l?"#f0f2f5":"transparent",
                          color: filterLevel===l?"#1F3864":"#555555", cursor:"pointer", fontSize:11
                        }}>{l==="all"?"All":`L${l}`}</button>
                      ))}
                    </div>
                  </div>
                  {filteredReqs.map(req => {
                    const isOpen = expanded[req.id];
                    const meta = CAT_META[selectedCat] || { color:"#1F3864" };
                    return (
                      <div key={req.id} style={{ marginBottom:6, borderRadius:8, overflow:"hidden", border:`1px solid ${req.implemented?meta.color+"40":"#f0f2f5"}`, background:req.implemented?meta.color+"08":"#f5f6fa" }}>
                        <button onClick={() => setExpanded(p => ({ ...p, [req.id]:!p[req.id] }))}
                          style={{ width:"100%", padding:"9px 12px", background:"transparent", border:"none", cursor:"pointer", display:"flex", alignItems:"center", gap:8, textAlign:"left" }}>
                          <span style={{ fontSize:13 }}>{req.implemented?"✅":"⬜"}</span>
                          <span style={{ fontSize:11, fontWeight:700, color:meta.color, background:meta.color+"20", padding:"2px 5px", borderRadius:4, flexShrink:0 }}>{req.id}</span>
                          <span style={{ fontSize:10, color:"#666666", background:"#f0f2f5", padding:"2px 4px", borderRadius:4, flexShrink:0 }}>L{req.level}</span>
                          {req.verificationMethod && req.verificationMethod !== "SAST" && <span style={{ fontSize:10, color:"#9C6500", background:"#FFF2CC", padding:"2px 4px", borderRadius:4, flexShrink:0 }}>{req.verificationMethod} only</span>}
                          <span style={{ fontSize:12, color:req.implemented?"#333333":"#666666", flex:1 }}>{req.requirement.slice(0,85)}...</span>
                          {req.finding && <span style={{ fontSize:10, padding:"2px 5px", borderRadius:4, background:CONF_COLOR[req.finding.confidence]+"20", color:CONF_COLOR[req.finding.confidence], flexShrink:0 }}>{req.finding.confidence}</span>}
                          <span style={{ color:"#666666", fontSize:11 }}>{isOpen?"▲":"▼"}</span>
                        </button>
                        {isOpen && (
                          <div style={{ padding:"0 12px 10px", borderTop:"1px solid #21262d" }}>
                            <p style={{ fontSize:12, color:"#333333", lineHeight:1.7, margin:"8px 0" }}>{req.requirement}</p>
                            {req.finding && <div style={{ background:"#f5f6fa", borderRadius:6, padding:"7px 10px", fontSize:12, color:"#555555" }}><span style={{ color:CONF_COLOR[req.finding.confidence], fontWeight:700 }}>{req.finding.confidence.toUpperCase()}:</span> {req.finding.note}</div>}
                            {!req.implemented && (
                              <div style={{ background:"#FFF2CC", borderRadius:6, padding:"7px 10px", fontSize:12, color:"#9C6500", marginTop:5, border:"1px solid #FFEB9C" }}>
                                <strong>⚠️ Not Detected</strong><br/>
                                <span style={{color:"#333333"}}>Requirement: {req.requirement}</span><br/>
                                <span style={{color:"#C00000", fontSize:11}}>Control missing from source code</span>
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    );
                  })}

                  {results.categoryResults[selectedCat].notTestable && results.categoryResults[selectedCat].notTestable.length > 0 && (
                    <div style={{ marginTop:16, paddingTop:14, borderTop:"1px solid #21262d" }}>
                      <button onClick={() => setShowNotTestable(p => ({ ...p, [selectedCat]: !p[selectedCat] }))}
                        style={{ width:"100%", background:"transparent", border:"none", cursor:"pointer", display:"flex", justifyContent:"space-between", alignItems:"center", padding:"4px 0" }}>
                        <span style={{ fontSize:12, fontWeight:700, color:"#9C6500" }}>
                          ⚠️ Not Tested by This Tool ({results.categoryResults[selectedCat].notTestable.length})
                        </span>
                        <span style={{ fontSize:11, color:"#666666" }}>{showNotTestable[selectedCat] ? "▲ hide" : "▼ show"}</span>
                      </button>
                      <div style={{ fontSize:11, color:"#666666", margin:"4px 0 8px" }}>
                        These ASVS 5.0.0 requirements need dynamic testing (DAST) or human review — source-code scanning cannot verify them.
                      </div>
                      {showNotTestable[selectedCat] && results.categoryResults[selectedCat].notTestable.map(req => (
                        <div key={req.id} style={{ padding:"7px 10px", marginBottom:5, borderRadius:6, background:"#FFF2CC30", border:"1px solid #FFEB9C" }}>
                          <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:3 }}>
                            <span style={{ fontSize:11, fontWeight:700, color:"#9C6500", background:"#FFEB9C", padding:"2px 5px", borderRadius:4 }}>{req.id}</span>
                            <span style={{ fontSize:10, color:"#666666", background:"#f0f2f5", padding:"2px 4px", borderRadius:4 }}>L{req.level}</span>
                            <span style={{ fontSize:10, fontWeight:700, color:"#9C6500" }}>{req.verificationMethod === "DAST" ? "🌐 Requires DAST" : "👤 Requires Manual Review"}</span>
                          </div>
                          <div style={{ fontSize:12, color:"#555555", lineHeight:1.5 }}>{req.requirement}</div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        )}

        {tab==="results" && !results && (
          <div style={{ textAlign:"center", padding:"80px 0", color:"#666666" }}>
            <div style={{ fontSize:48, marginBottom:16 }}>🔍</div>
            <div style={{ fontSize:16, marginBottom:6 }}>No analysis yet</div>
            <div style={{ fontSize:13 }}>Upload files and run analysis from the Analyze tab</div>
          </div>
        )}

        {/* HISTORY TAB */}
        {tab==="history" && (
          <div style={{ display:"flex", flexDirection:"column", gap:12 }}>
            <div style={{ fontWeight:700, fontSize:16, marginBottom:4 }}>Scan History</div>
            {scans.length >= 2 && (
              <div style={{ background:"#ffffff", border:"1px solid #e1e4e8", borderRadius:10, padding:20 }}>
                <div style={{ display:"flex", justifyContent:"space-between", alignItems:"baseline", marginBottom:10 }}>
                  <div style={{ fontWeight:700, fontSize:13 }}>Coverage Trend</div>
                  <div style={{ fontSize:11, color:"#666666" }}>Level-weighted score across your last {scans.length} scans</div>
                </div>
                <TrendChart scans={scans} />
                <div style={{ display:"flex", gap:16, marginTop:8, fontSize:11, color:"#555555" }}>
                  {[
                    { label: "Level 2", color: "#2ea043" },
                    { label: "Level 1", color: "#c99a06" },
                    { label: "Below Level 1", color: "#c0392b" },
                  ].map(l => (
                    <div key={l.label} style={{ display:"flex", alignItems:"center", gap:6 }}>
                      <span style={{ width:10, height:10, borderRadius:"50%", background:l.color, display:"inline-block" }}/>{l.label}
                    </div>
                  ))}
                </div>
              </div>
            )}
            {scans.length === 0 && <div style={{ color:"#666666", fontSize:13, textAlign:"center", padding:40 }}>No scans yet. Run your first analysis!</div>}
            {scans.map(s => (
              <div key={s.id} onClick={() => loadHistoryScan(s.id)} style={{ background:"#ffffff", border:"1px solid #30363d", borderRadius:10, padding:16, display:"flex", justifyContent:"space-between", alignItems:"center", cursor:"pointer", transition:"border-color 0.2s" }}
                onMouseEnter={e => e.currentTarget.style.borderColor="#2E75B6"}
                onMouseLeave={e => e.currentTarget.style.borderColor="#d0d7de"}>
                <div>
                  <div style={{ fontWeight:600, marginBottom:4 }}>📁 {s.project_name}</div>
                  <div style={{ fontSize:12, color:"#555555" }}>{s.files_count} file{s.files_count>1?"s":""} · {s.total_findings}/{s.total_reqs} controls · {s.created_at}</div>
                </div>
                <div style={{ display:"flex", gap:10, alignItems:"center" }}>
                  <div style={{ fontSize:20, fontWeight:700, color: s.overall_pct>=70?"#4aff4a":s.overall_pct>=40?"#ffd44a":"#ff4a4a" }}>{s.overall_pct}%</div>
                  <div style={{ fontSize:11, padding:"3px 8px", borderRadius:6, background:"#f0f2f5", color:"#333333" }}>{s.asvs_level}</div>
                  <div style={{ fontSize:11, color:"#1F3864" }}>View →</div>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* REFERENCE TAB */}
        {tab==="reference" && (
          <div style={{ display:"flex", flexDirection:"column", gap:10 }}>
            <div style={{ fontWeight:700, fontSize:16, marginBottom:4 }}>ASVS 5.0 Reference — All Requirements</div>
            {Object.entries(ASVS_DATA).map(([cat, reqs]) => {
              const meta = CAT_META[cat] || { color:"#1F3864", icon:"🔷" };
              const open = expanded["ref_"+cat];
              return (
                <div key={cat} style={{ background:"#ffffff", border:"1px solid #30363d", borderRadius:10, overflow:"hidden" }}>
                  <button onClick={() => setExpanded(p => ({ ...p, ["ref_"+cat]:!p["ref_"+cat] }))}
                    style={{ width:"100%", padding:"13px 16px", background:"transparent", border:"none", cursor:"pointer", display:"flex", alignItems:"center", gap:10, textAlign:"left" }}>
                    <span style={{ fontSize:18 }}>{meta.icon}</span>
                    <div style={{ flex:1 }}>
                      <div style={{ fontWeight:700, color:"#1a1a2e", fontSize:13 }}>{cat}</div>
                      <div style={{ fontSize:11, color:"#555555" }}>{reqs.length} requirements</div>
                    </div>
                    <span style={{ color:meta.color, fontSize:16 }}>{open?"▲":"▼"}</span>
                  </button>
                  {open && (
                    <div style={{ borderTop:"1px solid #21262d", padding:"10px 16px" }}>
                      {reqs.map(req => (
                        <div key={req.id} style={{ padding:"7px 0", borderBottom:"1px solid #21262d", display:"flex", gap:8, alignItems:"flex-start" }}>
                          <span style={{ fontSize:11, fontWeight:700, color:meta.color, background:meta.color+"20", padding:"2px 5px", borderRadius:4, flexShrink:0 }}>{req.id}</span>
                          <span style={{ fontSize:10, color:"#ffd44a", background:"#ffd44a20", padding:"2px 4px", borderRadius:4, flexShrink:0 }}>L{req.level}</span>
                          {req.verificationMethod && req.verificationMethod !== "SAST" && <span style={{ fontSize:10, color:"#ff884a", background:"#ff884a20", padding:"2px 4px", borderRadius:4, flexShrink:0 }}>{req.verificationMethod} only</span>}
                          <span style={{ fontSize:12, color:"#333333", lineHeight:1.6 }}>{req.requirement}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
