# Server-Side Request Forgery (SSRF) — SAST Description

## Description:
Server-Side Request Forgery (SSRF) occurs when an attacker can manipulate a server-side application to make unauthorized requests to internal or external systems. This typically happens when user-supplied input is used to construct a URL or request target without proper validation or filtering.

### How SAST Detects SSRF:
SAST tools detect SSRF by identifying untrusted input (sources) used in server-side request functions (sinks) such as:\
requests.get/post (Python)\
http.get / URLConnection (Java)\
HttpClient.send (C#)\
axios, fetch, http.request (Node.js/JavaScript)

### Mitigation:
Implement strict allowlists for permitted domains/IPs.\
Block access to internal IP ranges (e.g., 127.0.0.1, 169.254.x.x, metadata services).\
Normalize and validate URLs before processing.\
Use network-layer controls (e.g., firewall rules) to restrict outbound access.\
Avoid dynamic request forwarding unless absolutely necessary

## Example of SSRF Vulnerability:

### Vulnerable Code
using System;\
using System.Net.Http;\
using System.Web;\
public class SSRFVulnerable\
{\
 public static async System.Threading.Tasks.Task<string> FetchData(string url)\
 {\
 using (HttpClient client = new HttpClient())\
 {\
 HttpResponseMessage response = await client.GetAsync(url);\
 return await response.Content.ReadAsStringAsync();\
 }\
 }\
}

### Mitigation Code
using System;\
using System.Net.Http;\
using System.Web;\
using System.Text.RegularExpressions;\
public class SSRFProtected\
{\
 public static async System.Threading.Tasks.Task<string> FetchDataSecure(string url)\
 {\
 if (!IsValidUrl(url))\
 {\
 throw new ArgumentException("Invalid URL.");\
 }\
 using (HttpClient client = new HttpClient())\
 {\
 client.DefaultRequestHeaders.Add("User-Agent", "SecureClient");\
 HttpResponseMessage response = await client.GetAsync(url);\
 return await response.Content.ReadAsStringAsync();\
 }\
 }\
 private static bool IsValidUrl(string url)\
 {\
 Uri uriResult;\
 bool isValidUri = Uri.TryCreate(url, UriKind.Absolute, out uriResult)\
 && (uriResult.Scheme == Uri.UriSchemeHttps || uriResult.Scheme == Uri.UriSchemeHttp);\
 // Block internal IPs\
 if (isValidUri && IsPrivateIP(uriResult.Host))\
 {\
 return false;\
 }\
 return isValidUri;\
 }\
 private static bool IsPrivateIP(string host)\
 {\
 string[] privateRanges = { "127.", "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", 
"172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", 
"172.31." };\
 foreach (string range in privateRanges)\
 {\
 if (host.StartsWith(range))\
 {\
 return true;\
 }\
 }\
 return false;\
 }\
}
