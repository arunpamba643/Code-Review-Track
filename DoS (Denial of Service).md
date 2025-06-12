# Denial of Service (DoS) — SAST Description
## Description:
Denial of Service (DoS) vulnerabilities occur when an attacker is able to crash, hang, or significantly slow down an application by exploiting flaws in how it handles resources (CPU, memory, disk, etc.). DoS can be triggered through malformed inputs, infinite loops, excessive resource consumption, or blocking operations that degrade system availability.

## How SAST Detects DoS Vulnerabilities:
SAST tools analyze code for patterns that may lead to uncontrolled resource consumption or unhandled edge cases, including:\
Infinite or heavy loops (e.g., while(true) without breaks).\
Unbounded memory allocation (new byte[request.size()]).\
Excessive recursion that can lead to stack overflow.\
Inefficient regular expressions (ReDoS — Regular Expression DoS).\
Missing timeouts in external calls (HTTP, DB, file operations).\
Unchecked large file uploads or data parsing without size limits.

## Mitigation:
Set timeouts and size limits on user inputs, uploads, and external requests.\
Use non-blocking I/O or asynchronous processing where appropriate.\
Sanitize and validate all inputs with length and format checks.\
Use efficient and safe regular expressions; avoid nested quantifiers.\
Apply rate limiting, circuit breakers, and DoS protection at the infrastructure level (e.g., WAF, API gateways).

# Vulnerable code:
## DoS Vulnerable Code: Uncontrolled Infinite Loop
 If an attacker sends a request that triggers an infinite loop, the server's CPU usage will 
spike, leading to a crash.\
public void ProcessRequest(string input)\
{\
 while (true) // Infinite loop - consumes 100% CPU\
 {\
 Console.WriteLine($"Processing {input}");\
 }\
}
## Mitigation: Use Loop Termination Conditions
public void ProcessRequest(string input)\
{\
 int counter = 0;\
 while (counter < 100) // Restrict loop execution\
 {\
 Console.WriteLine($"Processing {input}");\
 counter++;\
 }\
}

## DoS Attack via Large File Upload
 Attackers can upload large files to exhaust disk space or cause memory overflows.\
public void UploadFile(IFormFile file)\
{\
 using (var memoryStream = new MemoryStream())\
 {\
 file.CopyTo(memoryStream); // Attacker can upload a 10GB+ file!\
 Console.WriteLine("File uploaded successfully!");\
 }\
}
## Mitigation: Enforce File Size Limits
public void UploadFile(IFormFile file)\
{\
 const int maxFileSize = 5 * 1024 * 1024; // Limit to 5MB\
 if (file.Length > maxFileSize)\
 {\
 throw new Exception("File too large!"); // Reject large files\
 }\
 using (var memoryStream = new MemoryStream())\
 {\
 file.CopyTo(memoryStream);\
 Console.WriteLine("File uploaded successfully!");\
 }\
}
