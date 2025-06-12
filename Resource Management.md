# Resource Management — SAST Description
## Description:
Resource Management vulnerabilities occur when an application fails to properly allocate, limit, or release system resources such as memory, file handles, database connections, threads, or sockets. This can lead to denial-of-service (DoS) conditions, performance degradation, or application crashes.

## How SAST Detects Resource Management Issues:
SAST tools analyze code for
Unclosed resources (e.g., files, database connections).\
Unbounded loops or recursive calls that exhaust memory or CPU.\
Absence of timeout or limit checks on operations like file uploads, queries, or threads.\
Missing finally or try-with-resources blocks (in languages like Java) to ensure cleanup.

## Mitigation:
Use constructs that auto-release resources (e.g., try-with-resources in Java, with in Python).\
Always close file/network/database connections in finally blocks or equivalent.\
Apply rate limiting, memory constraints, and timeouts to external resource access.\
Validate input size and control loops to prevent unbounded execution.\
Use connection pooling with proper configuration and monitoring.

## Examples of Resource Management Vulnerability:

### Poor Resource Management (Vulnerable Code)
The following code does not properly release resources, which can lead to resource 
exhaustion.\
public void ReadFile(string filePath)\
{\
 StreamReader reader = new StreamReader(filePath);\
 string content = reader.ReadToEnd();\
 // File handle remains open, leading to memory leaks\
}
### Mitigation Code
Proper Resource Management Using using (Safe Code)\
The using statement ensures that resources are automatically disposed when execution leaves 
the block.\
public void ReadFileSecurely(string filePath)\
{\
 using (StreamReader reader = new StreamReader(filePath))\
 {\
 string content = reader.ReadToEnd();\
 }\
} // File handle is automatically closed when the block ends.\
• implement IDisposable to ensure proper cleanup.

### Secure Database Connection Management
 Never leave database connections open indefinitely.
#### Insecure Code (Connection Not Closed Properly)
public void OpenConnection()\
{\
 SqlConnection conn = new SqlConnection("connection-string");\
 conn.Open();\
 // Connection remains open and is never closed!\
}
#### Secure Code Using using
public void OpenConnectionSecurely()\
{\
 using (SqlConnection conn = new SqlConnection("connection-string"))\
 {\
 conn.Open();\
 // Connection is automatically closed when execution leaves the block.\
 }\
}


### Secure Thread and Process Management
 Always dispose of unused threads and processes to prevent DoS attacks.
#### Vulnerable Code (Orphaned Threads)
public void StartThread()\
{\
 Thread myThread = new Thread(() => Console.WriteLine("Running"));\
 myThread.Start();\
 // Thread remains alive indefinitely!\
}
#### Secure Code (Proper Thread Cleanup)
public void StartThreadSecurely()\
{\
 using (CancellationTokenSource cts = new CancellationTokenSource())\
 {\
 Thread myThread = new Thread(() =>\
 {\
 while (!cts.Token.IsCancellationRequested)\
 {\
 Console.WriteLine("Running");\
 Thread.Sleep(1000);\
 }\
 });\
 myThread.Start();\
 cts.CancelAfter(TimeSpan.FromSeconds(5)); // Automatically cancels thread after 5 seconds\
 }\
}

### Secure API Resource Management
APIs should enforce rate limits and prevent excessive resource consumption.
#### Vulnerable API (No Rate Limiting)
[HttpGet("data")]\
public IActionResult GetData()\
{\
 return Ok("Data returned"); // Allows unlimited API requests, leading to DoS.\
}
#### Secure API With Rate Limiting
[HttpGet("data")]\
[EnableRateLimiting("fixed")]\
public IActionResult GetDataSecure()\
{\
 return Ok("Data returned with rate limit");\
}