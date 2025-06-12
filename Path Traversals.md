# Path Traversal — SAST Description
## Description:
Path Traversal (also known as Directory Traversal) occurs when user input is used to construct file paths without proper validation or sanitization, allowing attackers to access files and directories outside the intended scope (e.g., /etc/passwd, ../../config). This can lead to unauthorized access to sensitive files, information disclosure, or even remote code execution.

## How SAST Detects Path Traversal:
SAST tools detect path traversal by analyzing:\
File or directory operations (e.g., open(), readFile(), FileInputStream) that directly use user input.\
Lack of validation or sanitization for input used in file paths.\
Absence of canonicalization (i.e., resolving ../, ./, %2e) before file access.\
Insecure file upload paths that can be manipulated.

## Mitigation:
Normalize and canonicalize file paths before access.\
Use allowlists (only allow specific filenames or paths).\
Restrict file access to predefined directories.\
Reject inputs containing traversal patterns (../, ..\\, %2e, etc.).\
Use secure APIs that abstract file access (e.g., sandboxed file handlers).\
Perform permission checks before accessing or writing files.

## Vulnerable Code: Path Traversal Attack in .NET (C#)
using System;\
using System.IO;\
class Program\
{\
 static void Main()\
 {\
 Console.Write("Enter filename: ");\
 string fileName = Console.ReadLine(); // User-controlled input\
 string filePath = "C:\\Users\\Public\\Documents\\" + fileName; // Directly appending input\
 if (File.Exists(filePath))\
 {\
 string content = File.ReadAllText(filePath);\
 Console.WriteLine("File Content:\n" + content);\
 }\
 else\
 {\
 Console.WriteLine("File not found.");\
 }\
 }\
}
## Secure Code: Preventing Path Traversal
Use Path.GetFullPath() to Restrict File Access \
using System;\
using System.IO;\
class SecureProgram\
{\
 static void Main()\
 {\
 Console.Write("Enter filename: ");\
 string fileName = Console.ReadLine();\
 string baseDirectory = "C:\\Users\\Public\\Documents\\"; // Secure Base Directory\
 string filePath = Path.Combine(baseDirectory, fileName);\
 // Validate if the path is inside the allowed directory\
 string fullPath = Path.GetFullPath(filePath);\
 if (!fullPath.StartsWith(baseDirectory, StringComparison.OrdinalIgnoreCase))\
 {\
 Console.WriteLine("Access Denied: Invalid file path!");\
 return;\
 }\
 if (File.Exists(fullPath))\
 {\
 string content = File.ReadAllText(fullPath);\
 Console.WriteLine("File Content:\n" + content);\
 }\
 else\
 {\
 Console.WriteLine("File not found.");\
 }\
 }\
}\
Remark: in the above mitigation code\
• Uses Path.Combine() instead of direct string concatenation.\
• Uses Path.GetFullPath() to resolve absolute path and prevent directory escaping.\
• Ensures the file is within the allowed directory before reading