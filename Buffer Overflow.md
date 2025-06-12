# Buffer Overflow - SAST Description
A buffer overflow occurs when data exceeds the allocated memory buffer, overwriting adjacent 
memory locations. 
## This can lead to:
• Memory corruption
• Unexpected crashes
• Remote code execution
## Impact of Buffer Overflow Attacks
• Denial of Service (DoS): Application crashes due to memory corruption.
• Privilege Escalation: Attackers can execute arbitrary code.
• Data Manipulation: Sensitive data can be leaked or altered.

## How SAST Detects Buffer Overflows:
SAST tools detect buffer overflows by identifying:\
Fixed-size buffer allocations (e.g., char buffer[100]) followed by unchecked data writes.\
Dangerous functions like strcpy, sprintf, gets, scanf, or memcpy without bounds checks.\
Lack of input validation or size checks before copying or appending to memory.\
Integer overflows that can lead to under-allocated buffers.

## Mitigation:
Always validate input length before copying to buffers.\
Use safer alternatives: strncpy, snprintf, fgets, memmove_s where available.\
Prefer high-level languages (Java, Python) or libraries that perform automatic bounds checking.\
Use compiler protections: stack canaries, ASLR, DEP/NX, and PIE.\
Enable static and dynamic analysis (SAST/DAST/Fuzzing) in secure SDLC.

## Vulnerable Buffer Overflow Code (C# with Unsafe Code)
using System;\
class Program\
{\
 unsafe static void Main()\
 {\
 int bufferSize = 10;\
 char* buffer = stackalloc char[bufferSize];\
 string userInput = Console.ReadLine(); // Unchecked input length\
 for (int i = 0; i < userInput.Length; i++)\
 {\
 buffer[i] = userInput[i]; // Can cause buffer overflow\
 }\
 Console.WriteLine("Buffer stored successfully.");\
 }\
}
#### Remark: in the above code the length is not being set. It’s taking length from the user input.
## Secure Code: Preventing Buffer Overflow
### Mitigation: Use Bounds Checking
using System;\
class Program\
{\
 static void Main()\
 {\
 int bufferSize = 10;\
 char[] buffer = new char[bufferSize];\
 string userInput = Console.ReadLine();\
 if (userInput.Length > bufferSize) \
 {\
 Console.WriteLine("Input too long! Try again.");\
 return;\
 }\
 for (int i = 0; i < userInput.Length; i++)\
 {\
 buffer[i] = userInput[i];\
 }\
 Console.WriteLine("Input stored safely.");\
 }\
}

### Using .NET’s Built-in Memory Protection
Use Span<T> to Avoid Overflows\
using System;\
class Program\
{\
 static void Main()\
 {\
 Span<char> buffer = stackalloc char[10];\
 string userInput = Console.ReadLine();\
 if (userInput.Length > buffer.Length)\
 {\
 Console.WriteLine("Input too long!");\
 return;\
 }\
 userInput.AsSpan().CopyTo(buffer);\
 Console.WriteLine("Stored safely in buffer.");\
 }\
}
