# Cross-Site Scripting (XSS) – SAST Description

## Description:
Cross-Site Scripting (XSS) is a vulnerability that allows attackers to inject malicious scripts into web pages viewed by other users. In the context of Static Application Security Testing (SAST), XSS is identified by analyzing source code for unsafe handling of user input that is rendered in HTML or JavaScript without proper sanitization or encoding.

## How SAST Detects It:

SAST tools scan the codebase for patterns such as:

Direct insertion of user input into HTML, DOM, or script tags.\
Usage of untrusted data in functions like innerHTML, document.write, or eval.\
Missing or improper use of encoding functions (e.g., escaping <, >, ").\
Insecure templating or dynamic generation of content.


## Mitigation:

Use proper output encoding (e.g., HTML-encoding or JavaScript-encoding) before rendering user input.\
Avoid dangerous functions like eval() or innerHTML with untrusted data.\
Implement input validation and sanitization.\
Use security-focused libraries and frameworks that auto-escape content (e.g., React, Angular).\
Let me know if you want versions for reflected, stored, or DOM-based XSS as well.

# There are Three types of XSS majorly
# Reflected XSS
## Vulnerable Code : Asp.Net
public void Page_Load(object sender, EventArgs e)\
{\
 var userInput = Request.QueryString["q"];\
 Response.Write("User Input: " + userInput);\
}
## Mitigation code
using System.Web;\
public void Page_Load(object sender, EventArgs e)\
{\
 var userInput = Request.QueryString["q"];\
 var encodedInput = HttpUtility.HtmlEncode(userInput);\
 Response.Write("User Input: " + encodedInput);\
}

## Other mitigations:
• ASP.NET C# provides the HttpUtility.HtmlEncode()\
• html.escape() function in Flask is actually an alias for markupsafe.escape()\
• node.js uses escapeHtml() andsanitizeHtml()\
• The PHP function htmlspecialchars()\
# Stored XSS
## Vulnerable Code : Asp.Net
public void SaveComment(string userComment)\
{\
 var command = new SqlCommand("INSERT INTO Comments (Comment) \
VALUES ('" + userComment + "')", connection);\
 // Execute the command\
}\
public void DisplayComments()\
{\
 var reader = new SqlCommand("SELECT Comment FROM Comments",\
connection).ExecuteReader();\
 while (reader.Read())\
 {\
 Response.Write(reader["Comment"].ToString());\
 }\
 // Execute the command\
}\

## Mitigation code
using System.Web;\
public void SaveComment(string userComment)\
{\
 var command = new SqlCommand("INSERT INTO Comments (Comment) \
VALUES (@comment)", connection);\
 command.Parameters.AddWithValue("@comment", userComment);\
}\
public void DisplayComments()\
{\
 var reader = new SqlCommand("SELECT Comment FROM Comments",\
connection).ExecuteReader();\
 while (reader.Read())\
 {\
 var comment = reader["Comment"].ToString();\
 var sanitizedComment = HttpUtility.HtmlEncode(comment);\
 Response.Write(sanitizedComment);\
 }\
 reader.Close();\
}
## Other mitigations:
• In PHP use mysqli_real_escape_string() for avoiding the sql injection and 
htmlspecialchars()\
• In Node.js use sanitizeHTML() function\
• In Python use escape() function\
• In Asp.net use HttpUtility.HtmlEncode() and Parameters.AddWithValue()


# DOM XSS
## Vulnerable Code
```html
<!DOCTYPE html>
<html>
<head>
 <title>Vulnerable Page</title>
</head>
<body>
 <div id="greeting"></div>
 <script>
 const name = new
URLSearchParams(window.location.search).get('name');
 document.write("Hello, " + name);
 </script>
</body>
</html>
```

## Mitigation code:
```html
<!DOCTYPE html>
<html>
<head>
 <title>Secure Page</title>
</head>
<body>
 <div id="greeting"></div>
 <script>
 const name = new URLSearchParams(window.location.search).get('name');
 // Use textContent to safely insert user input and prevent XSS
 document.getElementById("greeting").textContent = "Hello, " + name;
 </script>
</body>
</html>
```





