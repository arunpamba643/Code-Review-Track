# XXE (XML External Entity) 

## Description:
XML External Entity (XXE) is a vulnerability that occurs when an application processes XML input containing a reference to an external entity. If the XML parser is improperly configured, attackers can exploit this to access internal files, perform SSRF (Server-Side Request Forgery), or cause denial of service.

## How SAST Identifies XXE:
SAST tools look for insecure XML parsing configurations in source code such as:\
Use of insecure parsers (DocumentBuilderFactory, SAXParserFactory, etc.)\\
Missing features to disable DTD and external entities\
Usage of legacy or non-hardened XML parsers without safe settings

## Example of XXE Vulnerability:

## Vulnerable Code
libxml_disable_entity_loader(false);\
if ($_SERVER['REQUEST_METHOD'] == 'POST') {\
 $xmlData = file_get_contents('php://input');\
 $doc = new DOMDocument();\
 $doc->loadXML($xmlData, LIBXML_NOENT | LIBXML_DTDLOAD);\
 $expandedContent = $doc->getElementsByTagName('name')[0]-
>textContent;\
 echo "Thank you, " .$expandedContent . "! Your message has been 
received.";\
}
## Mitigation code
### Java
Use the DocumentBuilderFactory and disable DTDs:\
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl",
true);\
dbf.setFeature("http://xml.org/sax/features/external-generalentities", false);\
dbf.setFeature("http://xml.org/sax/features/external-parameterentities", false);\
dbf.setFeature("http://apache.org/xml/features/nonvalidating/loadexternal-dtd", false);\
dbf.setXIncludeAware(false);\
dbf.setExpandEntityReferences(false);\
DocumentBuilder db = dbf.newDocumentBuilder();
### .NET
Configure XML readers to ignore DTDs and external entities:\
XmlReaderSettings settings = new XmlReaderSettings();\
settings.DtdProcessing = DtdProcessing.Prohibit;\
settings.XmlResolver = null;\
XmlReader reader = XmlReader.Create(stream, settings);
### PHP
Disable loading external entities by libxml:\
libxml_disable_entity_loader(true);
### Python
Use defusedxml library, which is designed to mitigate XML vulnerabilities:\
from defusedxml.ElementTree import parse\
et = parse(xml_input)