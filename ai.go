package Cx1ClientGo

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Message parsed from the GET /ssegateway/remediation-status stream
type aiRemediationStatus struct {
	CurrentPhase string  `json:"currentPhase"`
	Percentage   float64 `json:"percentage"`
	JobRunning   bool    `json:"jobRunning"`
}

// Triggers AI remediation for one specific engine result
// An error is returned if the request fails or the server does not respond with status "accepted".
func (c *Cx1Client) RequestAIRemediation(scanId, projectId, engine, resultId string) (string, error) {

	type AIRemediationRequest struct {
		ScanID    string                       `json:"scanID"`
		ProjectID string                       `json:"projectID"`
		Buckets   []AIRemediationRequestBucket `json:"buckets"`
	}

	request := AIRemediationRequest{
		ScanID:    scanId,
		ProjectID: projectId,
		Buckets: []AIRemediationRequestBucket{
			{
				ScannerType: engine,
				ResultIDs:   []string{resultId},
			},
		},
	}

	jsonBody, err := json.Marshal(request)
	if err != nil {
		return "", err
	}

	data, err := c.sendRequest(http.MethodPost, "/remediation/remediate", bytes.NewReader(jsonBody), nil)
	if err != nil {
		return "", fmt.Errorf("failed to request AI remediation for scan %v: %s", request.ScanID, err)
	}

	// Response to the initial POST /remediation/remediate request
	type AIRemediationResponse struct {
		Status           string  `json:"status"`
		Published        bool    `json:"published"`
		ExistingState    *string `json:"existingState"`
		RemediationJobId string  `json:"remediationJobId"`
	}

	var response AIRemediationResponse
	if err = json.Unmarshal(data, &response); err != nil {
		return "", err
	}

	if response.Status != "accepted" {
		return "", fmt.Errorf("AI remediation request for scan %v was not accepted, status: %v", request.ScanID, response.Status)
	}

	return response.RemediationJobId, nil
}

// Opens the ssegateway status stream for a single result's remediation job and reads
// messages from it until the job reports it is no longer running (or the stream ends).
// Returns the last status message received.
func (c *Cx1Client) PollAIRemediationStatus(scanID, engine, resultID string) (string, error) {
	var status aiRemediationStatus

	endpoint := fmt.Sprintf("/ssegateway/remediation-status?engine=%v&scanId=%v&resultHash=%v",
		url.QueryEscape(engine), url.QueryEscape(scanID), url.QueryEscape(resultID))

	response, err := c.sendRequestRawCx1(http.MethodGet, endpoint, nil, nil)
	if err != nil {
		return status.CurrentPhase, fmt.Errorf("failed to open AI remediation status stream for scan %v, result %v: %s", scanID, resultID, err)
	}
	defer response.Body.Close()

	scanner := bufio.NewScanner(response.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var payload string
		switch {
		case strings.HasPrefix(line, "data:"):
			payload = strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		case strings.HasPrefix(line, "message:"):
			payload = strings.TrimSpace(strings.TrimPrefix(line, "message:"))
		default:
			continue
		}

		if err := json.Unmarshal([]byte(payload), &status); err != nil {
			return status.CurrentPhase, fmt.Errorf("failed to parse AI remediation status message %q: %s", payload, err)
		}

		c.config.Logger.Tracef("AI remediation status for scan %v, result %v: phase=%v percentage=%v jobRunning=%v",
			scanID, resultID, status.CurrentPhase, status.Percentage, status.JobRunning)

		if !status.JobRunning {
			return status.CurrentPhase, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return status.CurrentPhase, fmt.Errorf("error reading AI remediation status stream for scan %v, result %v: %s", scanID, resultID, err)
	}

	return status.CurrentPhase, nil
}

// Fetches the completed AI remediation details (analysis, suggested diffs, generated tests) for one result.
func (c *Cx1Client) GetAIRemediationDetails(scanID, resultID string) (AIRemediationDetails, error) {
	var details AIRemediationDetails

	endpoint := fmt.Sprintf("/remediation/remediation-details/%v/%v", scanID, url.QueryEscape(resultID))

	data, err := c.sendRequest(http.MethodGet, endpoint, nil, nil)
	if err != nil {
		return details, fmt.Errorf("failed to get AI remediation details for scan %v, result %v: %s", scanID, resultID, err)
	}

	err = json.Unmarshal(data, &details)
	return details, err
}

var example_flow = `
POST https://deu.ast.checkmarx.net/api/remediation/remediate
{"scanID":"db9422b5-744d-4d43-acfc-f271e4bf1903","projectID":"a9e5a0eb-bdd9-4b2a-a003-8d81d29480fb","buckets":[{"scannerType":"sast","resultIDs":["HLg6qNYJoMQVCy0oO4HjOw9BOHo="]}]}

Response:
{
    "status": "accepted",
    "published": true,
    "existingState": null,
    "remediationJobId": "cb480c56-b781-4962-8149-034983248fb5"
}





GET https://deu.ast.checkmarx.net/api/ssegateway/remediation-status?engine=sast&scanId=db9422b5-744d-4d43-acfc-f271e4bf1903&resultHash=HLg6qNYJoMQVCy0oO4HjOw9BOHo%3D

response -> message stream
message: {"currentPhase":"COMPLETED","percentage":100.0,"jobRunning":false}



GET https://deu.ast.checkmarx.net/api/remediation/remediation-details/db9422b5-744d-4d43-acfc-f271e4bf1903/HLg6qNYJoMQVCy0oO4HjOw9BOHo%3D
response:
{
    "scanID": "db9422b5-744d-4d43-acfc-f271e4bf1903",
    "results": [
        {
            "resultID": "HLg6qNYJoMQVCy0oO4HjOw9BOHo=",
            "createdAt": "2026-09-30T14:23:48.659785+00:00",
            "finishedAt": "2026-09-30T14:25:08.501250+00:00",
            "autoPr": {
                "status": "unavailable",
                "url": null,
                "error_msg": "missing or invalid repo_id",
                "file_url": null
            },
            "data": {
                "error": null,
                "summary": "Fix Stored XSS vulnerability in ReportGenerator",
                "analysis": {
                    "what": "A Stored Cross-Site Scripting (XSS) vulnerability exists in the report generation flow where data retrieved from the database is rendered directly into an HTML response without sanitization. Attacker-controlled content stored in the database flows from 'dba.java' through 'ReportGenerator.user_lookup()' into 'ReportGenerator.showUserReport()', where it is concatenated into raw HTML and returned to the HTTP response. This allows a stored malicious payload (e.g., '<script>' tags) to execute in any user's browser when they view the affected report page.",
                    "why": "Stored XSS (CWE-79) is a critical severity vulnerability that persists in the database and executes in every victim's browser, enabling session hijacking, credential theft, and malware distribution. Because the payload is stored rather than reflected, it affects all users who view the report — not just a single targeted victim. This violates OWASP Top 10 A03:2021 and can result in full account takeover and regulatory non-compliance.",
                    "how": "Importing 'org.springframework.web.util.HtmlUtils' in 'ReportGenerator.java' and wrapping the database-originated value with 'HtmlUtils.htmlEscape()' in 'showUserReport()' before it is concatenated into the HTML string, breaking the taint flow at the rendering sink. The null-result fallback branch in 'user_lookup()' in 'ReportGenerator.java' is also updated to HTML-escape the 'email' parameter, closing a secondary XSS vector via the URL parameter. A new JUnit 5 test class 'ReportGeneratorXssTest.java' is created under 'src/test/' to verify that script injection, event handler, and attribute-breaking payloads are all properly encoded. The 'spring-boot-starter-test' dependency is added to 'pom.xml' to provide the JUnit 5 testing framework needed by the new tests."
                },
                "pr_title": "Fix Stored XSS vulnerability in ReportGenerator",
                "file_changes": [
                    {
                        "file_path": "src/main/java/org/company/application/simplespringbootapp/ReportGenerator.java",
                        "analysis": "File modified to address security vulnerability",
                        "diff": "diff --git a/src/main/java/org/company/application/simplespringbootapp/ReportGenerator.java b/src/main/java/org/company/application/simplespringbootapp/ReportGenerator.java\nindex 2291e27..9e8eb1e 100644\n--- a/src/main/java/org/company/application/simplespringbootapp/ReportGenerator.java\n+++ b/src/main/java/org/company/application/simplespringbootapp/ReportGenerator.java\n@@ -1,22 +1,25 @@\n package org.company.application.simplespringbootapp;\r\n \r\n import org.company.security.obsolete.sanitizers;\r\n+import org.springframework.web.util.HtmlUtils;\r\n // another small change\r\n public class ReportGenerator {\r\n \tprivate dba db = null;\r\n-\t\r\n+\r\n \tpublic static String showUserReport( String email ) {\r\n-\t\tString response = \"The user's data: \" + user_lookup( email );\r\n+\t\t// HTML-encode the user data returned from the database before embedding\r\n+\t\t// it in the response to prevent Stored XSS (CWE-79).\r\n+\t\tString response = \"The user's data: \" + HtmlUtils.htmlEscape( user_lookup( email ) );\r\n \t\treturn response;\r\n \t}\r\n-\t\r\n+\r\n \tpublic String user_lookup ( String email ) {\r\n \t\t// some kind of lookup\r\n \t\tString c_email = sanitizers.sanitize( email );\r\n-\t\t\r\n+\r\n \t\tString response = db.db_lookup( c_email );\r\n \t\tif ( response == null ) {\r\n-\t\t\tresponse = \"No results for \" + email;\r\n+\t\t\tresponse = \"No results for \" + HtmlUtils.htmlEscape( email );\r\n \t\t}\r\n \t\treturn response;\r\n \t}\r"
                    },
                    {
                        "file_path": "src/test/java/org/company/application/simplespringbootapp/ReportGeneratorXssTest.java",
                        "analysis": "Test file created as part of remediation",
                        "diff": "diff --git a/src/test/java/org/company/application/simplespringbootapp/ReportGeneratorXssTest.java b/src/test/java/org/company/application/simplespringbootapp/ReportGeneratorXssTest.java\nnew file mode 100644\nindex 0000000..6b989fd\n--- /dev/null\n+++ b/src/test/java/org/company/application/simplespringbootapp/ReportGeneratorXssTest.java\n@@ -0,0 +1,198 @@\n+package org.company.application.simplespringbootapp;\n+\n+import org.junit.jupiter.api.BeforeEach;\n+import org.junit.jupiter.api.Test;\n+import org.junit.jupiter.api.DisplayName;\n+\n+import java.lang.reflect.Field;\n+import java.lang.reflect.Method;\n+\n+import static org.junit.jupiter.api.Assertions.*;\n+\n+/**\n+ * Tests for the Stored XSS fix (CWE-79) in ReportGenerator.showUserReport().\n+ *\n+ * The taint flow is:\n+ *   DB data (attacker-controlled) → dba.db_lookup() → ReportGenerator.user_lookup()\n+ *   → ReportGenerator.showUserReport() → HTTP response\n+ *\n+ * The fix applies HtmlUtils.htmlEscape() in showUserReport() before the\n+ * DB-originated data is concatenated into the HTML output, breaking the taint\n+ * flow at the rendering point.\n+ */\n+public class ReportGeneratorXssTest {\n+\n+    private ReportGenerator reportGenerator;\n+    private FakeDba fakeDba;\n+\n+    /**\n+     * Minimal in-process stub for dba so we can control the value returned\n+     * from the database without a real JDBC connection.\n+     */\n+    static class FakeDba extends dba {\n+        private String stubbedResponse;\n+\n+        FakeDba(String stubbedResponse) {\n+            this.stubbedResponse = stubbedResponse;\n+        }\n+\n+        @Override\n+        public String db_lookup(String str) {\n+            return stubbedResponse;\n+        }\n+    }\n+\n+    @BeforeEach\n+    void setUp() throws Exception {\n+        reportGenerator = new ReportGenerator();\n+    }\n+\n+    // -----------------------------------------------------------------------\n+    // Helper: invoke showUserReport() via the static method under test,\n+    // pointing the internal ReportGenerator instance at our FakeDba.\n+    // -----------------------------------------------------------------------\n+\n+    /**\n+     * Injects a FakeDba into the ReportGenerator instance then calls\n+     * user_lookup() directly so we can test the encoding path.\n+     */\n+    private String callUserLookupWith(String email, String dbResponse) throws Exception {\n+        FakeDba fakeDba = new FakeDba(dbResponse);\n+        reportGenerator.init(fakeDba);\n+        // user_lookup is non-static; call through the instance\n+        return reportGenerator.user_lookup(email);\n+    }\n+\n+    // -----------------------------------------------------------------------\n+    // Tests for showUserReport() — the sink method\n+    // -----------------------------------------------------------------------\n+\n+    @Test\n+    @DisplayName(\"showUserReport wraps output in static prefix text\")\n+    void showUserReport_prefixIsPresent() throws Exception {\n+        // We stub user_lookup indirectly by constructing a ReportGenerator\n+        // whose internal db returns a safe string.\n+        FakeDba safe = new FakeDba(\"Alice\");\n+        reportGenerator.init(safe);\n+        // showUserReport is static — call it directly (it internally calls user_lookup\n+        // which uses the instance db; because showUserReport is static we pass email\n+        // to trigger the path).\n+        String result = ReportGenerator.showUserReport(\"alice@example.com\");\n+        assertTrue(result.startsWith(\"The user's data: \"),\n+                \"Response must start with the expected prefix\");\n+    }\n+\n+    @Test\n+    @DisplayName(\"showUserReport HTML-encodes a script tag stored in the DB\")\n+    void showUserReport_encodesScriptTagFromDb() throws Exception {\n+        // Arrange: attacker stored <script>alert(1)</script> in the DB\n+        String xssPayload = \"<script>alert(1)</script>\";\n+        FakeDba maliciousDb = new FakeDba(xssPayload);\n+        reportGenerator.init(maliciousDb);\n+\n+        // Act\n+        String result = ReportGenerator.showUserReport(\"victim@example.com\");\n+\n+        // Assert: raw script tag must NOT appear in output\n+        assertFalse(result.contains(\"<script>\"),\n+                \"Raw <script> tag must be HTML-encoded and must not appear in output\");\n+        assertFalse(result.contains(\"</script>\"),\n+                \"Raw </script> tag must be HTML-encoded and must not appear in output\");\n+\n+        // The encoded form of < and > should be present\n+        assertTrue(result.contains(\"&lt;script&gt;\") || result.contains(\"&#x3C;script&#x3E;\")\n+                        || result.contains(\"&lt;script\"),\n+                \"Script tag must appear in its HTML-encoded form\");\n+    }\n+\n+    @Test\n+    @DisplayName(\"showUserReport HTML-encodes an img onerror XSS vector\")\n+    void showUserReport_encodesImgOnerrorPayload() throws Exception {\n+        String xssPayload = \"<img src=x onerror=alert(document.cookie)>\";\n+        FakeDba maliciousDb = new FakeDba(xssPayload);\n+        reportGenerator.init(maliciousDb);\n+\n+        String result = ReportGenerator.showUserReport(\"victim@example.com\");\n+\n+        assertFalse(result.contains(\"<img\"),\n+                \"Raw <img tag must not appear in output unescaped\");\n+        assertFalse(result.contains(\"onerror\"),\n+                \"onerror attribute must not appear in output unescaped\");\n+    }\n+\n+    @Test\n+    @DisplayName(\"showUserReport HTML-encodes a javascript: URI from the DB\")\n+    void showUserReport_encodesJavascriptUri() throws Exception {\n+        String xssPayload = \"<a href=\\\"javascript:alert(1)\\\">click</a>\";\n+        FakeDba maliciousDb = new FakeDba(xssPayload);\n+        reportGenerator.init(maliciousDb);\n+\n+        String result = ReportGenerator.showUserReport(\"victim@example.com\");\n+\n+        assertFalse(result.contains(\"<a href\"),\n+                \"Raw anchor tag with JS URI must not appear in output\");\n+    }\n+\n+    @Test\n+    @DisplayName(\"showUserReport HTML-encodes double-quote and single-quote characters\")\n+    void showUserReport_encodesQuoteCharacters() throws Exception {\n+        String payload = \"\\\" onmouseover=\\\"alert(1)\";\n+        FakeDba maliciousDb = new FakeDba(payload);\n+        reportGenerator.init(maliciousDb);\n+\n+        String result = ReportGenerator.showUserReport(\"victim@example.com\");\n+\n+        assertFalse(result.contains(\"onmouseover\"),\n+                \"Event handler injected via quote must not appear unescaped\");\n+    }\n+\n+    @Test\n+    @DisplayName(\"showUserReport preserves safe plain-text user data unchanged\")\n+    void showUserReport_preservesSafePlainText() throws Exception {\n+        String safeData = \"John Doe, 42\";\n+        FakeDba safeDb = new FakeDba(safeData);\n+        reportGenerator.init(safeDb);\n+\n+        String result = ReportGenerator.showUserReport(\"john@example.com\");\n+\n+        assertTrue(result.contains(safeData),\n+                \"Safe plain-text content must pass through unaltered\");\n+    }\n+\n+    // -----------------------------------------------------------------------\n+    // Tests for user_lookup() null-path — also encodes the email\n+    // -----------------------------------------------------------------------\n+\n+    @Test\n+    @DisplayName(\"user_lookup null DB result encodes email with XSS payload\")\n+    void userLookup_nullDbResult_encodesEmailPayload() throws Exception {\n+        // db returns null → fallback message includes email which must be encoded\n+        String maliciousEmail = \"<script>alert('xss')</script>@evil.com\";\n+        String result = callUserLookupWith(maliciousEmail, null);\n+\n+        assertFalse(result.contains(\"<script>\"),\n+                \"Raw <script> in email must be HTML-encoded in the null-result fallback\");\n+        assertTrue(result.startsWith(\"No results for \"),\n+                \"Fallback message prefix must be present\");\n+    }\n+\n+    @Test\n+    @DisplayName(\"user_lookup null DB result preserves readable email address\")\n+    void userLookup_nullDbResult_preservesSafeEmail() throws Exception {\n+        String safeEmail = \"test@example.com\";\n+        String result = callUserLookupWith(safeEmail, null);\n+\n+        assertTrue(result.contains(\"test@example.com\"),\n+                \"Safe email address must appear in the fallback message\");\n+    }\n+\n+    @Test\n+    @DisplayName(\"user_lookup returns DB content when DB responds with a value\")\n+    void userLookup_returnsDbContent() throws Exception {\n+        String dbContent = \"UserID: 42, Name: Alice\";\n+        String result = callUserLookupWith(\"alice@example.com\", dbContent);\n+\n+        assertEquals(dbContent, result,\n+                \"user_lookup must return the raw DB value when it is non-null\");\n+    }\n+}"
                    },
                    {
                        "file_path": "pom.xml",
                        "analysis": "File modified to address security vulnerability",
                        "diff": "diff --git a/pom.xml b/pom.xml\nindex 6ccca4b..eadf898 100644\n--- a/pom.xml\n+++ b/pom.xml\n@@ -15,6 +15,11 @@\n \t\t<groupId>org.springframework.boot</groupId>\r\n \t\t<artifactId>spring-boot-starter-web</artifactId>\r\n \t</dependency>\r\n+\t<dependency>\r\n+\t\t<groupId>org.springframework.boot</groupId>\r\n+\t\t<artifactId>spring-boot-starter-test</artifactId>\r\n+\t\t<scope>test</scope>\r\n+\t</dependency>\r\n \t</dependencies>\r\n   <properties>\r\n     <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>\r"
                    }
                ],
                "test_creation": {
                    "error": null,
                    "summary": "Successfully created 1 test files",
                    "analysis": "Generated comprehensive test suite with 1 test files covering security validation",
                    "test_files": [
                        {
                            "file_path": "src/test/java/org/company/application/simplespringbootapp/ReportGeneratorXssTest.java",
                            "file_content": "package org.company.application.simplespringbootapp;\n\nimport org.junit.jupiter.api.BeforeEach;\nimport org.junit.jupiter.api.Test;\nimport org.junit.jupiter.api.DisplayName;\n\nimport java.lang.reflect.Field;\nimport java.lang.reflect.Method;\n\nimport static org.junit.jupiter.api.Assertions.*;\n\n/**\n * Tests for the Stored XSS fix (CWE-79) in ReportGenerator.showUserReport().\n *\n * The taint flow is:\n *   DB data (attacker-controlled) → dba.db_lookup() → ReportGenerator.user_lookup()\n *   → ReportGenerator.showUserReport() → HTTP response\n *\n * The fix applies HtmlUtils.htmlEscape() in showUserReport() before the\n * DB-originated data is concatenated into the HTML output, breaking the taint\n * flow at the rendering point.\n */\npublic class ReportGeneratorXssTest {\n\n    private ReportGenerator reportGenerator;\n    private FakeDba fakeDba;\n\n    /**\n     * Minimal in-process stub for dba so we can control the value returned\n     * from the database without a real JDBC connection.\n     */\n    static class FakeDba extends dba {\n        private String stubbedResponse;\n\n        FakeDba(String stubbedResponse) {\n            this.stubbedResponse = stubbedResponse;\n        }\n\n        @Override\n        public String db_lookup(String str) {\n            return stubbedResponse;\n        }\n    }\n\n    @BeforeEach\n    void setUp() throws Exception {\n        reportGenerator = new ReportGenerator();\n    }\n\n    // -----------------------------------------------------------------------\n    // Helper: invoke showUserReport() via the static method under test,\n    // pointing the internal ReportGenerator instance at our FakeDba.\n    // -----------------------------------------------------------------------\n\n    /**\n     * Injects a FakeDba into the ReportGenerator instance then calls\n     * user_lookup() directly so we can test the encoding path.\n     */\n    private String callUserLookupWith(String email, String dbResponse) throws Exception {\n        FakeDba fakeDba = new FakeDba(dbResponse);\n        reportGenerator.init(fakeDba);\n        // user_lookup is non-static; call through the instance\n        return reportGenerator.user_lookup(email);\n    }\n\n    // -----------------------------------------------------------------------\n    // Tests for showUserReport() — the sink method\n    // -----------------------------------------------------------------------\n\n    @Test\n    @DisplayName(\"showUserReport wraps output in static prefix text\")\n    void showUserReport_prefixIsPresent() throws Exception {\n        // We stub user_lookup indirectly by constructing a ReportGenerator\n        // whose internal db returns a safe string.\n        FakeDba safe = new FakeDba(\"Alice\");\n        reportGenerator.init(safe);\n        // showUserReport is static — call it directly (it internally calls user_lookup\n        // which uses the instance db; because showUserReport is static we pass email\n        // to trigger the path).\n        String result = ReportGenerator.showUserReport(\"alice@example.com\");\n        assertTrue(result.startsWith(\"The user's data: \"),\n                \"Response must start with the expected prefix\");\n    }\n\n    @Test\n    @DisplayName(\"showUserReport HTML-encodes a script tag stored in the DB\")\n    void showUserReport_encodesScriptTagFromDb() throws Exception {\n        // Arrange: attacker stored <script>alert(1)</script> in the DB\n        String xssPayload = \"<script>alert(1)</script>\";\n        FakeDba maliciousDb = new FakeDba(xssPayload);\n        reportGenerator.init(maliciousDb);\n\n        // Act\n        String result = ReportGenerator.showUserReport(\"victim@example.com\");\n\n        // Assert: raw script tag must NOT appear in output\n        assertFalse(result.contains(\"<script>\"),\n                \"Raw <script> tag must be HTML-encoded and must not appear in output\");\n        assertFalse(result.contains(\"</script>\"),\n                \"Raw </script> tag must be HTML-encoded and must not appear in output\");\n\n        // The encoded form of < and > should be present\n        assertTrue(result.contains(\"&lt;script&gt;\") || result.contains(\"&#x3C;script&#x3E;\")\n                        || result.contains(\"&lt;script\"),\n                \"Script tag must appear in its HTML-encoded form\");\n    }\n\n    @Test\n    @DisplayName(\"showUserReport HTML-encodes an img onerror XSS vector\")\n    void showUserReport_encodesImgOnerrorPayload() throws Exception {\n        String xssPayload = \"<img src=x onerror=alert(document.cookie)>\";\n        FakeDba maliciousDb = new FakeDba(xssPayload);\n        reportGenerator.init(maliciousDb);\n\n        String result = ReportGenerator.showUserReport(\"victim@example.com\");\n\n        assertFalse(result.contains(\"<img\"),\n                \"Raw <img tag must not appear in output unescaped\");\n        assertFalse(result.contains(\"onerror\"),\n                \"onerror attribute must not appear in output unescaped\");\n    }\n\n    @Test\n    @DisplayName(\"showUserReport HTML-encodes a javascript: URI from the DB\")\n    void showUserReport_encodesJavascriptUri() throws Exception {\n        String xssPayload = \"<a href=\\\"javascript:alert(1)\\\">click</a>\";\n        FakeDba maliciousDb = new FakeDba(xssPayload);\n        reportGenerator.init(maliciousDb);\n\n        String result = ReportGenerator.showUserReport(\"victim@example.com\");\n\n        assertFalse(result.contains(\"<a href\"),\n                \"Raw anchor tag with JS URI must not appear in output\");\n    }\n\n    @Test\n    @DisplayName(\"showUserReport HTML-encodes double-quote and single-quote characters\")\n    void showUserReport_encodesQuoteCharacters() throws Exception {\n        String payload = \"\\\" onmouseover=\\\"alert(1)\";\n        FakeDba maliciousDb = new FakeDba(payload);\n        reportGenerator.init(maliciousDb);\n\n        String result = ReportGenerator.showUserReport(\"victim@example.com\");\n\n        assertFalse(result.contains(\"onmouseover\"),\n                \"Event handler injected via quote must not appear unescaped\");\n    }\n\n    @Test\n    @DisplayName(\"showUserReport preserves safe plain-text user data unchanged\")\n    void showUserReport_preservesSafePlainText() throws Exception {\n        String safeData = \"John Doe, 42\";\n        FakeDba safeDb = new FakeDba(safeData);\n        reportGenerator.init(safeDb);\n\n        String result = ReportGenerator.showUserReport(\"john@example.com\");\n\n        assertTrue(result.contains(safeData),\n                \"Safe plain-text content must pass through unaltered\");\n    }\n\n    // -----------------------------------------------------------------------\n    // Tests for user_lookup() null-path — also encodes the email\n    // -----------------------------------------------------------------------\n\n    @Test\n    @DisplayName(\"user_lookup null DB result encodes email with XSS payload\")\n    void userLookup_nullDbResult_encodesEmailPayload() throws Exception {\n        // db returns null → fallback message includes email which must be encoded\n        String maliciousEmail = \"<script>alert('xss')</script>@evil.com\";\n        String result = callUserLookupWith(maliciousEmail, null);\n\n        assertFalse(result.contains(\"<script>\"),\n                \"Raw <script> in email must be HTML-encoded in the null-result fallback\");\n        assertTrue(result.startsWith(\"No results for \"),\n                \"Fallback message prefix must be present\");\n    }\n\n    @Test\n    @DisplayName(\"user_lookup null DB result preserves readable email address\")\n    void userLookup_nullDbResult_preservesSafeEmail() throws Exception {\n        String safeEmail = \"test@example.com\";\n        String result = callUserLookupWith(safeEmail, null);\n\n        assertTrue(result.contains(\"test@example.com\"),\n                \"Safe email address must appear in the fallback message\");\n    }\n\n    @Test\n    @DisplayName(\"user_lookup returns DB content when DB responds with a value\")\n    void userLookup_returnsDbContent() throws Exception {\n        String dbContent = \"UserID: 42, Name: Alice\";\n        String result = callUserLookupWith(\"alice@example.com\", dbContent);\n\n        assertEquals(dbContent, result,\n                \"user_lookup must return the raw DB value when it is non-null\");\n    }\n}\n",
                            "test_type": "unit",
                            "coverage_description": "Security validation test for vulnerability fix",
                            "framework_used": ""
                        }
                    ],
                    "total_tests_created": 1,
                    "coverage_areas": [
                        "security_validation",
                        "regression_testing"
                    ]
                }
            },
            "remediationID": "c8fbae98-8f9f-4065-85c7-d2b83647f329"
        }
    ]
}
`
