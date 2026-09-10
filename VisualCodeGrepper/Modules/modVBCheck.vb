' VisualCodeGrepper - Code security scanner
' Copyright (C) 2012-2014 Nick Dunn and John Murray
'
' This program is free software: you can redistribute it and/or modify
' it under the terms of the GNU General Public License as published by
' the Free Software Foundation, either version 3 of the License, or
' (at your option) any later version.
'
' This program is distributed in the hope that it will be useful,
' but WITHOUT ANY WARRANTY; without even the implied warranty of
' MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
' GNU General Public License for more details.
'
' You should have received a copy of the GNU General Public License
' along with this program.  If not, see <http://www.gnu.org/licenses/>.

Option Explicit On

Imports System.Text.RegularExpressions

Module modVBCheck

    ' Specific checks for VB code
    '============================

    Public Sub CheckVBCode(CodeLine As String, FileName As String)
        ' Carry out any specific checks for the language in question.
        ' A lot of our VB checks are generic ASP checks and use the functions
        ' in the C# module.
        '====================================================================

        CheckInputValidation(CodeLine, FileName)        '(same check will work for VB and C# - hence we use function in C# module)
        CheckSQLInjection(CodeLine, FileName)           ' Check for SQLi (same check will work for VB and C# - hence we use function in C# module)
        CheckXSS(CodeLine, FileName)                    ' Check for XSS (same check will work for VB and C# - hence we use function in C# module)
        CheckSecureStorage(CodeLine, FileName)          ' Are sensitive variables stored without using SecureString? (same check will work for VB and C# - hence we use function in C# module)
        CheckLogDisplay(CodeLine, FileName)             ' Is data sanitised before being written to logs? (same check will work for VB and C# - hence we use function in C# module)
        CheckFileRace(CodeLine, FileName)               ' Check for race conditions and TOCTOU vulns (same check will work for VB and C# - hence we use function in C# module)
        CheckHTTPRedirect(CodeLine, FileName)           ' Check for safe redirects and safe use of URLs (same check will work for VB and C# - hence we use function in C# module)
        CheckRandomisation(CodeLine, FileName)          ' Locate any use of randomisation functions that are not cryptographically secure
        CheckSAML2Validation(CodeLine, FileName)        ' Check for correct implementation of inherited SAML2 functions
        CheckUnsafeTempFiles(CodeLine, FileName)        ' Check for static/obvious filenames for temp files
        CheckCryptoKeys(CodeLine, FileName)             ' Check for hardcoded keys
        CheckExecutable(CodeLine, FileName)             ' Check for unvalidated variables being executed via cmd line/system calls (same check will work for VB and C# - hence we use function in C# module)
        CheckWebConfig(CodeLine, FileName)              ' Check config file to determine whether .NET debugging and default errors are enabled
        CheckInsecureSerialization(CodeLine, FileName)  ' Check for potential insecure deserialization vulnerabilities
        CheckOpenRedirect(CodeLine, FileName)           ' Check for potential open redirect vulnerabilities
        CheckXXE(CodeLine, FileName)                    ' Check for XXE
        CheckUnrestrictedFileUpload(CodeLine, FileName) ' Check for Unrestricted File Upload
        CheckUnsafeMemoryOperationsVB(CodeLine, FileName)       ' Check for potential process injection or hollowing techniques

        '== Extended ruleset ==
        CheckVBWeakCryptography(CodeLine, FileName)      ' Broken hashes/ciphers, ECB, hard-coded keys, weak KDF and key sizes
        CheckVBCertificateValidation(CodeLine, FileName) ' Disabled TLS cert validation and obsolete protocol versions
        CheckVBPathTraversal(CodeLine, FileName)         ' User-controlled filesystem paths and Zip Slip
        CheckVBSSRF(CodeLine, FileName)                  ' User-controlled outbound request destinations
        CheckVBDeserializationExtended(CodeLine, FileName) ' TypeNameHandling, unsafe formatters, ViewState MAC and machineKey
        CheckVBCookieAndSession(CodeLine, FileName)      ' Insecure cookie flags, cookieless sessions, disabled anti-forgery
        CheckVBCorsPolicy(CodeLine, FileName)            ' Permissive or credentialed CORS configuration
        CheckVBHardcodedSecrets(CodeLine, FileName)      ' API keys, private keys and credentials embedded in source
        CheckVBDynamicCodeExecution(CodeLine, FileName)  ' Assembly loading, runtime compilation, CallByName, process launch
        CheckVBInformationLeakage(CodeLine, FileName)    ' Exception detail returned to client, On Error Resume Next
        CheckVBHeaderInjection(CodeLine, FileName)       ' Response splitting and Host header trust
        CheckVBAuthorisationWeakness(CodeLine, FileName) ' Weak password policy, lockout and impersonation handling

        If Regex.IsMatch(CodeLine, "\S*(Password|password|pwd|passwd)\S*\.(ToLower|ToUpper)\s*\(") Then
            frmMain.ListCodeIssue("Unsafe Password Management", "The application appears to handle passwords in a case-insensitive manner. This can greatly increase the likelihood of successful brute-force and/or dictionary attacks.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

    End Sub

    Public Enum Rules
        MapControllerRoute   ' Identifies the use of MapControllerRoute, which is used to configure routes in ASP.NET MVC.
        MapHttpRoute         ' Identifies the use of MapHttpRoute, which configures Web API routes. It might expose sensitive routes if misconfigured.
        MapPageRoute         ' Detects usage of MapPageRoute, which configures routing for WebForms pages. Hardcoded routes might be a security concern.
        MapRoute             ' Checks for MapRoute, used to define routing in MVC. Possible hardcoded routes should be reviewed.
        CreateRoute          ' Detects the use of CreateRoute, which might create routes dynamically but can expose sensitive paths.
        MapGet               ' Detects MapGet, used in minimal APIs to handle HTTP GET requests. Should check for any unsafe path configurations.
        MapPost              ' Detects MapPost, used in minimal APIs to handle HTTP POST requests. Needs to ensure data validation on POST.
        HttpGet              ' Detects HttpGet, which marks an action as responding to GET requests. Watch for information exposure via query strings.
        HttpPost             ' Detects HttpPost, which marks an action as responding to POST requests. Ensure proper validation to avoid data leaks.
        connectionString     ' Detects hardcoded connection strings. Hardcoded database connection strings should be replaced with secure alternatives like configuration files or environment variables.
    End Enum

    Private Sub CheckRandomisation(CodeLine As String, FileName As String)
        ' Check for any random functions that are not cryptographically secure
        '=====================================================================

        '== Check for non-time-based seed ==
        If Regex.IsMatch(CodeLine, "\bRandomize\b\(\)") Or Regex.IsMatch(CodeLine, "\bRandomize\b\(\w*(T|t)ime\w*\)") Then
            ctCodeTracker.HasSeed = False
        ElseIf Regex.IsMatch(CodeLine, "\bRandomize\b\(\S+\)") Then
            ctCodeTracker.HasSeed = True
        End If

        '== Check for unsafe functions Next() or NextBytes() ==
        If Regex.IsMatch(CodeLine, "\bRnd\b\s*\(") Then
            If ctCodeTracker.HasSeed Then
                frmMain.ListCodeIssue("Use of Deterministic Pseudo-Random Values", "The code appears to use the Next() and/or NextBytes() functions. The resulting values, while appearing random to a casual observer, are predictable and may be enumerated by a skilled and determined attacker, although this is partly mitigated by a seed that does not appear to be time-based.", FileName, CodeIssue.STANDARD, CodeLine)
            Else
                frmMain.ListCodeIssue("Use of Deterministic Pseudo-Random Values", "The code appears to use the Next() and/or NextBytes() functions without a seed to generate pseudo-random values. The resulting values, while appearing random to a casual observer, are predictable and may be enumerated by a skilled and determined attacker.", FileName, CodeIssue.MEDIUM, CodeLine)
            End If
        End If

    End Sub

    Private Sub CheckSAML2Validation(CodeLine As String, FileName As String)
        ' Check for validation of SAML2 conditions
        '=========================================

        '== Locate entry into overridden SAML2 function ==
        If ctCodeTracker.IsSamlFunction = False And Regex.IsMatch(CodeLine, "\bOverrides\b\s+\b(Sub|Function)\b\s+\bValidateConditions\b\(\bSaml2Conditions\b") Then
            ctCodeTracker.IsSamlFunction = True
        ElseIf ctCodeTracker.IsSamlFunction = True Then
            '== Report issue if function is empty ==
            If (CodeLine.Trim <> "" And CodeLine.Trim <> "{" And CodeLine.Trim <> "}") Then
                If Regex.IsMatch(CodeLine, "\s*\S*\s*validate|encode|sanitize|sanitise\S*\(\S*\s*conditions") Then ctCodeTracker.IsSamlFunction = False
            Else
                ctCodeTracker.IsSamlFunction = ctCodeTracker.TrackBraces(CodeLine, ctCodeTracker.ClassBraces)
                If ctCodeTracker.IsSamlFunction = False Then
                    frmMain.ListCodeIssue("Insufficient SAML2 Condition Validation", "The code includes a token handling class that inherits from Saml2SecurityTokenHandler. It appears not to perform any validation on the Saml2Conditions object passed, violating its contract with the superclass and undermining authentication/authorisation conditions.", FileName, CodeIssue.MEDIUM)
                End If
            End If
            If Regex.IsMatch(CodeLine, "\bEnd\b\s+\b(Sub|Function)\b") Then ctCodeTracker.IsSamlFunction = True
        End If

    End Sub

    Private Sub CheckUnsafeTempFiles(CodeLine As String, FileName As String)
        ' Identify any creation of temp files with static names
        '======================================================

        If Regex.IsMatch(CodeLine, "(file\S*|File\S*|\.FileName)\s+\=\s+\""\S*(temp|tmp)\S*\""\,") Then
            frmMain.ListCodeIssue("Unsafe Temporary File Allocation", "The application appears to create a temporary file with a static, hard-coded name. This causes security issues in the form of a classic race condition (an attacker creates a file with the same name between the application's creation and attempted usage) or a symbolic linbk attack where an attacker creates a symbolic link at the temporary file location.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

    End Sub

    Private Sub CheckCryptoKeys(CodeLine As String, FileName As String)
        ' Identify any hardcoded static keys and IVs
        '===========================================

        If Regex.IsMatch(CodeLine, "\b(Private|Public|Dim)\b\s+\b(Const|ReadOnly)\b\s+\w*(crypt|Crypt|CRYPT|key|Key|KEY)\w*\s+As\s+String\s*\=\s*\""") Or
            Regex.IsMatch(CodeLine, "\b(Private|Public|Dim)\b\s+\b(Const|ReadOnly)\b\s+\w*(iv|Iv|IV)\s+As\s+Byte\(\)\s*\=\s*New\s+Byte\s*\(\w*\)\s*\{") Then
            frmMain.ListCodeIssue("Hardcoded Crypto Key", "The code appears to use hardcoded encryption keys. These can be rendered visible with the use of debugger or hex editor, exposing encrypted data.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

    End Sub

    Public Sub CheckWebConfig(CodeLine As String, FileName As String)
        ' Report any security issues in config file such as debugging or .NET default errors
        '===================================================================================

        If Not FileName.ToLower().EndsWith("web.config") Then Exit Sub

        ' Check for .NET Default Errors Enabled
        If Regex.IsMatch(CodeLine, "<\s*customErrors\s+mode\s*=\s*""Off""\s*/>") Then
            frmMain.ListCodeIssue(".NET Default Errors Enabled", "The application is configured to display .NET default errors. This can provide an attacker with useful information and should not be used in a live application.", FileName, CodeIssue.MEDIUM)

            ' Check for .NET Debugging Enabled
        ElseIf Regex.IsMatch(CodeLine, "\bdebug\b\s*=\s*""true""") Then
            frmMain.ListCodeIssue(".NET Debugging Enabled", "The application is configured to return .NET debug information. This can provide an attacker with useful information and should not be used in a live application.", FileName, CodeIssue.MEDIUM)

            ' Check for IIS Custom Errors Enabled
        ElseIf Regex.IsMatch(CodeLine, "<\s*customErrors\s+mode\s*=\s*""On""\s+defaultRedirect\s*=\s*""~/Error""\s*/>") Then
            frmMain.ListCodeIssue("IIS Custom Errors Enabled", "Custom errors are properly configured to prevent accidental leakage of error details to clients.", FileName, CodeIssue.LOW)

            ' Check for HTTP Errors Mode set to Custom
        ElseIf Regex.IsMatch(CodeLine, "<\s*httpErrors\s+errorMode\s*=\s*""Custom""\s*/>") Then
            frmMain.ListCodeIssue("HTTP Errors Custom Mode Enabled", "HTTP errors are set to custom mode, improving user experience and preventing error details leakage.", FileName, CodeIssue.LOW)

            ' Check for Debug Compilation Disabled
        ElseIf Regex.IsMatch(CodeLine, "<\s*compilation\s+debug\s*=\s*""false""\s*/>") Then
            frmMain.ListCodeIssue("Debug Compilation Disabled", "The debug compilation setting is correctly set to false to avoid performance issues in production.", FileName, CodeIssue.LOW)

            ' Check for IIS Version Exposure Prevention
        ElseIf Regex.IsMatch(CodeLine, "<\s*modules\s+runAllManagedModulesForAllRequests\s*=\s*""true""\s*/>") Then
            frmMain.ListCodeIssue("IIS Version Exposure Prevention", "The configuration ensures that the IIS version is not exposed via the Server HTTP response header.", FileName, CodeIssue.LOW)

            ' Check for Removing Server Header in IIS 7+
        ElseIf Regex.IsMatch(CodeLine, "<\s*requestFiltering\s+removeServerHeader\s*=\s*""true""\s*/>") Then
            frmMain.ListCodeIssue("IIS Server Header Removal", "The configuration ensures that the Server HTTP response header is removed in IIS 7+ to prevent IIS version exposure.", FileName, CodeIssue.LOW)

            ' Check for ASP.NET Version Exposure Prevention
        ElseIf Regex.IsMatch(CodeLine, "<\s*remove\s+name\s*=\s*""X-Powered-By""\s*/>") Then
            frmMain.ListCodeIssue("ASP.NET Version Exposure Prevention", "The X-Powered-By header is removed to prevent ASP.NET version exposure.", FileName, CodeIssue.LOW)

            ' Check for ASP.NET Version Header Removal Using Rewrite Rule
        ElseIf Regex.IsMatch(CodeLine, "<\s*rule\s+name\s*=\s*""Remove X-Powered-By HTTP response header"">") Then
            frmMain.ListCodeIssue("ASP.NET Version Exposure Prevention Using Rewrite", "An IIS URL Rewrite rule is used to remove the X-Powered-By header, preventing ASP.NET version exposure.", FileName, CodeIssue.LOW)

            ' Check for ASP.NET Version Header Disabled
        ElseIf Regex.IsMatch(CodeLine, "<\s*httpRuntime\s+enableVersionHeader\s*=\s*""false""\s*/>") Then
            frmMain.ListCodeIssue("ASP.NET Version Header Disabled", "The version header in ASP.NET is disabled to prevent version exposure.", FileName, CodeIssue.LOW)

            ' Check for HTTPS Requirement
        ElseIf Regex.IsMatch(CodeLine, "<\s*httpRedirect\s+enabled\s*=\s*""false""\s*/>") Then
            frmMain.ListCodeIssue("HTTPS Requirement in Root Site", "The configuration disables HTTP redirects, ensuring that HTTPS is required.", FileName, CodeIssue.LOW)

            ' Check for HTTP-Only and SSL-Only Cookies
        ElseIf Regex.IsMatch(CodeLine, "<\s*httpCookies\s+httpOnlyCookies\s*=\s*""true""\s+requireSSL\s*=\s*""true""\s*/>") Then
            frmMain.ListCodeIssue("HTTP-Only and SSL-Only Cookies Enabled", "The cookies are set to HTTP-Only and SSL-Only, protecting against XSS and man-in-the-middle attacks.", FileName, CodeIssue.LOW)

            ' Check for SSL Requirement for Forms Authentication
        ElseIf Regex.IsMatch(CodeLine, "<\s*forms\s+requireSSL\s*=\s*""true""\s*/>") Then
            frmMain.ListCodeIssue("SSL Required for Forms Authentication", "The configuration ensures that SSL is required for forms authentication cookies, protecting against unauthorized access.", FileName, CodeIssue.LOW)

            ' Check for HSTS (Strict Transport Security)
        ElseIf Regex.IsMatch(CodeLine, "<\s*appendHeader\s+name\s*=\s*""Strict-Transport-Security""\s+value\s*=\s*""max-age=31536000""\s*/>") Then
            frmMain.ListCodeIssue("Strict Transport Security (HSTS) Enabled", "The Strict-Transport-Security header is enabled, helping prevent HTTPS Strip and man-in-the-middle attacks.", FileName, CodeIssue.LOW)

            ' Check for Click-Jacking Protection (X-Frame-Options)
        ElseIf Regex.IsMatch(CodeLine, "<\s*add\s+name\s*=\s*""X-Frame-Options""\s+value\s*=\s*""DENY""\s*/>") Then
            frmMain.ListCodeIssue("Click-Jacking Protection", "The X-Frame-Options header is set to DENY, preventing Click-Jacking attacks.", FileName, CodeIssue.LOW)

            ' Check for X-Frame-Options SAMEORIGIN
        ElseIf Regex.IsMatch(CodeLine, "<\s*add\s+name\s*=\s*""X-Frame-Options""\s+value\s*=\s*""SAMEORIGIN""\s*/>") Then
            frmMain.ListCodeIssue("Framing Allowed from Same Origin", "The X-Frame-Options header is set to SAMEORIGIN, allowing framing only from the same origin.", FileName, CodeIssue.LOW)

            ' Check for Cache Control
        ElseIf Regex.IsMatch(CodeLine, "<\s*meta\s+http-equiv\s*=\s*""Cache-Control""\s+content\s*=\s*""no-cache, no-store""\s*/>") Then
            frmMain.ListCodeIssue("Cache Control for Secure Content", "Cache-Control is set to no-cache, no-store to prevent secure content from being cached.", FileName, CodeIssue.LOW)

            ' Check for Machine Encryption and Decryption Keys
        ElseIf Regex.IsMatch(CodeLine, "<\s*machineKey\s+decryption\s*=\s*""AES""\s+decryptionKey\s*=\s*""[A-Za-z0-9]+""\s+validation\s*=\s*""SHA1""\s+validationKey\s*=\s*""[A-Za-z0-9]+""\s*/>") Then
            frmMain.ListCodeIssue("Machine Encryption/Decryption Keys Configured", "Machine keys for encryption and decryption are explicitly configured.", FileName, CodeIssue.LOW)

            ' Check for Trace.axd Disabled
        ElseIf Regex.IsMatch(CodeLine, "<\s*trace\s+enabled\s*=\s*""false""\s+localOnly\s*=\s*""true""\s*/>") Then
            frmMain.ListCodeIssue("Trace.axd Disabled", "Trace.axd is disabled, preventing accidental information leakage in production environments.", FileName, CodeIssue.LOW)

            ' Check for Azure ARRAffinity Cookie
        ElseIf Regex.IsMatch(CodeLine, "<\s*add\s+name\s*=\s*""Arr-Disable-Session-Affinity""\s+value\s*=\s*""True""\s*/>") Then
            frmMain.ListCodeIssue("ARR Affinity Cookie Disabled", "ARR Affinity cookie is disabled, preventing insecure session affinity cookies in Azure.", FileName, CodeIssue.LOW)

            ' Check for Role Manager SSL Requirement
        ElseIf Regex.IsMatch(CodeLine, "<\s*roleManager\s+cookieRequireSSL\s*=\s*""true""\s*/>") Then
            frmMain.ListCodeIssue("Secure Role Manager Cookies", "Role Manager cookies are set to require SSL, enhancing security.", FileName, CodeIssue.LOW)

            ' Check for Required SSL for ViewState
        ElseIf Regex.IsMatch(CodeLine, "<\s*pages\s+requireSSL\s*=\s*""true""\s+/>\s*") Then
            frmMain.ListCodeIssue("SSL Required for ViewState", "ViewState is set to require SSL, enhancing security for state management.", FileName, CodeIssue.LOW)

        End If
    End Sub

    Public Sub CheckInsecureSerialization(CodeLine As String, FileName As String)
        ' Check for insecure serialization and deserialization vulnerabilities
        '=====================================================================

        Dim strClassName As String = ""
        Dim arrFragments As String()

        ' Regex patterns for serialization and sanitization checks
        Dim serializerPattern As String = "\b(?:BinaryFormatter|SoapFormatter|XmlSerializer|DataContractSerializer|JavaScriptSerializer)\b"
        Dim sanitizationPattern As String = "\b(?:SanitizeInput|Escape|HtmlEncode|UrlEncode|Clean|Validate)\s*\("
        Dim gadgetPattern As String = "\b(?:System.Diagnostics.Process|System.Runtime.InteropServices.Marshal|System.IO.File|System.Security.Principal.WindowsIdentity|System.Web.UI.Page)\b"

        ' Check for insecure deserialization
        If Regex.IsMatch(CodeLine, "\.(Deserialize|ReadObject)\s*\(") Then
            frmMain.ListCodeIssue("Unsafe Object Deserialization", "The code allows objects to be deserialized. This can allow potentially hostile objects to be instantiated directly from data held in the filesystem.", FileName, CodeIssue.STANDARD, CodeLine)
        End If

        ' Check if serialization or deserialization classes are used
        If Regex.IsMatch(CodeLine, serializerPattern) Then
            ' Check for common sanitization methods
            If Not Regex.IsMatch(CodeLine, sanitizationPattern) Then
                frmMain.ListCodeIssue("Insecure Deserialization", "The application may be deserializing untrusted input. Verify that input is validated before deserialization.", FileName, CodeIssue.HIGH, CodeLine)
            End If

            ' Check for known gadgets that could be used for exploitation
            If Regex.IsMatch(CodeLine, gadgetPattern) Then
                frmMain.ListCodeIssue("Insecure Deserialization - Gadget Detected", "Potentially dangerous gadget found. Review code for exploitation risks associated with deserialization.", FileName, CodeIssue.HIGH, CodeLine)
            End If
        End If

        ' Check for TypeNameHandling usage in JsonConvert.DeserializeObject
        If Regex.IsMatch(CodeLine, "JsonConvert\.DeserializeObject\s*\(.*,\s*new\s+JsonSerializerSettings\s*\(\)\s*{\s*TypeNameHandling\s*=\s*TypeNameHandling\.All\s*\}\s*\)") Then
            frmMain.ListCodeIssue("Deserialization Risk", "TypeNameHandling is set to All, which may allow unsafe type resolution and deserialization attacks. Consider using None or Objects with strict type controls.", FileName, CodeIssue.CRITICAL, CodeLine)
        ElseIf Regex.IsMatch(CodeLine, "JsonConvert\.DeserializeObject\s*\(.*,\s*new\s+JsonSerializerSettings\s*\(\)\s*{\s*TypeNameHandling\s*=\s*TypeNameHandling\.Objects\s*\}\s*\)") Then
            frmMain.ListCodeIssue("Deserialization Risk", "TypeNameHandling is set to Objects, which may allow unsafe deserialization attacks. Ensure that untrusted input is not allowed.", FileName, CodeIssue.HIGH, CodeLine)
        End If

        ' Check for serialization
        If ctCodeTracker.IsSerializable = False And CodeLine.Contains("using System.Runtime.Serialization") Then
            ' Serialization is implemented in the code module
            ctCodeTracker.IsSerializable = True
        ElseIf ctCodeTracker.IsSerializable = True And ctCodeTracker.IsSerializableClass = False And CodeLine.Contains("[Serializable") Then
            ' Serialization is implemented for the class
            ctCodeTracker.IsSerializableClass = True
        ElseIf ctCodeTracker.IsSerializable = True And ctCodeTracker.IsSerializableClass = False And (CodeLine.Contains("[assembly: SecurityPermission(") Or CodeLine.Contains("[SecurityPermissionAttribute(")) Then
            ' Serialization is safely implemented so discontinue the checks
            ctCodeTracker.IsSerializable = False
            ctCodeTracker.IsSerializableClass = False
        ElseIf ctCodeTracker.IsSerializableClass = True And CodeLine.Contains("public class ") Then
            ' Extract the vulnerable class name and write out results
            ctCodeTracker.IsSerializableClass = False ' Reset after class name is found
            arrFragments = CodeLine.Split("{")
            arrFragments = arrFragments.First().Split(":")
            strClassName = GetLastItem(arrFragments.First())
            If Regex.IsMatch(strClassName, "^[a-zA-Z0-9_]*$") Then
                frmMain.ListCodeIssue("Unsafe Object Serialization", "The code allows the object " & strClassName & " to be serialized. This can allow potentially sensitive data to be saved to the filesystem.", FileName, CodeIssue.STANDARD, CodeLine)
            End If
        End If

    End Sub

    Public Sub CheckOpenRedirect(CodeLine As String, FileName As String)
        ' Regex để tìm các pattern chỉ ra khả năng redirect trong VB.NET
        Dim redirectPattern As String = "\bResponse\.Redirect\s*\(\s*[^\)]+\s*\)|\bServer\.Transfer\s*\(\s*[^\)]+\s*\)"
        Dim queryParamPattern As String = "\?url=|redirect=|returnUrl="

        ' Kiểm tra sự hiện diện của redirect và tham số query
        If Regex.IsMatch(CodeLine, redirectPattern, RegexOptions.IgnoreCase) OrElse Regex.IsMatch(CodeLine, queryParamPattern, RegexOptions.IgnoreCase) Then
            ' Kiểm tra xem có các phương thức kiểm tra hoặc làm sạch URL không
            Dim validationPattern As String = "\b(StartsWith|UrlEncode|IsLocalUrl|SanitizeInput|Validate)\s*\("

            If Not Regex.IsMatch(CodeLine, validationPattern, RegexOptions.IgnoreCase) Then
                frmMain.ListCodeIssue("Open Redirect Vulnerability",
                "The application appears to allow open redirects without proper validation or sanitization of the URL. Ensure all redirect URLs are validated to prevent open redirects.",
                FileName, CodeIssue.HIGH, CodeLine)
            End If
        End If
    End Sub

    Public Sub CheckUnrestrictedFileUpload(CodeLine As String, FileName As String)
        Dim isUploadFunctionPresent As Boolean = False
        Dim allowedExtensions As String() = {".txt", ".jpg", ".jpeg", ".png", ".gif", ".pdf", ".mp4", ".mov", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".xps"}

        ' Check for file upload elements in VB.NET
        If CodeLine.Contains("Request.Files") Or CodeLine.Contains("HttpPostedFileBase") Or
        CodeLine.Contains("FileUpload") Or CodeLine.Contains("UploadFile") Or CodeLine.Contains("SaveAs") Or
        CodeLine.Contains("IFormFile") Or CodeLine.Contains("Request.Form.Files") Or CodeLine.Contains("(MapPath") Or
        CodeLine.Contains("PostedFile.SaveAs") Then
            isUploadFunctionPresent = True
        End If

        ' Check for allowed file extensions
        If isUploadFunctionPresent Then
            Dim hasAllowedExtensions As Boolean = False
            For Each extension As String In allowedExtensions
                If CodeLine.Contains(extension) Then
                    hasAllowedExtensions = True
                    Exit For
                End If
            Next

            If Not hasAllowedExtensions Then
                frmMain.ListCodeIssue("Insecure File Upload", "Allowed file extensions are not properly defined.", FileName, CodeIssue.HIGH, CodeLine)
            End If

            ' Check for file size limit validation
            If Not (CodeLine.Contains(".ContentLength") Or CodeLine.Contains(".Length") Or CodeLine.Contains(".Size")) Then
                frmMain.ListCodeIssue("File Size Validation Missing", "File size limits are not validated.", FileName, CodeIssue.MEDIUM, CodeLine)
            End If
        End If
    End Sub

    Public Sub CheckXXE(CodeLine As String, FileName As String)
        ' Check XmlDocument in VB.NET with XmlResolver not set to Nothing
        If Regex.IsMatch(CodeLine, "Dim\s+parser\s*As\s*New\s+XmlDocument\(\);") Then
            If Regex.IsMatch(CodeLine, "parser\.XmlResolver\s*=\s*New\s+XmlUrlResolver\(\);") Then
                frmMain.ListCodeIssue("XXE Vulnerability", "The code is vulnerable to XXE attacks as it uses XmlUrlResolver. Consider setting XmlResolver to Nothing.", FileName, CodeIssue.HIGH, CodeLine)
            ElseIf Regex.IsMatch(CodeLine, "parser\.XmlResolver\s*=\s*Nothing;") Then
                ' Compliant code, do nothing
            Else
                frmMain.ListCodeIssue("XXE Vulnerability", "The XmlResolver should be set to Nothing to prevent XXE attacks.", FileName, CodeIssue.HIGH, CodeLine)
            End If
        End If

        ' Check XmlTextReader and DtdProcessing in VB.NET
        If Regex.IsMatch(CodeLine, "Dim\s+reader\s*As\s*New\s+XmlTextReader\(\s*.*\s*\);") Then
            If Not Regex.IsMatch(CodeLine, "reader\.DtdProcessing\s*=\s*DtdProcessing\.Prohibit;") Then
                frmMain.ListCodeIssue("XXE Vulnerability", "XmlTextReader should have DtdProcessing set to Prohibit to prevent XXE attacks.", FileName, CodeIssue.HIGH, CodeLine)
            End If
        End If
    End Sub

    Private Sub CheckMisconfiguredRoutes(CodeLine As String, FileName As String)
        ' Check for potential misconfigurations in routes and HTTP methods defined in enum.Rules
        '=======================================================================================

        ' Create a dictionary with the rules and corresponding warning messages
        Dim rulesDictionary As New Dictionary(Of Rules, String) From {
        {Rules.MapControllerRoute, "Possible misconfigured route: MapControllerRoute"},
        {Rules.MapHttpRoute, "Possible misconfigured route: MapHttpRoute"},
        {Rules.MapPageRoute, "Possible misconfigured route: MapPageRoute"},
        {Rules.MapRoute, "Possible misconfigured route: MapRoute"},
        {Rules.CreateRoute, "Possible misconfigured route: CreateRoute"},
        {Rules.MapGet, "Potential issue with hardcoded HTTP GET: MapGet"},
        {Rules.MapPost, "Potential issue with hardcoded HTTP POST: MapPost"},
        {Rules.HttpGet, "Use of HTTP GET detected, check if it’s secure"},
        {Rules.HttpPost, "Use of HTTP POST detected, validate data properly"},
        {Rules.connectionString, "Potential hardcoded connection string detected"}
    }

        ' Loop through each rule and check the CodeLine for violations
        For Each rule In rulesDictionary.Keys
            Dim pattern As String = ""

            ' Generate the regular expression pattern based on the rule
            Select Case rule
                Case Rules.MapControllerRoute, Rules.MapHttpRoute, Rules.MapPageRoute, Rules.MapRoute, Rules.CreateRoute
                    ' Match route mapping functions
                    pattern = "\b" & Regex.Escape(rule.ToString()) & "\("
                Case Rules.MapGet, Rules.MapPost, Rules.HttpGet, Rules.HttpPost
                    ' Match HTTP verbs
                    pattern = "\b" & Regex.Escape(rule.ToString()) & "\("
                Case Rules.connectionString
                    ' Match potential hardcoded connection string
                    pattern = "connectionString=\"""
            End Select

            ' Ensure the pattern is not empty
            If Not String.IsNullOrEmpty(pattern) Then
                ' Check if the current line matches the regular expression pattern
                If Regex.IsMatch(CodeLine, pattern) Then
                    ' Log the issue found in the code with severity level
                    frmMain.ListCodeIssue("Misconfiguration Detected", rulesDictionary(rule), FileName, CodeIssue.MEDIUM, CodeLine)
                End If
            End If
        Next
    End Sub

    Public Sub CheckUnsafeMemoryOperationsVB(CodeLine As String, FileName As String)
        Dim blnIsFound As Boolean
        blnIsFound = False

        ' Keywords related to memory operations and process injection/hollowing
        Dim memoryAndInjectionKeywords As String = "virtualallocex|writeprocessmemory|createremotethread|ntunmapviewofsection|setthreadcontext|resumethread|rtlcreateprocessreflection|ntgetnextprocess|heapalloc|heapfree"

        ' Check for both unsafe memory operations and process injection techniques
        If Regex.IsMatch(CodeLine.ToLower(), memoryAndInjectionKeywords) Then
            ' Check for user-controlled variables used in these operations
            For Each strVar In ctCodeTracker.InputVars
                If CodeLine.Contains(strVar) Then
                    frmMain.ListCodeIssue("Potential Unsafe Memory Operation or Process Injection",
                "The code contains potential unsafe memory operations or process injection/hollowing techniques with user-controlled variables.",
                FileName, CodeIssue.CRITICAL, CodeLine)
                    blnIsFound = True
                    Exit For
                End If
            Next

            ' If no user-controlled variables are found
            If blnIsFound = False Then
                frmMain.ListCodeIssue("Unsafe Memory Operation or Process Injection Detected",
            "The code contains potential unsafe memory operations or process injection/hollowing techniques. Manual review required to check for misuse.",
            FileName, CodeIssue.HIGH, CodeLine)
            End If
        End If
    End Sub


    '======================================================================================
    '== EXTENDED RULESET                                                                 ==
    '== Additional checks appended without altering any pre-existing logic.              ==
    '======================================================================================

    Private Function IsUserInputVB(CodeLine As String) As Boolean
        ' Return True where the line appears to reference a tainted (user-controlled) source
        '==================================================================================

        If Regex.IsMatch(CodeLine, "\bRequest\s*(\.\s*(QueryString|Form|Params|Cookies|Headers|Files|Url|RawUrl|UserAgent|UrlReferrer|Item|ServerVariables)|\()") Then Return True
        If Regex.IsMatch(CodeLine, "\bHttpContext\s*\.\s*(Current\s*\.\s*)?Request\b") Then Return True
        If Regex.IsMatch(CodeLine, "<\s*From(Query|Body|Form|Route|Header)\s*>") Then Return True
        If Regex.IsMatch(CodeLine, "\b(Console\s*\.\s*ReadLine|Environment\s*\.\s*GetEnvironmentVariable|Environment\s*\.\s*GetCommandLineArgs|InputBox)\b") Then Return True
        If Regex.IsMatch(CodeLine, "\b\w*(txt|input|param|query|user)\w*\s*\.\s*Text\b") Then Return True

        For Each strVar In ctCodeTracker.InputVars
            If strVar <> "" AndAlso CodeLine.Contains(strVar) Then Return True
        Next

        Return False

    End Function

    Private Sub CheckVBWeakCryptography(CodeLine As String, FileName As String)
        ' Identify broken cryptographic primitives, unsafe modes and weak key derivation
        '===============================================================================
        Dim mchMatch As Match
        Dim intIterations As Integer = 0
        Dim intKeySize As Integer = 0


        '== Broken hash algorithms ==
        If Regex.IsMatch(CodeLine, "\b(MD5|MD4|SHA1|RIPEMD160)(CryptoServiceProvider|Managed|Cng)?\s*\.\s*Create\s*\(") Or _
           Regex.IsMatch(CodeLine, "\bNew\s+(MD5|SHA1|RIPEMD160)(CryptoServiceProvider|Managed|Cng)\b") Or _
           Regex.IsMatch(CodeLine, "\b(HMACMD5|HMACRIPEMD160)\b") Or _
           Regex.IsMatch(CodeLine, "(HashAlgorithm|CryptoConfig)\s*\.\s*Create\s*\(\s*""\s*(MD5|SHA1|SHA-1|MD4)") Then
            frmMain.ListCodeIssue("Use of Broken or Deprecated Hashing Algorithm", "The code uses MD4, MD5, SHA-1 or RIPEMD-160, for which practical collision attacks exist. These are unsuitable for signatures, integrity verification and password storage. Move to SHA-256 or better, and use a purpose-built KDF for passwords.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

        '== Broken symmetric ciphers ==
        If Regex.IsMatch(CodeLine, "\b(DES|TripleDES|RC2)(CryptoServiceProvider|Managed|Cng)?\s*\.\s*Create\s*\(") Or _
           Regex.IsMatch(CodeLine, "\bNew\s+(DES|TripleDES|RC2)(CryptoServiceProvider|Managed|Cng)\b") Then
            frmMain.ListCodeIssue("Use of Broken or Deprecated Symmetric Cipher", "DES has an effective 56-bit key and is brute-forceable; Triple-DES and RC2 use 64-bit blocks and are exposed to Sweet32 birthday attacks. Use AES-256 in GCM mode.", FileName, CodeIssue.HIGH, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\bCipherMode\s*\.\s*ECB\b") Then
            frmMain.ListCodeIssue("Use of ECB Cipher Mode", "ECB encrypts each block independently, so identical plaintext blocks produce identical ciphertext. Plaintext structure leaks and blocks can be reordered or replayed by an attacker.", FileName, CodeIssue.HIGH, CodeLine)
        End If

        '== Hard-coded key material ==
        If Regex.IsMatch(CodeLine, "\.\s*(Key|IV)\s*=\s*(Encoding\s*\.\s*\w+\s*\.\s*GetBytes\s*\(\s*""|Convert\s*\.\s*FromBase64String\s*\(\s*""|New\s+Byte\s*\(\s*\)\s*\{)") Then
            frmMain.ListCodeIssue("Hard-Coded Cryptographic Key or IV", "Key or IV material is embedded in source and is recoverable from the compiled assembly with any decompiler. Source keys from DPAPI, a key vault or an HSM, and generate IVs randomly per message.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If

        '== Weak key sizes ==
        mchMatch = Regex.Match(CodeLine, "\bNew\s+(RSACryptoServiceProvider|DSACryptoServiceProvider|RSACng)\s*\(\s*(\d+)")
        If mchMatch.Success Then
            If Integer.TryParse(mchMatch.Groups(2).Value, intKeySize) Then
                If intKeySize > 0 And intKeySize < 2048 Then
                    frmMain.ListCodeIssue("Insufficient Asymmetric Key Length", "An RSA/DSA key of " & intKeySize.ToString() & " bits is generated. Keys below 2048 bits are no longer considered to provide an adequate security margin. Use 3072 bits or an elliptic-curve equivalent.", FileName, CodeIssue.HIGH, CodeLine)
                End If
            End If
        End If

        '== Weak password-based key derivation ==
        If Regex.IsMatch(CodeLine, "\bNew\s+PasswordDeriveBytes\b") Then
            frmMain.ListCodeIssue("Use of Obsolete Key Derivation Function", "PasswordDeriveBytes implements the obsolete PBKDF1. Use Rfc2898DeriveBytes with HashAlgorithmName.SHA256 and a high iteration count.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If
        mchMatch = Regex.Match(CodeLine, "\bNew\s+Rfc2898DeriveBytes\s*\([^\)]*?,\s*(\d{1,7})\s*[\),]")
        If mchMatch.Success Then
            If Integer.TryParse(mchMatch.Groups(1).Value, intIterations) Then
                If intIterations < 100000 Then
                    frmMain.ListCodeIssue("Insufficient PBKDF2 Iteration Count", "PBKDF2 is configured with " & intIterations.ToString() & " iterations. Current OWASP guidance is at least 600,000 for PBKDF2-HMAC-SHA256; a low work factor allows an attacker holding the hashes to test candidates at very high rates on commodity GPUs.", FileName, CodeIssue.MEDIUM, CodeLine)
                End If
            End If
        End If

        '== Passwords hashed with a general-purpose digest ==
        If Regex.IsMatch(CodeLine, "(?i)\b\w*(password|passwd|pwd|secret)\w*\b") And Regex.IsMatch(CodeLine, "\b(ComputeHash|GetHashCode|HashPasswordForStoringInConfigFile)\b") Then
            frmMain.ListCodeIssue("Password Stored Using an Unsuitable Hash", "A password appears to be passed to a general-purpose hash function. Fast hashes are unsuitable for password storage regardless of the algorithm. Use ASP.NET Identity's PasswordHasher, Argon2id or PBKDF2 with a per-user salt and a high work factor.", FileName, CodeIssue.HIGH, CodeLine)
        End If

    End Sub

    Private Sub CheckVBCertificateValidation(CodeLine As String, FileName As String)
        ' Identify disabled TLS certificate validation and obsolete protocol selection
        '=============================================================================

        If Regex.IsMatch(CodeLine, "(ServerCertificateValidationCallback|ServerCertificateCustomValidationCallback|RemoteCertificateValidationCallback)") And _
           Regex.IsMatch(CodeLine, "(Return\s+True|Function\s*\(.*\)\s*True|AddressOf)") Then
            frmMain.ListCodeIssue("TLS Certificate Validation Disabled Or Overridden", "The certificate validation callback appears to accept any certificate. This removes all protection against active man-in-the-middle attacks and reduces TLS to unauthenticated encryption. Where a custom callback is genuinely required, verify SslPolicyErrors is None, or pin the expected certificate thumbprint.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\bDangerousAcceptAnyServerCertificateValidator\b") Then
            frmMain.ListCodeIssue("TLS Certificate Validation Disabled", "All certificate verification is disabled for this HTTP handler, leaving connections open to interception.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "SecurityProtocolType\s*\.\s*(Ssl3|Tls|Tls11)\b") Or Regex.IsMatch(CodeLine, "SslProtocols\s*\.\s*(Ssl2|Ssl3|Tls|Tls11|None)\b") Then
            frmMain.ListCodeIssue("Obsolete TLS/SSL Protocol Version Selected", "SSLv3, TLS 1.0 and TLS 1.1 are deprecated by RFC 8996 and vulnerable to POODLE, BEAST and downgrade attacks. Pin to TLS 1.2 or 1.3, or remove the assignment and let the platform negotiate.", FileName, CodeIssue.HIGH, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "(CheckCertificateRevocationList|CheckCertificateRevocation)\s*=\s*False") Then
            frmMain.ListCodeIssue("Certificate Revocation Checking Disabled", "Revoked certificates will still be accepted, so a compromised key remains usable against this application until it expires.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "RequireHttpsMetadata\s*=\s*False") Then
            frmMain.ListCodeIssue("Authentication Metadata Retrieved Over Cleartext", "Discovery documents and signing keys may be fetched over plain HTTP, allowing a network attacker to substitute their own signing keys and forge tokens.", FileName, CodeIssue.HIGH, CodeLine)
        End If

    End Sub

    Private Sub CheckVBPathTraversal(CodeLine As String, FileName As String)
        ' Identify filesystem operations driven by user-controlled data
        '==============================================================

        If Regex.IsMatch(CodeLine, "\b(File|FileInfo|Directory|DirectoryInfo|FileStream|StreamReader|StreamWriter|Path\s*\.\s*Combine|Server\s*\.\s*MapPath|My\s*\.\s*Computer\s*\.\s*FileSystem)\b") Then
            If IsUserInputVB(CodeLine) Then
                frmMain.ListCodeIssue("Potential Path Traversal", "A filesystem path appears to be built from user input. Path.Combine offers no protection: a rooted path or '..' sequence in the second argument escapes the intended directory and permits arbitrary read, overwrite or deletion. Canonicalise with Path.GetFullPath and confirm the result remains under the intended base directory.", FileName, CodeIssue.HIGH, CodeLine)
            End If
        End If

        If Regex.IsMatch(CodeLine, "\b(ExtractToDirectory|ExtractToFile|ExtractAll|WriteToDirectory)\b") Then
            frmMain.ListCodeIssue("Potential Zip Slip During Archive Extraction", "Archive entries are written to disk. Where the entry name is not validated a crafted '../' path writes outside the extraction directory, frequently allowing an attacker to overwrite application code. Resolve each entry and verify it remains under the destination root.", FileName, CodeIssue.HIGH, CodeLine)
        End If

    End Sub

    Private Sub CheckVBSSRF(CodeLine As String, FileName As String)
        ' Identify outbound requests whose destination is user-controlled
        '================================================================

        If Regex.IsMatch(CodeLine, "\b(WebRequest|HttpWebRequest|WebClient|HttpClient|FtpWebRequest)\b") Or Regex.IsMatch(CodeLine, "\bNew\s+Uri\s*\(") Or _
           Regex.IsMatch(CodeLine, "\.\s*(DownloadString|DownloadData|DownloadFile|GetAsync|PostAsync|OpenRead)\s*\(") Then
            If IsUserInputVB(CodeLine) Then
                frmMain.ListCodeIssue("Potential Server-Side Request Forgery (SSRF)", "The destination of an outbound request appears to derive from user input, allowing an attacker to reach internal services, loopback addresses and cloud metadata endpoints from the server's network position. Validate the host against an allow-list after resolution and reject private ranges.", FileName, CodeIssue.HIGH, CodeLine)
            End If
        End If

    End Sub

    Private Sub CheckVBDeserializationExtended(CodeLine As String, FileName As String)
        ' Additional deserialization and ViewState surfaces
        '==================================================

        If Regex.IsMatch(CodeLine, "TypeNameHandling\s*\.\s*(All|Objects|Arrays|Auto)\b") Then
            frmMain.ListCodeIssue("Json.NET TypeNameHandling Enabled", "TypeNameHandling instructs Json.NET to instantiate the CLR type named in the $type property of the incoming document. Gadget types present in the framework convert this directly into remote code execution. Set TypeNameHandling to None or supply a strict ISerializationBinder.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\b(LosFormatter|ObjectStateFormatter|NetDataContractSerializer|SoapFormatter|BinaryFormatter)\b") Then
            frmMain.ListCodeIssue("Use of Unsafe .NET Formatter", "These formatters reconstruct arbitrary object graphs from type information contained in the payload and cannot be used safely on untrusted input. BinaryFormatter is removed in .NET 9. Migrate to System.Text.Json or a contract-based serialiser.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "enableViewStateMac\s*=\s*""false""") Or Regex.IsMatch(CodeLine, "EnableViewStateMac\s*=\s*False") Then
            frmMain.ListCodeIssue("ViewState MAC Validation Disabled", "Without MAC validation the ViewState blob can be replaced by the client. As ViewState is deserialised with ObjectStateFormatter this yields remote code execution on the web server.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "(validationKey|decryptionKey)\s*=\s*""[0-9A-Fa-f]{16,}""") Then
            frmMain.ListCodeIssue("Hard-Coded Machine Key", "A static machineKey in configuration allows anyone holding it to forge ViewState, forms authentication tickets and anti-forgery tokens.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If

    End Sub

    Private Sub CheckVBCookieAndSession(CodeLine As String, FileName As String)
        ' Identify insecure cookie and session configuration
        '===================================================

        If Regex.IsMatch(CodeLine, "\b(HttpOnly|IsHttpOnly)\s*=\s*False") Or Regex.IsMatch(CodeLine, "httpOnlyCookies\s*=\s*""false""") Then
            frmMain.ListCodeIssue("Cookie Accessible To Client-Side Script", "HttpOnly is disabled, so the cookie is readable by JavaScript and any cross-site scripting flaw becomes session hijacking.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\.\s*Secure\s*=\s*False") Or Regex.IsMatch(CodeLine, "requireSSL\s*=\s*""false""") Then
            frmMain.ListCodeIssue("Cookie Transmitted Over Cleartext", "The Secure attribute is disabled, so the cookie is transmitted over plain HTTP where it can be captured by a network attacker.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "SameSite(Mode)?\s*(=|\.)\s*None") Then
            frmMain.ListCodeIssue("Cookie SameSite Attribute Set To None", "SameSite=None re-enables cross-site transmission of the cookie and therefore classic cross-site request forgery. Use Lax or Strict unless a genuine cross-site flow requires otherwise.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "cookieless\s*=\s*""(UseUri|AutoDetect|true)""") Then
            frmMain.ListCodeIssue("Cookieless Sessions Enabled", "The session identifier is carried in the URL, where it leaks through Referer headers, proxy logs, browser history and shared links.", FileName, CodeIssue.HIGH, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\bIgnoreAntiforgeryToken\b") Or Regex.IsMatch(CodeLine, "ValidateAntiForgeryToken\s*=\s*False") Then
            frmMain.ListCodeIssue("Anti-CSRF Token Validation Disabled", "Anti-forgery validation is suppressed for this endpoint, allowing state-changing requests to be triggered from any origin using the victim's ambient credentials.", FileName, CodeIssue.HIGH, CodeLine)
        End If

    End Sub

    Private Sub CheckVBCorsPolicy(CodeLine As String, FileName As String)
        ' Identify permissive cross-origin resource sharing configuration
        '================================================================

        If Regex.IsMatch(CodeLine, "\bAllowAnyOrigin\s*\(\s*\)") Or Regex.IsMatch(CodeLine, "WithOrigins\s*\(\s*""\s*\*\s*""") Or Regex.IsMatch(CodeLine, "Access-Control-Allow-Origin""\s*,\s*""\s*\*") Then
            frmMain.ListCodeIssue("Overly Permissive CORS Policy", "Any origin may read responses from this endpoint. Where the response contains user-specific data this exposes it to every site the victim visits.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\bAllowCredentials\s*\(\s*\)") And Regex.IsMatch(CodeLine, "\b(AllowAnyOrigin|SetIsOriginAllowed)\b") Then
            frmMain.ListCodeIssue("CORS Wildcard Origin Combined With Credentials", "Reflecting arbitrary origins while allowing credentials permits any website to issue authenticated cross-origin requests with the victim's cookies and to read the responses.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If

    End Sub

    Private Sub CheckVBHardcodedSecrets(CodeLine As String, FileName As String)
        ' Identify credentials and API keys embedded in source
        '=====================================================

        If Regex.IsMatch(CodeLine, "AKIA[0-9A-Z]{16}") Then
            frmMain.ListCodeIssue("Hard-Coded AWS Access Key", "A string matching the AWS access key ID format is present in source. Revoke it and move to an instance role or secrets manager.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "(gh[pousr]_[A-Za-z0-9]{36}|xox[baprs]-[A-Za-z0-9\-]{10,}|sk_live_[0-9a-zA-Z]{24,}|AIza[0-9A-Za-z\-_]{35})") Then
            frmMain.ListCodeIssue("Hard-Coded Third-Party API Token", "A GitHub, Slack, Stripe or Google API token appears to be embedded in source.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "-----BEGIN\s+(RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE KEY") Then
            frmMain.ListCodeIssue("Private Key Embedded In Source", "A PEM-encoded private key is stored in the repository and must be treated as compromised.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "(?i)\b(Dim|Const|Private|Public|Friend|ReadOnly)\b[^=]*\b\w*(password|passwd|pwd|secret|apikey|api_key|token|privatekey|clientsecret)\w*\b[^=]*=\s*""[^""]{4,}""") Then
            frmMain.ListCodeIssue("Hard-Coded Secret Assigned To Variable", "A variable whose name indicates a credential is initialised with a literal. The value is recoverable from the compiled assembly and persists in version control history.", FileName, CodeIssue.HIGH, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "(?i)(password|pwd)\s*=\s*[^""'&;\s\)]{4,}\s*;") And Regex.IsMatch(CodeLine, "(?i)(data\s+source|server|initial\s+catalog|uid|user\s+id)") Then
            frmMain.ListCodeIssue("Hard-Coded Database Credentials In Connection String", "A connection string with an inline password is present in source. Use integrated authentication, a managed identity, or a protected configuration section.", FileName, CodeIssue.HIGH, CodeLine)
        End If

    End Sub

    Private Sub CheckVBDynamicCodeExecution(CodeLine As String, FileName As String)
        ' Identify runtime code loading, late binding and reflection driven by input
        '==========================================================================

        If Regex.IsMatch(CodeLine, "\bAssembly\s*\.\s*(Load|LoadFrom|LoadFile|LoadWithPartialName|UnsafeLoadFrom)\s*\(") Then
            frmMain.ListCodeIssue("Dynamic Assembly Loading", "An assembly is loaded at runtime. Where the path or byte array is influenced by user input, or the load path is writable by a lower-privileged user, this results in arbitrary code execution in the process. Load only from trusted, non-writable locations and verify the signature.", FileName, CodeIssue.HIGH, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\b(VBCodeProvider|CSharpCodeProvider|CompileAssemblyFromSource|CompileAssemblyFromFile)\b") Then
            frmMain.ListCodeIssue("Runtime Code Compilation", "The application compiles source at runtime. If any part of the compiled text derives from user input this is a direct remote code execution primitive.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\b(CallByName|Activator\s*\.\s*CreateInstance|Type\s*\.\s*GetType|InvokeMember)\s*\(") And IsUserInputVB(CodeLine) Then
            frmMain.ListCodeIssue("Late Binding Driven By User Input", "CallByName and reflection resolve a member name at runtime. Where the name derives from user input an attacker can invoke arbitrary methods or properties on the target object.", FileName, CodeIssue.HIGH, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\b(Shell|Process\s*\.\s*Start|ProcessStartInfo)\b") And IsUserInputVB(CodeLine) Then
            frmMain.ListCodeIssue("Process Execution With User-Controlled Data", "A process is launched with arguments derived from user input. Where UseShellExecute is true, or the arguments are concatenated into a single string, shell metacharacters permit command injection. Pass arguments as a separate collection and validate them against an allow-list.", FileName, CodeIssue.HIGH, CodeLine)
        End If

    End Sub

    Private Sub CheckVBInformationLeakage(CodeLine As String, FileName As String)
        ' Identify exception detail returned to the client and suppressed errors
        '======================================================================

        If Regex.IsMatch(CodeLine, "\b(ex|e|exc|exception|err)\s*\.\s*(ToString\s*\(|StackTrace|InnerException|Message)\b") And _
           Regex.IsMatch(CodeLine, "\b(Response\s*\.\s*Write|Content\s*\(|Json\s*\(|ViewBag|ViewData|innerHTML|\.Text\s*=)") Then
            frmMain.ListCodeIssue("Exception Detail Returned To Client", "Exception text or a stack trace is written into the response, disclosing framework versions, file paths, SQL fragments and internal class names. Log the detail server-side and return only a correlation identifier.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\bOn\s+Error\s+Resume\s+Next\b") Then
            frmMain.ListCodeIssue("Unstructured Error Handling Suppresses All Failures", "On Error Resume Next causes execution to continue past every runtime error. Failed authorisation checks, failed cryptographic operations and failed writes all proceed silently, leaving the application in a state the developer believed impossible. Use structured Try/Catch.", FileName, CodeIssue.HIGH, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\bUseDeveloperExceptionPage\s*\(") And Not Regex.IsMatch(CodeLine, "(IsDevelopment|IsEnvironment)") Then
            frmMain.ListCodeIssue("Developer Exception Page Enabled Unconditionally", "The developer exception page is registered without an environment guard, exposing full stack traces, source snippets, headers and cookies in production.", FileName, CodeIssue.HIGH, CodeLine)
        End If

    End Sub

    Private Sub CheckVBHeaderInjection(CodeLine As String, FileName As String)
        ' Identify response splitting and host header trust issues
        '=========================================================

        If Regex.IsMatch(CodeLine, "Response\s*\.\s*(AddHeader|AppendHeader|Headers\s*\.\s*(Add|Append)|Cookies\s*\.\s*Add)") And IsUserInputVB(CodeLine) Then
            frmMain.ListCodeIssue("Potential HTTP Response Header Injection", "A response header value is built from user input. Where carriage return and line feed are not stripped an attacker can inject additional headers or a second response body, enabling cache poisoning and reflected cross-site scripting.", FileName, CodeIssue.HIGH, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "Request\s*\.\s*(Headers\s*\(\s*""Host""|Url\s*\.\s*Host|ServerVariables\s*\(\s*""HTTP_HOST"")") Then
            frmMain.ListCodeIssue("Reliance On The Host Header", "The Host header is attacker-controlled unless the web server enforces a host allow-list. Building absolute URLs from it leads to password-reset poisoning and web cache poisoning. Use a configured canonical hostname.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

    End Sub

    Private Sub CheckVBAuthorisationWeakness(CodeLine As String, FileName As String)
        ' Identify weakened authentication and authorisation configuration
        '=================================================================

        If Regex.IsMatch(CodeLine, "<\s*AllowAnonymous\s*>") Then
            frmMain.ListCodeIssue("Endpoint Explicitly Marked AllowAnonymous", "Authorisation is bypassed for this action. Confirm that it serves only public data and does not accept identifiers permitting access to another user's records.", FileName, CodeIssue.LOW, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "Password\s*\.\s*Require(Digit|LowerCase|UpperCase|NonAlphanumeric)\s*=\s*False") Then
            frmMain.ListCodeIssue("Relaxed Password Complexity Requirement", "A password complexity rule has been disabled. Where this is not compensated by a longer minimum length and a breached-password check the resulting policy is inadequate.", FileName, CodeIssue.LOW, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "Password\s*\.\s*RequiredLength\s*=\s*([0-9]|1[01])\b") Then
            frmMain.ListCodeIssue("Insufficient Minimum Password Length", "The minimum password length is set below 12 characters, which is inadequate in the absence of a breached-password check.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "Lockout\s*\.\s*AllowedForNewUsers\s*=\s*False") Then
            frmMain.ListCodeIssue("Account Lockout Disabled", "Lockout is disabled, permitting sustained online password guessing against the authentication endpoint.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\b(WindowsIdentity\s*\.\s*Impersonate|LogonUser|ImpersonateLoggedOnUser)\b") Then
            frmMain.ListCodeIssue("Thread Impersonation In Use", "Confirm that the impersonation context is always reverted in a Finally block; otherwise subsequent work on the pooled thread runs with the elevated identity.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

    End Sub
End Module
