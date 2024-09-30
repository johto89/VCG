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
        CheckProcessInjection(CodeLine, FileName)       ' Check for potential process injection or hollowing techniques

        If Regex.IsMatch(CodeLine, "\S*(Password|password|pwd|passwd)\S*\.(ToLower|ToUpper)\s*\(") Then
            frmMain.ListCodeIssue("Unsafe Password Management", "The application appears to handle passwords in a case-insensitive manner. This can greatly increase the likelihood of successful brute-force and/or dictionary attacks.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

    End Sub

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
        ' Regex để tìm các lớp serialization trong VB.NET
        Dim serializerPattern As String = "\b(?:BinaryFormatter|SoapFormatter|XmlSerializer|DataContractSerializer|JavaScriptSerializer)\b"

        ' Kiểm tra lớp serializer có xuất hiện trong mã không
        If Regex.IsMatch(CodeLine, serializerPattern, RegexOptions.IgnoreCase) Then
            ' Regex kiểm tra các phương thức xử lý đầu vào để xác định xem có kiểm tra hay làm sạch dữ liệu không
            Dim sanitizationPattern As String = "\b(?:SanitizeInput|Escape|HtmlEncode|UrlEncode|Clean|Validate)\s*\("

            If Not Regex.IsMatch(CodeLine, sanitizationPattern, RegexOptions.IgnoreCase) Then
                frmMain.ListCodeIssue("Insecure Deserialization",
                "The application may be deserializing untrusted input. Verify that input is validated before deserialization.",
                FileName, CodeIssue.HIGH, CodeLine)
            End If

            ' Kiểm tra sự hiện diện của các gadget có thể gây nguy hiểm
            Dim gadgetPattern As String = "\b(?:System.Diagnostics.Process|System.Runtime.InteropServices.Marshal|System.IO.File|System.Security.Principal.WindowsIdentity|System.Web.UI.Page)\b"

            If Regex.IsMatch(CodeLine, gadgetPattern, RegexOptions.IgnoreCase) Then
                frmMain.ListCodeIssue("Insecure Deserialization - Gadget Detected",
                "Potentially dangerous gadget found. Review code for exploitation risks associated with deserialization.",
                FileName, CodeIssue.HIGH, CodeLine)
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
        CodeLine.Contains("IFormFile") Or CodeLine.Contains("Request.Form.Files") Or
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

    Public Sub CheckProcessInjection(CodeLine As String, FileName As String)
        ' Check for potential process injection or hollowing techniques
        '=========================================================================

        Dim blnIsFound As Boolean
        blnIsFound = False

        ' List of keywords related to process injection/hollowing
        If Regex.IsMatch(CodeLine.ToLower(), "createremotethread|writeprocessmemory|virtualallocex|ntunmapviewofsection|setthreadcontext|resumethread|rtlcreateprocessreflection|ntgetnextprocess") Then
            ' Check for potential code injection patterns
            For Each strVar In ctCodeTracker.InputVars
                ' If the line contains a user-controlled variable, raise a critical issue
                If CodeLine.Contains(strVar) Then
                    frmMain.ListCodeIssue("Potential Process Injection Technique",
                "The code contains potential process injection/hollowing techniques with user-controlled variables.",
                FileName, CodeIssue.CRITICAL, CodeLine)
                    blnIsFound = True
                    Exit For
                End If
            Next

            ' If no user-controlled variables are found
            If blnIsFound = False Then
                ' Raise a high-priority issue for manual review
                frmMain.ListCodeIssue("Process Injection Technique Detected",
            "The code contains potential process injection/hollowing techniques. Manual review required to check for misuse.",
            FileName, CodeIssue.HIGH, CodeLine)
            End If
        End If

    End Sub


End Module
