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

Module modCSharpCheck

    ' Specific checks for C# code
    '============================

    Public Sub CheckCSharpCode(CodeLine As String, FileName As String)
        ' Carry out any specific checks for the language in question
        '===========================================================

        CheckXXE(CodeLine, FileName)                    ' Check for XXE
        CheckUnrestrictedFileUpload(CodeLine, FileName) ' Check for Unrestricted File Upload
        IdentifyLabels(CodeLine, FileName)              ' Identify and record ASP.NET label controls in the code, which may be vulnerable to XSS if not properly sanitized.
        CheckInputValidation(CodeLine, FileName)        ' Has .NET default validation been turned off?
        CheckSQLInjection(CodeLine, FileName)           ' Check for SQLi
        CheckXSS(CodeLine, FileName)                    ' Check for XSS
        CheckSecureStorage(CodeLine, FileName)          ' Are sensitive variables stored without using SecureString?
        CheckIntOverflow(CodeLine, FileName)            ' Are int overflows being trapped?
        CheckLogDisplay(CodeLine, FileName)             ' Is data sanitised before being written to logs?
        CheckFileRace(CodeLine, FileName)               ' Check for race conditions and TOCTOU vulns
        CheckSerialization(CodeLine, FileName)          ' Identify serializable objects and check their security permissions
        CheckHTTPRedirect(CodeLine, FileName)           ' Check for safe redirects and safe use of URLs
        CheckRandomisation(CodeLine, FileName)          ' Locate any use of randomisation functions that are not cryptographically secure
        CheckSAML2Validation(CodeLine, FileName)        ' Check for correct implementation of inherited SAML2 functions
        CheckUnsafeTempFiles(CodeLine, FileName)        ' Check for static/obvious filenames for temp files
        CheckUnsafeCode(CodeLine, FileName)             ' Check for use and abuse of the "unsafe" directive
        CheckThreadIssues(CodeLine, FileName)           ' Check for good/bad thread management
        CheckExecutable(CodeLine, FileName)             ' Check for unvalidated variables being executed via cmd line/system calls
        CheckWebConfig(CodeLine, FileName)              ' Check config file to determine whether .NET debugging and default errors are enabled
        CheckUnsafeMemoryOperationsCsharp(CodeLine, FileName)       ' Check for potential process injection or hollowing techniques
        CheckMisconfiguredRoutes(CodeLine, FileName)    ' Check for potential misconfigured routes or connection strings

        '== Extended ruleset ==
        CheckWeakCryptography(CodeLine, FileName)        ' Broken hashes/ciphers, ECB, static IV/key, weak KDF and key sizes
        CheckCertificateValidation(CodeLine, FileName)   ' Disabled TLS cert validation, obsolete protocol versions
        CheckPathTraversal(CodeLine, FileName)           ' User-controlled filesystem paths and Zip Slip
        CheckSSRF(CodeLine, FileName)                    ' User-controlled outbound request destinations
        CheckLdapAndXPathInjection(CodeLine, FileName)   ' LDAP and XPath queries built by concatenation
        CheckNoSqlInjection(CodeLine, FileName)          ' NoSQL/BSON query and server-side JavaScript sinks
        CheckJwtValidation(CodeLine, FileName)           ' Weakened JWT validation parameters and hard-coded signing keys
        CheckCorsPolicy(CodeLine, FileName)              ' Permissive or credentialed CORS configuration
        CheckCookieAndSessionSecurity(CodeLine, FileName) ' Insecure cookie flags and session configuration
        CheckCsrfProtection(CodeLine, FileName)          ' Disabled anti-forgery and framing protection
        CheckMassAssignment(CodeLine, FileName)          ' Over-posting via unrestricted model binding
        CheckDynamicCodeExecution(CodeLine, FileName)    ' Assembly loading, runtime compilation, reflection on user input
        CheckHardcodedSecrets(CodeLine, FileName)        ' API keys, private keys and credentials embedded in source
        CheckRegexDoS(CodeLine, FileName)                ' Catastrophic backtracking and missing regex timeouts
        CheckInformationLeakage(CodeLine, FileName)      ' Exception detail returned to the client, empty catch blocks
        CheckAuthorisationWeakness(CodeLine, FileName)   ' Weak password policy, lockout and impersonation handling
        CheckXmlProcessing(CodeLine, FileName)           ' XSLT scripting, DTD processing and inline schema handling
        CheckConcurrencyAndResource(CodeLine, FileName)  ' Blocking waits, undisposed resources, removed size limits
        CheckDeserializationExtended(CodeLine, FileName) ' TypeNameHandling, unsafe formatters, ViewState MAC and machineKey
        CheckHeaderInjection(CodeLine, FileName)         ' Response splitting and Host header trust

        If Regex.IsMatch(CodeLine, "\S*(Password|password|pwd|passwd)\S*(\.|\-\>)(ToLower|ToUpper)\s*\(") Then
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

    Public Sub IdentifyLabels(CodeLine As String, FileName As String)
        ' Locate and record any labels in asp pages. These will be checked for XSS later.
        '================================================================================
        Dim arrFragments As String()
        Dim strLabel As String = ""

        '== Detect default .net input validation
        If ctCodeTracker.HasValidator = False And (FileName.ToLower.EndsWith(".asp") Or FileName.ToLower.EndsWith(".aspx")) And CodeLine.Contains("<asp:Label ID=""") Then
            arrFragments = Regex.Split(CodeLine, "\<asp\:Label\s+ID=""")
            strLabel = GetFirstItem(arrFragments.Last, """")
            If strLabel <> "" And Not ctCodeTracker.AspLabels.Contains(strLabel) Then ctCodeTracker.AspLabels.Add(strLabel)
        End If

    End Sub

    Public Sub CheckInputValidation(CodeLine As String, FileName As String)
        ' Check any input validation of user-controlled variables (or lack of)
        '=====================================================================

        '== Detect default .net input validation
        If ctCodeTracker.HasValidator = False And FileName.ToLower.EndsWith(".config") And CodeLine.ToLower.Contains("<pages validateRequest=""true""") Then
            ctCodeTracker.HasValidator = True
        ElseIf ctCodeTracker.HasValidator = False And FileName.ToLower.EndsWith(".xml") And CodeLine.ToLower.Contains("<pages> element with validateRequest=""true""") Then
            ctCodeTracker.HasValidator = True
        ElseIf FileName.ToLower.EndsWith(".config") And CodeLine.ToLower.Contains("<pages validateRequest=""false""") Then
            '== .NET validation turned off deliberately ==
            ctCodeTracker.HasValidator = False
            frmMain.ListCodeIssue("Potential Input Validation Issues", "The application appears to deliberately de-activate the default .NET input validation functionality.", FileName, CodeIssue.HIGH, CodeLine)
        ElseIf FileName.ToLower.EndsWith(".xml") And CodeLine.ToLower.Contains("<pages> element with validateRequest=""false""") Then
            '== .NET validation turned off deliberately ==
            ctCodeTracker.HasValidator = False
            frmMain.ListCodeIssue("Potential Input Validation Issues", "The application appears to deliberately de-activate the default .NET input validation functionality.", FileName, CodeIssue.HIGH, CodeLine)
        End If

    End Sub

    Public Sub CheckUnrestrictedFileUpload(CodeLine As String, FileName As String)
        Dim isUploadFunctionPresent As Boolean = False
        Dim allowedExtensions As String() = {".txt", ".jpg", ".jpeg", ".png", ".gif", ".pdf", ".mp4", ".mov", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".xps"}

        ' Check for presence of file upload elements and functions in both ASP.NET Web Forms and ASP.NET Core
        If CodeLine.Contains("Request.Files") Or CodeLine.Contains("HttpPostedFileBase") Or
            CodeLine.Contains("FileUpload") Or CodeLine.Contains("UploadFile") Or CodeLine.Contains("SaveAs") Or
            CodeLine.Contains("IFormFile") Or CodeLine.Contains("Request.Form.Files") Or CodeLine.Contains("(MapPath") Then
            isUploadFunctionPresent = True
        End If

        ' Check for allowed extensions
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

            If Not (CodeLine.Contains(".Length") Or CodeLine.Contains(".Size")) Then
                frmMain.ListCodeIssue("File Size Validation Missing", "File size limits are not validated.", FileName, CodeIssue.MEDIUM, CodeLine)
            End If
        End If
    End Sub


    Public Sub CheckXXE(CodeLine As String, FileName As String)
        ' Check for potential XXE vulnerabilities in XML parsing code
        '===========================================================

        ' Check for use of XmlDocument with XmlResolver not set to null
        If Regex.IsMatch(CodeLine, "XmlDocument\s+parser\s*=\s*new\s+XmlDocument\(\);") Then
            If Regex.IsMatch(CodeLine, "parser\.XmlResolver\s*=\s*new\s+XmlUrlResolver\(\);") Then
                frmMain.ListCodeIssue("XXE Vulnerability", "The code is vulnerable to XXE attacks as it uses XmlUrlResolver. Consider setting XmlResolver to null.", FileName, CodeIssue.HIGH, CodeLine)
            ElseIf Regex.IsMatch(CodeLine, "parser\.XmlResolver\s*=\s*null;") Then
                ' Compliant code, do nothing
            ElseIf Regex.IsMatch(CodeLine, "parser\.XmlResolver\s*=\s*.*;") Then
                frmMain.ListCodeIssue("XXE Vulnerability", "The XmlResolver should be set to null to prevent XXE attacks.", FileName, CodeIssue.HIGH, CodeLine)
            End If
        End If

        ' Check for use of XDocument (safe by default in .NET 4.5.2 and later)
        If Regex.IsMatch(CodeLine, "XDocument\s+doc\s*=\s*new\s+XDocument\(\);") Then
            frmMain.ListCodeIssue("XXE Vulnerability", "XDocument is safe by default from .NET 4.5.2 onwards, but ensure the application is not targeting an earlier version.", FileName, CodeIssue.LOW, CodeLine)
        End If

        ' Check for use of XmlTextReader and ensure DtdProcessing is set to Prohibit
        If Regex.IsMatch(CodeLine, "XmlTextReader\s+reader\s*=\s*new\s+XmlTextReader\(\s*.*\s*\);") Then
            If Not Regex.IsMatch(CodeLine, "reader\.DtdProcessing\s*=\s*DtdProcessing\.Prohibit;") Then
                frmMain.ListCodeIssue("XXE Vulnerability", "XmlTextReader should have DtdProcessing set to Prohibit to prevent XXE attacks.", FileName, CodeIssue.HIGH, CodeLine)
            End If
        End If

        ' Check for XPathNavigator and ensure it's created with a safe parser
        If Regex.IsMatch(CodeLine, "XPathNavigator\s+nav\s*=\s*doc\.CreateNavigator\(\);") Then
            If Not Regex.IsMatch(CodeLine, "XPathDocument\s+doc\s*=\s*new\s+XPathDocument\(\s*XmlReader\.Create\(\s*.*\s*\)\);") Then
                frmMain.ListCodeIssue("XXE Vulnerability", "Ensure that XPathNavigator is created with a safe XmlReader to prevent XXE attacks.", FileName, CodeIssue.HIGH, CodeLine)
            End If
        End If

        ' Check for XmlReader and ensure DtdProcessing is set to Prohibit
        If Regex.IsMatch(CodeLine, "XmlReader\s+reader\s*=\s*XmlReader\.Create\(\s*.*\s*\);") Then
            If Not Regex.IsMatch(CodeLine, "reader\.DtdProcessing\s*=\s*DtdProcessing\.Prohibit;") Then
                frmMain.ListCodeIssue("XXE Vulnerability", "XmlReader should have DtdProcessing set to Prohibit to prevent XXE attacks.", FileName, CodeIssue.HIGH, CodeLine)
            End If
        End If

        ' Check for use of XmlReaderSettings
        If Regex.IsMatch(CodeLine, "XmlReaderSettings") Then
            frmMain.ListCodeIssue("XXE Vulnerability", "The code uses XmlReaderSettings, which may enable DTD processing. Ensure DtdProcessing is set to Prohibit.", FileName, CodeIssue.HIGH, CodeLine)
        End If
    End Sub

    Public Sub CheckSQLInjection(CodeLine As String, FileName As String)
        ' Check for any SQL injection problems 
        '=====================================
        Dim strVarName As String = ""   ' Holds the variable name for the dynamic SQL statement


        '== Only check unvalidated code ==
        If ctCodeTracker.HasValidator = True Then Exit Sub


        '== Is unsanitised dynamic SQL statement prepared beforehand? ==
        If CodeLine.Contains("=") And (CodeLine.ToLower.Contains("sql") Or CodeLine.ToLower.Contains("query")) And (CodeLine.Contains("""") And (CodeLine.Contains("&") Or CodeLine.Contains("+"))) Then
            '== Extract variable name from assignment statement ==
            strVarName = GetVarName(CodeLine)
            ctCodeTracker.HasVulnSQLString = True
            If Regex.IsMatch(strVarName, "^[a-zA-Z0-9_]*$") And Not ctCodeTracker.SQLStatements.Contains(strVarName) Then ctCodeTracker.SQLStatements.Add(strVarName)
        End If


        If Regex.IsMatch(CodeLine, "validate|encode|sanitize|sanitise") Then
            '== Remove any variables which have been sanitised from the list of vulnerable variables ==  
            RemoveSanitisedVars(CodeLine)
        ElseIf Regex.IsMatch(CodeLine, "ExecuteQuery|ExecuteSQL|ExecuteStatement|SqlCommand\(|ExecuteNonQuery|ExecuteScalar|ExecuteReader") Then

            '== Check usage of SQL execution methods == 
            If CodeLine.Contains("""") And CodeLine.Contains("&") Then
                '== Dynamic SQL built into connection/update ==
                frmMain.ListCodeIssue("Potential SQL Injection", "The application appears to allow SQL injection via dynamic SQL statements.", FileName, CodeIssue.CRITICAL, CodeLine)
            ElseIf ctCodeTracker.HasVulnSQLString = True Then
                '== Otherwise check for use of pre-prepared statements ==
                For Each strVar In ctCodeTracker.SQLStatements
                    If CodeLine.Contains(strVar) Then
                        frmMain.ListCodeIssue("Potential SQL Injection", "The application appears to allow SQL injection via a pre-prepared dynamic SQL statement.", FileName, CodeIssue.CRITICAL, CodeLine)
                        Exit For
                    End If
                Next
            End If
        End If

    End Sub

    Public Sub CheckXSS(CodeLine As String, FileName As String)
        ' Check for any XSS problems 
        '===========================
        Dim strVarName As String = ""
        Dim arrFragments As String()
        Dim blnIsFound As Boolean = False
        '== Only check unvalidated code ==
        If ctCodeTracker.HasValidator = True Then Exit Sub


        If Regex.IsMatch(CodeLine, "validate|encode|sanitize|sanitise") Then
            '== Remove any variables which have been sanitised from the list of vulnerable variables ==  
            RemoveSanitisedVars(CodeLine)
            Exit Sub
        ElseIf Regex.IsMatch(CodeLine, "\bHttpCookie\b\s+\S+\s+=\s+\S+\.Cookies\.Get\(") Then
            '== Extract variable name from assignment statement ==
            strVarName = GetVarName(CodeLine)
            If Regex.IsMatch(strVarName, "^[a-zA-Z0-9_]*$") And Not ctCodeTracker.InputVars.Contains(strVarName) Then ctCodeTracker.InputVars.Add(strVarName)
        ElseIf Regex.IsMatch(CodeLine, "\bRequest\b\.Form\(""") Then
            '== Extract variable name from assignment statement ==
            arrFragments = Regex.Split(CodeLine, "\bRequest\b\.Form\(""")
            strVarName = GetFirstItem(arrFragments.First, """")
            If Regex.IsMatch(strVarName, "^[a-zA-Z0-9_]*$") And Not ctCodeTracker.InputVars.Contains(strVarName) Then ctCodeTracker.InputVars.Add(strVarName)
        ElseIf (CodeLine.Contains("=") And (CodeLine.Contains(".Value")) Or Regex.IsMatch(CodeLine, "=\s*Request\.QueryString\[")) Then
            '== Extract variable name from assignment statement ==
            strVarName = GetVarName(CodeLine)
            If Regex.IsMatch(strVarName, "^[a-zA-Z0-9_]*$") And Not ctCodeTracker.InputVars.Contains(strVarName) Then ctCodeTracker.InputVars.Add(strVarName)
        End If

        If CodeLine.Contains("Response.Write(") And CodeLine.Contains("Request.Form(") Then
            '== Classic ASP XSS==
            frmMain.ListCodeIssue("Potential XSS", "The application appears to reflect user input to the screen with no apparent validation or sanitisation.", FileName, CodeIssue.HIGH, CodeLine)
        ElseIf CodeLine.Contains("Response.Write(") And CodeLine.Contains("""") And CodeLine.Contains("+") Then
            CheckUserVarXSS(CodeLine, FileName)
        ElseIf CodeLine.Contains("Response.Write(") And Not CodeLine.Contains("""") Then
            CheckUserVarXSS(CodeLine, FileName)
        ElseIf CodeLine.Contains(".Text =") Then
            For Each strLabel In ctCodeTracker.AspLabels
                If CodeLine.Contains(strLabel) Then
                    If CodeLine.Contains("Request.QueryString[") Or CodeLine.Contains(".Cookies.Get(") Then
                        frmMain.ListCodeIssue("Potential XSS", "The application appears to reflect a user-supplied variable to the screen with no apparent validation or sanitisation.", FileName, CodeIssue.HIGH, CodeLine)
                    Else
                        CheckUserVarXSS(CodeLine, FileName)
                    End If
                End If
            Next
        End If


        '== Check for use of raw strings in HTML output ==
        If Regex.IsMatch(CodeLine, "\bHtml\b\.Raw\(") Then
            For Each strVar In ctCodeTracker.InputVars
                If CodeLine.Contains(strVar) Then
                    frmMain.ListCodeIssue("Potential XSS", "The application uses the potentially dangerous Html.Raw construct in conjunction with a user-supplied variable.", FileName, CodeIssue.HIGH, CodeLine)
                    blnIsFound = True
                    Exit For
                End If
            Next

            If Not blnIsFound Then
                frmMain.ListCodeIssue("Potential XSS", "The application uses the potentially dangerous Html.Raw construct.", FileName, CodeIssue.MEDIUM, CodeLine)
            End If
        End If


        '== Check for DOM-based XSS in .asp pages ==
        If FileName.ToLower.EndsWith(".asp") Or FileName.ToLower.EndsWith(".aspx") Then
            If Regex.IsMatch(CodeLine, "\s+var\s+\w+\s*=\s*""\s*\<\%\s*\=\s*\w+\%\>""\;") And Not Regex.IsMatch(CodeLine, "validate|encode|sanitize|sanitise") Then
                '== Extract variable name from assignment statement ==
                strVarName = GetVarName(CodeLine)
                If Regex.IsMatch(strVarName, "^[a-zA-Z0-9_]*$") And Not ctCodeTracker.SQLStatements.Contains(strVarName) Then ctCodeTracker.InputVars.Add(strVarName)
            ElseIf ((CodeLine.Contains("document.write(") And CodeLine.Contains("+") And CodeLine.Contains("""")) Or Regex.IsMatch(CodeLine, ".innerHTML\s*\=\s*\w+;")) And Not Regex.IsMatch(CodeLine, "\s*\S*\s*validate|encode|sanitize|sanitise\s*\S*\s*") Then
                For Each strVar In ctCodeTracker.InputVars
                    If CodeLine.Contains(strVar) Then
                        frmMain.ListCodeIssue("Potential DOM-Based XSS", "The application appears to allow XSS via an unencoded/unsanitised input variable.", FileName, CodeIssue.HIGH, CodeLine)
                        Exit For
                    End If
                Next
            End If
        End If

    End Sub

    Public Sub CheckUserVarXSS(CodeLine As String, FileName As String)
        ' Check for presence of user controlled variables in a line which writes data the screen
        '=======================================================================================
        Dim blnIsFound As Boolean = False

        For Each strVar In ctCodeTracker.InputVars
            If CodeLine.Contains(strVar) Then
                frmMain.ListCodeIssue("Potential XSS", "The application appears to reflect a user-supplied variable to the screen with no apparent validation or sanitisation.", FileName, CodeIssue.HIGH, CodeLine)
                blnIsFound = True
                Exit For
            End If
        Next

        If Not blnIsFound Then
            frmMain.ListCodeIssue("Potential XSS", "The application appears to reflect data to the screen with no apparent validation or sanitisation. It was not clear if this variable is controlled by the user.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

    End Sub

    Public Sub CheckSecureStorage(CodeLine As String, FileName As String)
        ' Check if passwords are stored with char[] or String instead of SecureString
        '============================================================================

        If Regex.IsMatch(CodeLine, "\s+(String|char\[\])\s+\S*(Password|password|key)\S*") Then
            frmMain.ListCodeIssue("Insecure Storage of Sensitive Information", "The code uses standard strings and byte arrays to store sensitive transient data such as passwords and cryptographic private keys instead of the more secure SecureString class.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

    End Sub

    Public Sub CheckIntOverflow(CodeLine As String, FileName As String)
        ' Check whether precautions are in place to deal with integer overflows
        '======================================================================

        If Regex.IsMatch(CodeLine, "\bint\b\s*\w+\s*\=\s*\bchecked\b\s+\(") Then
            ' A check is in place, exit function
            Return
        ElseIf ((Regex.IsMatch(CodeLine, "\bint\b\s*\w+\s*\=\s*\bunchecked\b\s+\(")) And (CodeLine.Contains("+") Or CodeLine.Contains("*"))) Then
            ' Checks have been switched off
            frmMain.ListCodeIssue("Integer Operation With Overflow Check Deliberately Disabled", "The code carries out integer operations with a deliberate disabling of overflow defences. Manually review the code to ensure that it is safe.", FileName, CodeIssue.STANDARD, CodeLine)
        ElseIf ((Regex.IsMatch(CodeLine, "\bint\b\s*\w+\s*\=")) And (CodeLine.Contains("+") Or CodeLine.Contains("*"))) Then
            ' Unchecked operation
            frmMain.ListCodeIssue("Integer Operation Without Overflow Check", "The code carries out integer operations without enabling overflow defences. Manually review the code to ensure that it is safe", FileName, CodeIssue.STANDARD, CodeLine)
        End If

    End Sub

    Public Sub CheckExecutable(CodeLine As String, FileName As String)
        ' Check for unvalidated variables being executed via cmd line/system calls
        '=========================================================================
        Dim blnIsFound As Boolean = False


        If Regex.IsMatch(CodeLine, "validate|encode|sanitize|sanitise") Then Exit Sub

        If CodeLine.ToLower.Contains("process\.start|shellexecute|.ProcessStartInfo(") Then
            For Each strVar In ctCodeTracker.InputVars
                If CodeLine.Contains(strVar) Then
                    frmMain.ListCodeIssue("User Controlled Variable Used on System Command Line", "The application appears to allow the use of an unvalidated user-controlled variable when executing a command.", FileName, CodeIssue.HIGH, CodeLine)
                    blnIsFound = True
                    Exit For
                End If
            Next
            If blnIsFound = False And ((Not CodeLine.Contains("""")) Or (CodeLine.Contains("""") And CodeLine.Contains("+"))) Then
                frmMain.ListCodeIssue("Application Variable Used on System Command Line", "The application appears to allow the use of an unvalidated variable when executing a command. Carry out a manual check to determine whether the variable is user-controlled.", FileName, CodeIssue.MEDIUM, CodeLine)
            End If
        End If

    End Sub

    Public Sub CheckUnsafeMemoryOperationsCsharp(CodeLine As String, FileName As String)
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


    Public Sub CheckLogDisplay(CodeLine As String, FileName As String)
        ' Check output written to logs is sanitised first
        '================================================


        '== Only check unvalidated code ==
        If ctCodeTracker.HasValidator = True And Not CodeLine.ToLower.Contains("password") Then Exit Sub

        If Regex.IsMatch(CodeLine, "validate|encode|sanitize|sanitise") And Not CodeLine.ToLower.Contains("password") Then
            RemoveSanitisedVars(CodeLine)
        ElseIf Regex.IsMatch(CodeLine, "LogError|Logger|logger|Logging|logging|System\.Diagnostics\.Debug|System\.Diagnostics\.Trace") And CodeLine.ToLower.Contains("password") Then
            If (InStr(CodeLine.ToLower, "log") < InStr(CodeLine.ToLower, "password")) Then frmMain.ListCodeIssue("Application Appears to Log User Passwords", "The application appears to write user passwords to logfiles creating a risk of credential theft.", FileName, CodeIssue.HIGH, CodeLine)
        ElseIf Regex.IsMatch(CodeLine, "LogError|Logger|logger|Logging|logging|System\.Diagnostics\.Debug|System\.Diagnostics\.Trace") Then
            For Each strVar In ctCodeTracker.InputVars
                If CodeLine.Contains(strVar) Then
                    frmMain.ListCodeIssue("Unsanitized Data Written to Logs", "The application appears to write unsanitized data to its logfiles. If logs are viewed by a browser-based application this exposes risk of XSS attacks.", FileName, CodeIssue.MEDIUM, CodeLine)
                    Exit For
                End If
            Next
        End If

    End Sub

    Public Sub CheckSerialization(CodeLine As String, FileName As String)
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


    Public Sub CheckHTTPRedirect(CodeLine As String, FileName As String)
        ' Check for safe use HTTP redirects and potential open redirect vulnerabilities
        '================================================================================

        Dim blnIsFound As Boolean = False

        '== Check for secure HTTP usage ==
        If CodeLine.Contains("Response.Redirect(") And CodeLine.Contains("HTTP:") Then
            frmMain.ListCodeIssue("URL request sent over HTTP:",
            "The URL used in the HTTP request appears to be unencrypted. Check the code manually to ensure that sensitive data is not being submitted.",
            FileName, CodeIssue.STANDARD, CodeLine)

            '== Check for insecure variables in redirects ==
        ElseIf Regex.IsMatch(CodeLine, "Response\.Redirect\(") And Not Regex.IsMatch(CodeLine, "Response\.Redirect\(\s*\""\S+\""\s*\)") Then
            For Each strVar In ctCodeTracker.InputVars
                If Regex.IsMatch(CodeLine, "Response\.Redirect\(\s*" & strVar) Or Regex.IsMatch(CodeLine, "Response\.Redirect\(\s*(\""\S+\""|S+)\s*(\+|\&)\s*" & strVar) Then
                    frmMain.ListCodeIssue("URL Request Gets Path from Unvalidated Variable",
                    "The URL used in the HTTP request is loaded from an unsanitised variable. This can allow an attacker to redirect the user to a site under the control of a third party.",
                    FileName, CodeIssue.MEDIUM, CodeLine)
                    blnIsFound = True
                    Exit For
                End If
            Next
            If blnIsFound = False Then
                frmMain.ListCodeIssue("URL Request Gets Path from Variable",
                "The URL used in the HTTP request appears to be loaded from a variable. Check the code manually to ensure that malicious URLs cannot be submitted by an attacker.",
                FileName, CodeIssue.STANDARD, CodeLine)
            End If
        End If

        '== Check for potential open redirect vulnerabilities ==
        Dim redirectPattern As String = "\bResponse\.Redirect\s*\(\s*[^""]+\s*\)|\bServer\.Transfer\s*\(\s*[^""]+\s*\)"
        Dim queryParamPattern As String = "\?url=|redirect=|returnUrl="

        If Regex.IsMatch(CodeLine, redirectPattern) OrElse Regex.IsMatch(CodeLine, queryParamPattern) Then
            Dim validationPattern As String = "\b(StartsWith|UrlEncode|IsLocalUrl|SanitizeInput|Validate)\s*\("
            If Not Regex.IsMatch(CodeLine, validationPattern) Then
                frmMain.ListCodeIssue("Open Redirect Vulnerability",
                "The application appears to allow open redirects without proper validation or sanitization of the URL. Ensure all redirect URLs are validated to prevent open redirects.",
                FileName, CodeIssue.HIGH, CodeLine)
            End If
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
        If Regex.IsMatch(CodeLine, "\bRandom\b\.Next(Bytes\(|\()") Then
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
        If ctCodeTracker.IsSamlFunction = False And Regex.IsMatch(CodeLine, "\boverride\b\s+\bvoid\b\s+\bValidateConditions\b\(\bSaml2Conditions\b") Then
            If CodeLine.Contains("{") Then
                ctCodeTracker.IsSamlFunction = ctCodeTracker.TrackBraces(CodeLine, ctCodeTracker.ClassBraces)
            Else
                ctCodeTracker.IsSamlFunction = True
            End If
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

        End If

    End Sub

    Private Sub CheckUnsafeTempFiles(CodeLine As String, FileName As String)
        ' Identify any creation of temp files with static names
        '======================================================

        If Regex.IsMatch(CodeLine, "\=\s*File\.Open\(\""\S*(temp|tmp)\S*\""\,") Then
            frmMain.ListCodeIssue("Unsafe Temporary File Allocation", "The application appears to create a temporary file with a static, hard-coded name. This causes security issues in the form of a classic race condition (an attacker creates a file with the same name between the application's creation and attempted usage) or a symbolic link attack where an attacker creates a symbolic link at the temporary file location.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

    End Sub

    Public Sub CheckFileRace(CodeLine As String, FileName As String)
        ' Check for potential TOCTOU/race conditions
        '===========================================

        Dim intSeverity As Integer = 0  ' For TOCTOU vulns, severity will be modified according to length of time between check and usage.


        '== Check for TOCTOU (Time Of Check, Time Of Use) vulnerabilities==
        If (Not ctCodeTracker.IsLstat) And (Regex.IsMatch(CodeLine, "(File|Directory)\.Exists\(") And Not Regex.IsMatch(CodeLine, "Process\.Start\(|new\s+FileInfo\(|Directory\.GetFiles\(|\.FileName\;")) Then
            ' Check has taken place - begin monitoring for use of the file/dir
            ctCodeTracker.IsLstat = True
        ElseIf ctCodeTracker.IsLstat Then
            ' Increase line count while monitoring
            If CodeLine.Trim <> "" And CodeLine.Trim <> "{" And CodeLine.Trim <> "}" Then
                ctCodeTracker.TocTouLineCount += 1
            End If

            If ctCodeTracker.TocTouLineCount < 2 And Regex.IsMatch(CodeLine, "Process\.Start\(|new\s+FileInfo\(|Directory\.GetFiles\(|\.FileName\;") Then
                ' Usage takes place almost immediately so no problem
                ctCodeTracker.IsLstat = False
            ElseIf ctCodeTracker.TocTouLineCount > 1 And Regex.IsMatch(CodeLine, "Process\.Start\(|new\s+FileInfo\(|Directory\.GetFiles\(|\.FileName\;") Then
                ' Usage takes place sometime later. Set severity accordingly and notify user
                ctCodeTracker.IsLstat = False
                If ctCodeTracker.TocTouLineCount > 5 Then intSeverity = 2
                frmMain.ListCodeIssue("Potential TOCTOU (Time Of Check, Time Of Use) Vulnerability", "The .Exists() check occurs " & ctCodeTracker.TocTouLineCount & " lines before the file/directory is accessed. The longer the time between the check and the fopen(), the greater the likelihood that the check will no longer be valid.", FileName)
            End If
        End If

    End Sub

    Private Sub CheckUnsafeCode(CodeLine As String, FileName As String)
        ' Identify any unsafe code directives
        '====================================

        If ctCodeTracker.IsUnsafe = False And Regex.IsMatch(CodeLine, "\bunsafe\b") Then
            frmMain.ListCodeIssue("Unsafe Code Directive", "The uses the 'unsafe' directive which allows the use of C-style pointers in the code. This code has an increased risk of unexpected behaviour, including buffer overflows, memory leaks and crashes.", FileName, CodeIssue.MEDIUM, CodeLine)
            If CodeLine.Contains("{") Then
                ctCodeTracker.IsUnsafe = ctCodeTracker.TrackBraces(CodeLine, ctCodeTracker.UnsafeBraces)
            Else
                ctCodeTracker.IsUnsafe = True
            End If
        End If
        If ctCodeTracker.IsUnsafe = True Then
            '== Locate any fixed size buffers ==
            If Regex.IsMatch(CodeLine, "\bfixed\b\s+char\s+\w+\s*\[") Then
                ctCodeTracker.AddBuffer(CodeLine)
            ElseIf Regex.IsMatch(CodeLine, "\bfixed\b\s+byte\s+\w+\s*\[") Then
                ctCodeTracker.AddBuffer(CodeLine, "byte")
            End If
            ctCodeTracker.IsUnsafe = ctCodeTracker.TrackBraces(CodeLine, ctCodeTracker.UnsafeBraces)
        End If

    End Sub

    Private Sub CheckThreadIssues(CodeLine As String, FileName As String)
        ' Identify potential for race conditions and deadlocking
        '=======================================================
        Dim blnIsRace As Boolean = False
        Dim strSyncObject As String = ""



        '== Identify object locked for use in synchronized block ==
        If ctCodeTracker.IsSynchronized = False And Regex.IsMatch(CodeLine, "\block\b\s*\(\s*\w+\s*\)") Then
            strSyncObject = GetSyncObject(CodeLine)
            ctCodeTracker.LockedObject = strSyncObject
            ctCodeTracker.SyncIndex += 1
        End If



        '== Identify entry into a synchronized block ==
        '== The synchronized may be followed by method type and name for a synchronized method, or by braces for a synchronized block ==
        If ctCodeTracker.IsSynchronized = False And Regex.IsMatch(CodeLine, "\block\b\s*\S*\s*\S*\s*\(") Then
            If CodeLine.Contains("{") Then
                ctCodeTracker.IsSynchronized = ctCodeTracker.TrackBraces(CodeLine, ctCodeTracker.SyncBraces)
            Else
                ctCodeTracker.IsSynchronized = True
            End If

        ElseIf ctCodeTracker.IsSynchronized = False Then

            '== Check for any unsafe modifications to instance variables == 
            If ctCodeTracker.GlobalVars.Count > 0 Then
                For Each itmItem In ctCodeTracker.GlobalVars
                    blnIsRace = CheckRaceCond(CodeLine, FileName, itmItem)
                    If blnIsRace Then Exit For
                Next
            End If

            If blnIsRace = False And ctCodeTracker.GetSetMethods.Count > 0 Then
                For Each itmItem In ctCodeTracker.GetSetMethods
                    blnIsRace = CheckRaceCond(CodeLine, FileName, itmItem)
                    If blnIsRace Then Exit For
                Next
            End If

        ElseIf ctCodeTracker.IsSynchronized Then
            '== Track the amount of code that is inside the lock - resources may be locked unnecessarily ==
            If (CodeLine.Trim <> "{" And CodeLine.Trim <> "}") Then ctCodeTracker.SyncLineCount += 1

            '== Check whether still inside synchronized code ==
            ctCodeTracker.IsSynchronized = ctCodeTracker.TrackBraces(CodeLine, ctCodeTracker.SyncBraces)

            '== Check for large areas of locked code and potential deadlock ==
            CheckSyncIssues(CodeLine, FileName)
        End If

    End Sub

    Private Sub CheckSyncIssues(CodeLine As String, FileName As String)
        ' Check for, and report on, any issues located inside the synchronized block or when leaving the block
        '=====================================================================================================
        Dim intSeverity As Integer = 0
        Dim intIndex As Integer = 0
        Dim strSyncObject As String = ""
        Dim strOuterSyncObject As String = ""


        '== Report potentially excessive locking when leaving the code block ==
        If ctCodeTracker.IsSynchronized = False Then

            If ctCodeTracker.SyncLineCount > 14 Then
                intSeverity = CodeIssue.MEDIUM
            ElseIf ctCodeTracker.SyncLineCount > 10 Then
                intSeverity = CodeIssue.STANDARD
            ElseIf ctCodeTracker.SyncLineCount > 6 Then
                intSeverity = CodeIssue.LOW
            End If

            If ctCodeTracker.SyncLineCount > 6 Then
                frmMain.ListCodeIssue("Thread Locks - Possible Performance Impact", "There are " & ctCodeTracker.SyncLineCount & " lines of code in the locked code block. Manually check the code to ensure any shared resources are not being locked unnecessarily.", FileName, intSeverity)
            End If

            ctCodeTracker.SyncLineCount = 0

        ElseIf ctCodeTracker.LockedObject <> "" And Regex.IsMatch(CodeLine, "\block\b\s*\(\s*\w+\s*\)") Then
            '== Build dictionary for potential deadlocks by tracking synchronized blocks inside synchronized blocks ==
            strOuterSyncObject = ctCodeTracker.LockedObject
            strSyncObject = GetSyncObject(CodeLine)

            If strSyncObject <> "" Then
                '== Check if this sync block already exists ==
                For Each itmItem In ctCodeTracker.SyncBlockObjects
                    If itmItem.BlockIndex = ctCodeTracker.SyncIndex Then
                        intIndex = itmItem.BlockIndex
                        '== Add to existing block ==
                        If Not itmItem.InnerObjects.Contains(strSyncObject) Then itmItem.InnerObjects.Add(strSyncObject)
                        Exit For
                    End If
                Next

                '== Create new sync block an add inner object name ==
                If intIndex = 0 Then AddNewSyncBlock(strOuterSyncObject, strSyncObject)

                CheckDeadlock(strOuterSyncObject, strSyncObject, FileName)

            End If
        End If

    End Sub

    Private Function GetSyncObject(CodeLine As String) As String
        ' Extract the name of a synchronized object from a line of code
        '==============================================================
        Dim strSyncObject As String = ""
        Dim strFragments As String()


        strFragments = Regex.Split(CodeLine, "\block\b\s*\(")
        strSyncObject = GetFirstItem(strFragments.Last, ")")
        If strSyncObject <> "" Then ctCodeTracker.LockedObject = strSyncObject

        Return strSyncObject

    End Function

    Private Function CheckRaceCond(CodeLine As String, FileName As String, DictionaryItem As KeyValuePair(Of String, String)) As Boolean
        ' Check if line contains any references to public variables of servlets or to getter/setter methods of servlets
        '==============================================================================================================
        Dim strServletName As String = ""
        Dim arrFragments As String()
        Dim blnRetVal As Boolean = False


        If CodeLine.Contains("." & DictionaryItem.Key) Then
            arrFragments = Regex.Split(CodeLine, "." & DictionaryItem.Key)
            strServletName = GetLastItem(arrFragments.First)
            If ctCodeTracker.ServletInstances.Count > 0 And ctCodeTracker.ServletInstances.ContainsKey(strServletName) Then
                If DictionaryItem.Value = ctCodeTracker.ServletInstances.Item(strServletName) Then
                    frmMain.ListCodeIssue("Possible Race Condition", "A global variable is being used/modified without a 'lock' block.", FileName, CodeIssue.HIGH)
                    blnRetVal = True
                End If
            End If
        End If

        Return blnRetVal

    End Function

    Public Sub RemoveSanitisedVars(CodeLine As String)
        ' Remove any variables which have been sanitised from the list of vulnerable variables
        '=====================================================================================

        If ctCodeTracker.InputVars.Count > 0 Then
            For Each strVar In ctCodeTracker.InputVars
                If Not (strVar.contains("(") Or strVar.contains(")") Or strVar.contains("[") Or strVar.contains("]") Or strVar.contains(" ") Or strVar.contains("+") Or strVar.contains("*")) Then
                    If Regex.IsMatch(CodeLine, strVar & "\s*\=\s*\S*(validate|encode|sanitize|sanitise)\S*\(" & strVar) Then
                        ctCodeTracker.InputVars.Remove(strVar)
                        Exit For
                    End If
                End If
            Next
        End If

    End Sub

    Public Sub CheckWebConfig(CodeLine As String, FileName As String)
        ' Report any security issues in config file such as debugging or .net default errors
        '===================================================================================

        If Not FileName.ToLower.EndsWith("web.config") Then Exit Sub

        ' Check for .NET Default Errors Enabled
        If Regex.IsMatch(CodeLine, "\<\s*customErrors\s+mode\s*\=\s*\""Off\""\s*\/\>") Then
            frmMain.ListCodeIssue(".NET Default Errors Enabled", "The application is configured to display .NET default errors. This can provide an attacker with useful information and should not be used in a live application.", FileName, CodeIssue.MEDIUM)

            ' Check for .NET Debugging Enabled
        ElseIf Regex.IsMatch(CodeLine, "\bdebug\b\s*\=\s*\""\s*true\s*\""") Then
            frmMain.ListCodeIssue(".NET Debugging Enabled", "The application is configured to return .NET debug information. This can provide an attacker with useful information and should not be used in a live application.", FileName, CodeIssue.MEDIUM)

            ' Check for IIS Custom Errors Enabled
        ElseIf Regex.IsMatch(CodeLine, "\<\s*customErrors\s+mode\s*\=\s*\""On\""\s+defaultRedirect\s*\=\s*\""~/Error\""\s*\/\>") Then
            frmMain.ListCodeIssue("IIS Custom Errors Enabled", "Custom errors are properly configured to prevent accidental leakage of error details to clients.", FileName, CodeIssue.LOW)

            ' Check for HTTP Errors Mode set to Custom
        ElseIf Regex.IsMatch(CodeLine, "\<\s*httpErrors\s+errorMode\s*\=\s*\""Custom\""\s*\/\>") Then
            frmMain.ListCodeIssue("HTTP Errors Custom Mode Enabled", "HTTP errors are set to custom mode, improving user experience and preventing error details leakage.", FileName, CodeIssue.LOW)

            ' Check for Debug Compilation Disabled
        ElseIf Regex.IsMatch(CodeLine, "\<\s*compilation\s+debug\s*\=\s*\""false\""\s*\/\>") Then
            frmMain.ListCodeIssue("Debug Compilation Disabled", "The debug compilation setting is correctly set to false to avoid performance issues in production.", FileName, CodeIssue.LOW)

            ' Check for IIS Version Exposure Prevention
        ElseIf Regex.IsMatch(CodeLine, "\<\s*modules\s+runAllManagedModulesForAllRequests\s*\=\s*\""true\""\s*\/\>") Then
            frmMain.ListCodeIssue("IIS Version Exposure Prevention", "The configuration ensures that the IIS version is not exposed via the Server HTTP response header.", FileName, CodeIssue.LOW)

            ' Check for Removing Server Header in IIS 7+
        ElseIf Regex.IsMatch(CodeLine, "\<\s*requestFiltering\s+removeServerHeader\s*\=\s*\""true\""\s*\/\>") Then
            frmMain.ListCodeIssue("IIS Server Header Removal", "The configuration ensures that the Server HTTP response header is removed in IIS 7+ to prevent IIS version exposure.", FileName, CodeIssue.LOW)

            ' Check for ASP.NET Version Exposure Prevention
        ElseIf Regex.IsMatch(CodeLine, "\<\s*remove\s+name\s*\=\s*\""X-Powered-By\""\s*\/\>") Then
            frmMain.ListCodeIssue("ASP.NET Version Exposure Prevention", "The X-Powered-By header is removed to prevent ASP.NET version exposure.", FileName, CodeIssue.LOW)

            ' Check for ASP.NET Version Header Removal Using Rewrite Rule
        ElseIf Regex.IsMatch(CodeLine, "\<\s*rule\s+name\s*\=\s*\""Remove X-Powered-By HTTP response header\""\>") Then
            frmMain.ListCodeIssue("ASP.NET Version Exposure Prevention Using Rewrite", "An IIS URL Rewrite rule is used to remove the X-Powered-By header, preventing ASP.NET version exposure.", FileName, CodeIssue.LOW)

            ' Check for ASP.NET Version Header Disabled
        ElseIf Regex.IsMatch(CodeLine, "\<\s*httpRuntime\s+enableVersionHeader\s*\=\s*\""false\""\s*\/\>") Then
            frmMain.ListCodeIssue("ASP.NET Version Header Disabled", "The version header in ASP.NET is disabled to prevent version exposure.", FileName, CodeIssue.LOW)

            ' Check for HTTPS Requirement
        ElseIf Regex.IsMatch(CodeLine, "\<\s*httpRedirect\s+enabled\s*\=\s*\""false\""\s*\/\>") Then
            frmMain.ListCodeIssue("HTTPS Requirement in Root Site", "The configuration disables HTTP redirects, ensuring that HTTPS is required.", FileName, CodeIssue.LOW)

            ' Check for HTTP-Only and SSL-Only Cookies
        ElseIf Regex.IsMatch(CodeLine, "\<\s*httpCookies\s+httpOnlyCookies\s*\=\s*\""true\""\s+requireSSL\s*\=\s*\""true\""\s*\/\>") Then
            frmMain.ListCodeIssue("HTTP-Only and SSL-Only Cookies Enabled", "The cookies are set to HTTP-Only and SSL-Only, protecting against XSS and man-in-the-middle attacks.", FileName, CodeIssue.LOW)

            ' Check for SSL Requirement for Forms Authentication
        ElseIf Regex.IsMatch(CodeLine, "\<\s*forms\s+requireSSL\s*\=\s*\""true\""\s*\/\>") Then
            frmMain.ListCodeIssue("SSL Required for Forms Authentication", "The configuration ensures that SSL is required for forms authentication cookies, protecting against unauthorized access.", FileName, CodeIssue.LOW)

            ' Check for HSTS (Strict Transport Security)
        ElseIf Regex.IsMatch(CodeLine, "\<\s*appendHeader\s+name\s*\=\s*\""Strict-Transport-Security\""\s+value\s*\=\s*\""max-age\=31536000\""\s*\/\>") Then
            frmMain.ListCodeIssue("Strict Transport Security (HSTS) Enabled", "The Strict-Transport-Security header is enabled, helping prevent HTTPS Strip and man-in-the-middle attacks.", FileName, CodeIssue.LOW)

            ' Check for Click-Jacking Protection (X-Frame-Options)
        ElseIf Regex.IsMatch(CodeLine, "\<\s*add\s+name\s*\=\s*\""X-Frame-Options\""\s+value\s*\=\s*\""DENY\""\s*\/\>") Then
            frmMain.ListCodeIssue("Click-Jacking Protection", "The X-Frame-Options header is set to DENY, preventing Click-Jacking attacks.", FileName, CodeIssue.LOW)

            ' Check for X-Frame-Options SAMEORIGIN
        ElseIf Regex.IsMatch(CodeLine, "\<\s*add\s+name\s*\=\s*\""X-Frame-Options\""\s+value\s*\=\s*\""SAMEORIGIN\""\s*\/\>") Then
            frmMain.ListCodeIssue("Framing Allowed from Same Origin", "The X-Frame-Options header is set to SAMEORIGIN, allowing framing only from the same origin.", FileName, CodeIssue.LOW)

            ' Check for Cache Control
        ElseIf Regex.IsMatch(CodeLine, "\<\s*meta\s+http\-equiv\s*\=\s*\""Cache\-Control\""\s+content\s*\=\s*\""no\-cache, no\-store\""\s*\/\>") Then
            frmMain.ListCodeIssue("Cache Control for Secure Content", "Cache-Control is set to no-cache, no-store to prevent secure content from being cached.", FileName, CodeIssue.LOW)

            ' Check for Machine Encryption and Decryption Keys
        ElseIf Regex.IsMatch(CodeLine, "\<\s*machineKey\s+decryption\s*\=\s*\""AES\""\s+decryptionKey\s*\=\s*\""[A-Za-z0-9]+\""\s+validation\s*\=\s*\""SHA1\""\s+validationKey\s*\=\s*\""[A-Za-z0-9]+\""\s*\/\>") Then
            frmMain.ListCodeIssue("Machine Encryption/Decryption Keys Configured", "Machine keys for encryption and decryption are explicitly configured.", FileName, CodeIssue.LOW)

            ' Check for Trace.axd Disabled
        ElseIf Regex.IsMatch(CodeLine, "\<\s*trace\s+enabled\s*\=\s*\""false\""\s+localOnly\s*\=\s*\""true\""\s*\/\>") Then
            frmMain.ListCodeIssue("Trace.axd Disabled", "Trace.axd is disabled, preventing accidental information leakage in production environments.", FileName, CodeIssue.LOW)

            ' Check for Azure ARRAffinity Cookie
        ElseIf Regex.IsMatch(CodeLine, "\<\s*add\s+name\s*\=\s*\""Arr-Disable-Session-Affinity\""\s+value\s*\=\s*\""True\""\s*\/\>") Then
            frmMain.ListCodeIssue("ARR Affinity Cookie Disabled", "ARR Affinity cookie is disabled, preventing insecure session affinity cookies in Azure.", FileName, CodeIssue.LOW)

            ' Check for Role Manager SSL Requirement
        ElseIf Regex.IsMatch(CodeLine, "\<\s*roleManager\s+cookieRequireSSL\s*\=\s*\""true\""\s*\/\>") Then
            frmMain.ListCodeIssue("Secure Role Manager Cookies", "Role Manager cookies are set to require SSL, enhancing security for role management.", FileName, CodeIssue.LOW)

            ' Check for OWIN Secure Cookies
        ElseIf Regex.IsMatch(CodeLine, "CookieSecure\s*=\s*CookieSecureOption.Always") Then
            frmMain.ListCodeIssue("Secure OWIN Cookies", "OWIN cookie authentication is configured to use secure cookies, preventing cookie theft.", FileName, CodeIssue.LOW)

            ' Check for Renamed Forms Authentication Cookie
        ElseIf Regex.IsMatch(CodeLine, "\<\s*forms\s+name\s*\=\s*\""myformscookie\""\s*\/\>") Then
            frmMain.ListCodeIssue("Renamed Forms Authentication Cookie", "Forms authentication cookie has been renamed to obscure technology stack.", FileName, CodeIssue.LOW)

            ' Check for Renamed Role Manager Cookie
        ElseIf Regex.IsMatch(CodeLine, "\<\s*roleManager\s+cookieName\s*\=\s*\""myrolescookie\""\s*\/\>") Then
            frmMain.ListCodeIssue("Renamed Role Manager Cookie", "Role Manager cookie has been renamed to obscure technology stack.", FileName, CodeIssue.LOW)

            ' Check for Renamed Session State Cookie
        ElseIf Regex.IsMatch(CodeLine, "\<\s*sessionState\s+cookieName\s*\=\s*\""mysessioncookie\""\s*\/\>") Then
            frmMain.ListCodeIssue("Renamed Session State Cookie", "Session state cookie has been renamed to obscure technology stack.", FileName, CodeIssue.LOW)

            ' Check for Renamed Anti-Forgery Cookie
        ElseIf Regex.IsMatch(CodeLine, "AntiForgeryConfig.CookieName\s*=\s*\""myxsrfcookie\"";") Then
            frmMain.ListCodeIssue("Renamed Anti-Forgery Cookie", "Anti-Forgery cookie has been renamed to obscure technology stack.", FileName, CodeIssue.LOW)

            ' Check for Renamed ASP.NET Identity Cookie
        ElseIf Regex.IsMatch(CodeLine, "CookieName\s*=\s*\""myauthcookie\"";") Then
            frmMain.ListCodeIssue("Renamed ASP.NET Identity Cookie", "ASP.NET Identity cookie has been renamed to obscure technology stack.", FileName, CodeIssue.LOW)

        End If
    End Sub

    Private Sub CheckMisconfiguredRoutes(CodeLine As String, FileName As String)
        ' Check for potential misconfigured routes or connection strings
        ' =============================================================

        ' Create a dictionary containing regex patterns and corresponding warning messages
        Dim rulesDictionary As New Dictionary(Of Rules, String) From {
        {Rules.MapControllerRoute, "Potential misconfigured route: MapControllerRoute"},
        {Rules.MapHttpRoute, "Potential misconfigured route: MapHttpRoute"},
        {Rules.MapPageRoute, "Potential misconfigured route: MapPageRoute"},
        {Rules.MapRoute, "Potential misconfigured route: MapRoute"},
        {Rules.CreateRoute, "Potential misconfigured route: CreateRoute"},
        {Rules.MapGet, "Potential misconfigured HTTP GET: MapGet"},
        {Rules.MapPost, "Potential misconfigured HTTP POST: MapPost"},
        {Rules.HttpGet, "Use of HTTP GET detected, verify it does not expose sensitive data"},
        {Rules.HttpPost, "Use of HTTP POST detected, ensure proper input validation"},
        {Rules.connectionString, "Potential hardcoded connection string detected"}
    }

        ' Loop through each rule and check against the code line
        For Each rule In rulesDictionary.Keys
            Dim pattern As String = ""

            ' Create the regular expression pattern based on the rule
            Select Case rule
                Case Rules.MapControllerRoute, Rules.MapHttpRoute, Rules.MapPageRoute, Rules.MapRoute, Rules.CreateRoute, Rules.MapGet, Rules.MapPost, Rules.HttpGet, Rules.HttpPost
                    pattern = "\b" & rule.ToString() & "\("
                Case Rules.connectionString
                    pattern = "connectionString=\"""
            End Select

            ' Check if the code line matches the pattern
            If Regex.IsMatch(CodeLine, pattern) Then
                frmMain.ListCodeIssue("Potential Misconfiguration Detected", rulesDictionary(rule), FileName, CodeIssue.MEDIUM, CodeLine)
            End If
        Next
    End Sub


    '======================================================================================
    '== EXTENDED RULESET                                                                 ==
    '== Additional checks appended without altering any pre-existing logic.              ==
    '======================================================================================

    Private Function IsUserInputCSharp(CodeLine As String) As Boolean
        ' Return True where the line appears to reference a tainted (user-controlled) source
        '==================================================================================

        If Regex.IsMatch(CodeLine, "\bRequest\s*(\.\s*(QueryString|Form|Params|Cookies|Headers|Files|Url|RawUrl|UserAgent|UrlReferrer|Item|Body|Path|QueryHelpers)|\[)") Then Return True
        If Regex.IsMatch(CodeLine, "\bHttpContext\s*\.\s*(Current\s*\.\s*)?Request\b") Then Return True
        If Regex.IsMatch(CodeLine, "\[\s*From(Query|Body|Form|Route|Header)\s*\]") Then Return True
        If Regex.IsMatch(CodeLine, "\b(Console\s*\.\s*ReadLine|Environment\s*\.\s*GetEnvironmentVariable|Environment\s*\.\s*GetCommandLineArgs)\b") Then Return True
        If Regex.IsMatch(CodeLine, "\bargs\s*\[") Then Return True
        If Regex.IsMatch(CodeLine, "\b\w*(txt|input|param|query|user)\w*\s*\.\s*Text\b") Then Return True

        '== Fall back on any variable already flagged as user-controlled by the tracker ==
        For Each strVar In ctCodeTracker.InputVars
            If strVar <> "" AndAlso CodeLine.Contains(strVar) Then Return True
        Next

        Return False

    End Function

    Private Sub CheckWeakCryptography(CodeLine As String, FileName As String)
        ' Identify broken/deprecated cryptographic primitives, unsafe modes and weak key derivation
        '=========================================================================================
        Dim intIterations As Integer = 0
        Dim intKeySize As Integer = 0
        Dim mchMatch As Match


        '== Broken or deprecated hash algorithms ==
        If Regex.IsMatch(CodeLine, "\b(MD5|MD4|SHA1|RIPEMD160)(CryptoServiceProvider|Managed|Cng)?\s*\.\s*Create\s*\(") Or _
           Regex.IsMatch(CodeLine, "\bnew\s+(MD5|SHA1|RIPEMD160)(CryptoServiceProvider|Managed|Cng)\s*\(") Or _
           Regex.IsMatch(CodeLine, "\b(HMACMD5|HMACRIPEMD160)\b") Or _
           Regex.IsMatch(CodeLine, "(HashAlgorithm|CryptoConfig)\s*\.\s*Create\s*\(\s*""\s*(MD5|SHA1|SHA-1|MD4)") Then
            frmMain.ListCodeIssue("Use of Broken or Deprecated Hashing Algorithm", "The code uses a hash function (MD4/MD5/SHA-1/RIPEMD-160) for which practical collision attacks exist. Where the hash is used for signatures, integrity checks or password storage this permits forgery or offline recovery. Migrate to SHA-256/SHA-384/SHA-512 or, for passwords, to a memory-hard KDF such as Argon2id, scrypt or PBKDF2-HMAC-SHA256 with a high iteration count.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

        '== Broken or deprecated symmetric ciphers ==
        If Regex.IsMatch(CodeLine, "\b(DES|TripleDES|RC2)(CryptoServiceProvider|Managed|Cng)?\s*\.\s*Create\s*\(") Or _
           Regex.IsMatch(CodeLine, "\bnew\s+(DES|TripleDES|RC2)(CryptoServiceProvider|Managed|Cng)\s*\(") Or _
           Regex.IsMatch(CodeLine, "(SymmetricAlgorithm|CryptoConfig)\s*\.\s*Create\s*\(\s*""\s*(DES|3DES|TripleDES|RC2|RC4)") Then
            frmMain.ListCodeIssue("Use of Broken or Deprecated Symmetric Cipher", "The code uses DES, Triple-DES or RC2. DES has a 56-bit effective key and is trivially brute-forced; Triple-DES and RC2 have 64-bit blocks and are subject to birthday-bound (Sweet32) attacks after roughly 32GB of ciphertext under one key. Use AES-256 in an authenticated mode (GCM) instead.", FileName, CodeIssue.HIGH, CodeLine)
        End If

        '== Unauthenticated / deterministic cipher modes ==
        If Regex.IsMatch(CodeLine, "\bCipherMode\s*\.\s*ECB\b") Then
            frmMain.ListCodeIssue("Use of ECB Cipher Mode", "ECB encrypts each block independently, so identical plaintext blocks produce identical ciphertext blocks. This leaks structure of the plaintext and permits block reordering, splicing and cut-and-paste attacks. Use an authenticated mode (AES-GCM) or, at minimum, CBC with a random IV plus a separate HMAC.", FileName, CodeIssue.HIGH, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\bPaddingMode\s*\.\s*(None|Zeros|ANSIX923)\b") Then
            frmMain.ListCodeIssue("Potentially Unsafe Padding Mode", "A padding mode has been selected which does not permit unambiguous removal of padding, or which is prone to implementation error. Combined with CBC and an error oracle this may permit padding-oracle decryption. Prefer authenticated encryption.", FileName, CodeIssue.LOW, CodeLine)
        End If

        '== Static or hard-coded key/IV material ==
        If Regex.IsMatch(CodeLine, "\.\s*(Key|IV)\s*=\s*(Encoding\s*\.\s*\w+\s*\.\s*GetBytes\s*\(\s*""|Convert\s*\.\s*FromBase64String\s*\(\s*""|new\s+byte\s*\[\s*\]\s*\{)") Then
            frmMain.ListCodeIssue("Hard-Coded Cryptographic Key or IV", "The symmetric key or initialisation vector appears to be embedded in the source. Anyone with the binary can recover it via decompilation, so the encryption provides no confidentiality against an attacker who obtains the ciphertext. Keys should be sourced from a key vault, DPAPI or an HSM, and IVs must be randomly generated per message.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\.\s*IV\s*=\s*new\s+byte\s*\[\s*\d+\s*\]\s*(;|$)") Then
            frmMain.ListCodeIssue("Zeroed Initialisation Vector", "The IV is assigned an all-zero byte array. A fixed IV in CBC mode makes encryption deterministic, revealing whether two plaintexts share a common prefix; in CTR/GCM modes IV reuse is catastrophic and allows recovery of the keystream. Generate the IV with RandomNumberGenerator for every operation.", FileName, CodeIssue.HIGH, CodeLine)
        End If

        '== Weak asymmetric key sizes ==
        mchMatch = Regex.Match(CodeLine, "\bnew\s+(RSACryptoServiceProvider|DSACryptoServiceProvider|RSACng)\s*\(\s*(\d+)")
        If mchMatch.Success Then
            If Integer.TryParse(mchMatch.Groups(2).Value, intKeySize) Then
                If intKeySize > 0 And intKeySize < 2048 Then
                    frmMain.ListCodeIssue("Insufficient Asymmetric Key Length", "An RSA/DSA key of " & intKeySize.ToString() & " bits is created. Keys below 2048 bits no longer provide an adequate security margin and are rejected by current standards (NIST SP 800-57, BSI TR-02102). Use 3072 bits or an elliptic-curve key (P-256 or better).", FileName, CodeIssue.HIGH, CodeLine)
                End If
            End If
        End If
        If Regex.IsMatch(CodeLine, "\.\s*KeySize\s*=\s*(512|768|1024)\b") Then
            frmMain.ListCodeIssue("Insufficient Asymmetric Key Length", "The key size has been explicitly reduced to a value below 2048 bits, which is no longer considered adequate. Use 3072 bits for RSA or an elliptic-curve equivalent.", FileName, CodeIssue.HIGH, CodeLine)
        End If

        '== Weak password-based key derivation ==
        If Regex.IsMatch(CodeLine, "\bnew\s+(Rfc2898DeriveBytes|PasswordDeriveBytes)\s*\(") Then
            If Regex.IsMatch(CodeLine, "\bnew\s+PasswordDeriveBytes\s*\(") Then
                frmMain.ListCodeIssue("Use of Obsolete Key Derivation Function", "PasswordDeriveBytes implements PBKDF1, which is limited to 160 bits of output and is obsolete. Use Rfc2898DeriveBytes with HashAlgorithmName.SHA256 and a high iteration count, or a memory-hard KDF.", FileName, CodeIssue.MEDIUM, CodeLine)
            End If
            mchMatch = Regex.Match(CodeLine, "\bnew\s+Rfc2898DeriveBytes\s*\([^\)]*?,\s*(\d{1,7})\s*[\),]")
            If mchMatch.Success Then
                If Integer.TryParse(mchMatch.Groups(1).Value, intIterations) Then
                    If intIterations < 100000 Then
                        frmMain.ListCodeIssue("Insufficient PBKDF2 Iteration Count", "PBKDF2 is configured with " & intIterations.ToString() & " iterations. OWASP currently recommends at least 600,000 iterations for PBKDF2-HMAC-SHA256. A low work factor allows an attacker with the hash database to test billions of candidate passwords per second on commodity GPUs.", FileName, CodeIssue.MEDIUM, CodeLine)
                    End If
                End If
            ElseIf Not CodeLine.Contains(",") Then
                frmMain.ListCodeIssue("Default PBKDF2 Iteration Count", "Rfc2898DeriveBytes has been constructed without an explicit iteration count, defaulting to 1000 iterations of HMAC-SHA1. Specify at least 600,000 iterations and HashAlgorithmName.SHA256.", FileName, CodeIssue.MEDIUM, CodeLine)
            End If
        End If

        '== Passwords stored using a raw, unsalted hash ==
        If Regex.IsMatch(CodeLine, "(?i)\b\w*(password|passwd|pwd|secret)\w*\b") And Regex.IsMatch(CodeLine, "\b(ComputeHash|GetHashCode|HashPasswordForStoringInConfigFile)\b") Then
            frmMain.ListCodeIssue("Password Stored Using an Unsuitable Hash", "A password value appears to be passed to a general-purpose hash function. General hashes are designed to be fast and are therefore unsuitable for password storage. Use ASP.NET Core Identity's PasswordHasher, Argon2id, scrypt or PBKDF2 with a per-user salt and a high work factor.", FileName, CodeIssue.HIGH, CodeLine)
        End If

    End Sub

    Private Sub CheckCertificateValidation(CodeLine As String, FileName As String)
        ' Identify disabled TLS certificate validation and weak protocol selection
        '=========================================================================

        '== Blanket acceptance of any server certificate ==
        If Regex.IsMatch(CodeLine, "(ServerCertificateValidationCallback|ServerCertificateCustomValidationCallback|RemoteCertificateValidationCallback|ClientCertificateValidationCallback)") And _
           Regex.IsMatch(CodeLine, "(=>\s*true|return\s+true|delegate\s*\(|\{\s*return\s+true)") Then
            frmMain.ListCodeIssue("TLS Certificate Validation Disabled", "The certificate validation callback unconditionally returns true, so any certificate - including self-signed, expired or attacker-supplied certificates - is accepted. This removes all protection against active man-in-the-middle attacks and reduces TLS to unauthenticated encryption. Validate the chain, hostname and revocation status, or pin the expected certificate.", FileName, CodeIssue.CRITICAL, CodeLine)
        ElseIf Regex.IsMatch(CodeLine, "(ServerCertificateValidationCallback|ServerCertificateCustomValidationCallback|RemoteCertificateValidationCallback)\s*(\+|)=") Then
            frmMain.ListCodeIssue("Custom TLS Certificate Validation In Use", "A custom certificate validation callback is installed. Manually review the callback body to confirm that the certificate chain, hostname and expiry are all verified and that SslPolicyErrors is checked for None before the connection is accepted.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "\bDangerousAcceptAnyServerCertificateValidator\b") Then
            frmMain.ListCodeIssue("TLS Certificate Validation Disabled", "HttpClientHandler.DangerousAcceptAnyServerCertificateValidator disables all certificate verification for the handler, leaving connections open to man-in-the-middle interception.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If

        '== Obsolete protocol versions ==
        If Regex.IsMatch(CodeLine, "SecurityProtocolType\s*\.\s*(Ssl3|Tls|Tls11)\b") Or Regex.IsMatch(CodeLine, "SslProtocols\s*\.\s*(Ssl2|Ssl3|Tls|Tls11|None)\b") Then
            frmMain.ListCodeIssue("Obsolete TLS/SSL Protocol Version Selected", "SSLv3, TLS 1.0 and TLS 1.1 are deprecated (RFC 8996) and are vulnerable to POODLE, BEAST and downgrade attacks. Remove the explicit assignment so the OS negotiates the strongest available version, or pin to TLS 1.2/1.3.", FileName, CodeIssue.HIGH, CodeLine)
        End If

        '== Revocation checking turned off ==
        If Regex.IsMatch(CodeLine, "(CheckCertificateRevocationList|CheckCertificateRevocation)\s*=\s*false") Then
            frmMain.ListCodeIssue("Certificate Revocation Checking Disabled", "Revocation checking has been explicitly disabled, so certificates that have been revoked following a key compromise will still be accepted.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

        '== Transport downgrade / cleartext ==
        If Regex.IsMatch(CodeLine, "RequireHttpsMetadata\s*=\s*false") Then
            frmMain.ListCodeIssue("OIDC/JWT Metadata Retrieved Over Cleartext", "RequireHttpsMetadata is set to false, allowing OpenID Connect discovery documents and signing keys to be fetched over plain HTTP. An attacker on the network path can substitute their own signing keys and mint valid tokens.", FileName, CodeIssue.HIGH, CodeLine)
        End If

    End Sub

    Private Sub CheckPathTraversal(CodeLine As String, FileName As String)
        ' Identify filesystem operations driven by user-controlled data
        '==============================================================

        If Not Regex.IsMatch(CodeLine, "\b(File|FileInfo|Directory|DirectoryInfo|FileStream|StreamReader|StreamWriter|Path\s*\.\s*Combine|Server\s*\.\s*MapPath|File\s*\.\s*(ReadAllText|ReadAllBytes|ReadAllLines|WriteAllText|WriteAllBytes|Open|Delete|Copy|Move)|WriteAllTextAsync|SendFileAsync|PhysicalFile)\b") Then Exit Sub

        If IsUserInputCSharp(CodeLine) Then
            frmMain.ListCodeIssue("Potential Path Traversal", "A filesystem path appears to be constructed from user-controlled data. Path.Combine does not protect against traversal: if the second argument is rooted or contains '..' sequences the result escapes the intended directory, allowing arbitrary file read, overwrite or deletion. Canonicalise with Path.GetFullPath and verify the result begins with the intended base directory, or map the input to a whitelist of identifiers.", FileName, CodeIssue.HIGH, CodeLine)
        End If

        '== Archive extraction without entry-name validation (Zip Slip) ==
        If Regex.IsMatch(CodeLine, "\b(ExtractToDirectory|ExtractToFile|ExtractAll|ExtractCurrentFile|WriteToDirectory)\b") Then
            frmMain.ListCodeIssue("Potential Zip Slip During Archive Extraction", "Archive contents are extracted to disk. Where entry names inside the archive are not validated, a crafted entry such as '../../windows/system32/x.dll' will be written outside the extraction directory, permitting arbitrary file overwrite and, frequently, remote code execution. Resolve each entry to an absolute path and confirm it remains under the destination root before writing.", FileName, CodeIssue.HIGH, CodeLine)
        End If

    End Sub

    Private Sub CheckSSRF(CodeLine As String, FileName As String)
        ' Identify outbound requests whose destination is user-controlled
        '================================================================

        If Not Regex.IsMatch(CodeLine, "\b(WebRequest|HttpWebRequest|WebClient|HttpClient|HttpRequestMessage|RestClient|RestRequest|FtpWebRequest)\b") And _
           Not Regex.IsMatch(CodeLine, "\bnew\s+Uri\s*\(") And _
           Not Regex.IsMatch(CodeLine, "\.\s*(DownloadString|DownloadData|DownloadFile|GetAsync|PostAsync|SendAsync|GetStringAsync|GetStreamAsync|OpenRead)\s*\(") Then Exit Sub

        If IsUserInputCSharp(CodeLine) Then
            frmMain.ListCodeIssue("Potential Server-Side Request Forgery (SSRF)", "The destination of an outbound HTTP/FTP request appears to be derived from user input. An attacker can redirect the request to internal services, loopback addresses or cloud metadata endpoints (169.254.169.254) to reach systems that are not exposed externally and to steal instance credentials. Validate the target against an allow-list of hosts, resolve the hostname and reject private/link-local ranges, and disable automatic redirect following.", FileName, CodeIssue.HIGH, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "(AllowAutoRedirect|FollowRedirects)\s*=\s*true") Then
            frmMain.ListCodeIssue("Automatic Redirect Following Enabled", "The HTTP client follows redirects automatically. Where the initial URL is user-influenced, an allow-listed host can redirect the client to an internal address, bypassing the allow-list check. Disable redirect following and re-validate every hop.", FileName, CodeIssue.LOW, CodeLine)
        End If

    End Sub

    Private Sub CheckLdapAndXPathInjection(CodeLine As String, FileName As String)
        ' Identify LDAP and XPath queries built through concatenation
        '============================================================

        '== LDAP ==
        If Regex.IsMatch(CodeLine, "\b(DirectorySearcher|DirectoryEntry|SearchRequest|PrincipalSearcher)\b") Or Regex.IsMatch(CodeLine, "\.\s*Filter\s*=") Then
            If Regex.IsMatch(CodeLine, "\.\s*Filter\s*=\s*.*(\+|String\s*\.\s*(Format|Concat)|\$"")") Or (Regex.IsMatch(CodeLine, "\b(DirectorySearcher|SearchRequest)\b") And CodeLine.Contains("+")) Then
                frmMain.ListCodeIssue("Potential LDAP Injection", "An LDAP search filter appears to be assembled by string concatenation. Unescaped metacharacters such as '*', '(', ')', '\' and NUL allow an attacker to rewrite the filter - for example turning a login filter into '(|(uid=*)(uid=x))' to authenticate as any user or to enumerate the directory. Escape input per RFC 4515 or use parameterised search APIs.", FileName, CodeIssue.HIGH, CodeLine)
            End If
        End If

        '== XPath ==
        If Regex.IsMatch(CodeLine, "\.\s*(SelectSingleNode|SelectNodes|XPathSelectElement|XPathSelectElements|XPathEvaluate|Compile)\s*\(") And _
           (CodeLine.Contains("+") Or Regex.IsMatch(CodeLine, "(String\s*\.\s*Format|\$"")")) Then
            frmMain.ListCodeIssue("Potential XPath Injection", "An XPath expression appears to be constructed by concatenation. Injected quotes and boolean operators (for example: ' or '1'='1) allow an attacker to bypass authentication checks or to extract the entire XML document. Use XPath variables via XsltContext, or validate input against a strict whitelist.", FileName, CodeIssue.HIGH, CodeLine)
        End If

    End Sub

    Private Sub CheckNoSqlInjection(CodeLine As String, FileName As String)
        ' Identify NoSQL queries constructed from raw strings or user data
        '=================================================================

        If Regex.IsMatch(CodeLine, "\b(BsonDocument\s*\.\s*Parse|new\s+JsonFilterDefinition|new\s+BsonJavaScript|\$where|MapReduce|EvalAsync)\b") Then
            frmMain.ListCodeIssue("Potential NoSQL Injection", "A NoSQL query or server-side JavaScript fragment is built from a string. Where any part originates from the request an attacker can inject operators such as $ne, $gt or $regex to bypass authentication, or supply JavaScript to $where for server-side execution. Use the typed filter builders and never pass request data into Parse or JavaScript contexts.", FileName, CodeIssue.HIGH, CodeLine)
        End If

    End Sub

    Private Sub CheckJwtValidation(CodeLine As String, FileName As String)
        ' Identify weakened JSON Web Token validation parameters
        '=======================================================

        If Regex.IsMatch(CodeLine, "\b(ValidateIssuer|ValidateAudience|ValidateLifetime|ValidateIssuerSigningKey|ValidateActor|ValidateTokenReplay)\s*=\s*false") Then
            frmMain.ListCodeIssue("Weakened JWT Validation", "One or more standard JWT validation checks have been disabled. Disabling issuer or audience validation permits tokens minted for a different application or tenant to be replayed here; disabling lifetime validation makes stolen tokens valid indefinitely; disabling signing-key validation removes all cryptographic assurance of authenticity.", FileName, CodeIssue.HIGH, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "\b(RequireSignedTokens|RequireExpirationTime|RequireAudience)\s*=\s*false") Then
            frmMain.ListCodeIssue("JWT Signature or Expiry Requirement Removed", "The token handler has been configured to accept tokens without a signature or without an expiry claim. Unsigned ('alg':'none') tokens can be forged entirely by the client, giving arbitrary identity and role claims.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "\bSignatureValidator\s*=") Then
            frmMain.ListCodeIssue("Custom JWT Signature Validator", "A custom SignatureValidator replaces the built-in signature check. Manually confirm that the delegate actually verifies the signature - a delegate which simply returns a parsed JwtSecurityToken performs no validation at all and accepts forged tokens.", FileName, CodeIssue.HIGH, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "new\s+SymmetricSecurityKey\s*\(\s*(Encoding\s*\.\s*\w+\s*\.\s*GetBytes\s*\(\s*""|Convert\s*\.\s*FromBase64String\s*\(\s*"")") Then
            frmMain.ListCodeIssue("Hard-Coded JWT Signing Key", "The HMAC signing key for JWTs is embedded in source. Recovery of this key from the binary or repository allows an attacker to forge tokens for any user or role. Store the key in a secrets manager and ensure it holds at least 256 bits of entropy.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "\.\s*(ReadJwtToken|ReadToken)\s*\(") And Not CodeLine.Contains("ValidateToken") Then
            frmMain.ListCodeIssue("JWT Read Without Validation", "ReadJwtToken/ReadToken parses a token but performs no signature, issuer, audience or lifetime validation. Any claim read from the resulting object is entirely attacker-controlled. Use ValidateToken with a fully populated TokenValidationParameters before trusting any claim.", FileName, CodeIssue.HIGH, CodeLine)
        End If

    End Sub

    Private Sub CheckCorsPolicy(CodeLine As String, FileName As String)
        ' Identify permissive cross-origin resource sharing configuration
        '================================================================

        If Regex.IsMatch(CodeLine, "\bAllowAnyOrigin\s*\(\s*\)") Or Regex.IsMatch(CodeLine, "WithOrigins\s*\(\s*""\s*\*\s*""") Or _
           Regex.IsMatch(CodeLine, "\[\s*EnableCors\s*\(\s*(origins\s*:\s*)?""\s*\*\s*""") Or _
           Regex.IsMatch(CodeLine, "Access-Control-Allow-Origin""\s*,\s*""\s*\*") Then
            frmMain.ListCodeIssue("Overly Permissive CORS Policy", "Any origin is permitted to read responses from this endpoint. Where the endpoint returns non-public data this exposes it to every site the victim visits. Restrict the policy to an explicit list of trusted origins.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "\bAllowCredentials\s*\(\s*\)") And Regex.IsMatch(CodeLine, "\b(AllowAnyOrigin|SetIsOriginAllowed)\b") Then
            frmMain.ListCodeIssue("CORS Wildcard Origin Combined With Credentials", "The policy reflects arbitrary origins while also allowing credentials. Any website can then issue authenticated cross-origin requests with the victim's cookies and read the responses, which is a full account takeover primitive. Never combine credential support with a reflected or wildcard origin.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "SetIsOriginAllowed\s*\(\s*(_|\w+)\s*=>\s*true") Then
            frmMain.ListCodeIssue("CORS Origin Check Always Returns True", "The origin predicate accepts every origin, which is equivalent to a wildcard but additionally reflects the requesting origin - enabling credentialed cross-origin reads.", FileName, CodeIssue.HIGH, CodeLine)
        End If

    End Sub

    Private Sub CheckCookieAndSessionSecurity(CodeLine As String, FileName As String)
        ' Identify insecure cookie and session configuration
        '===================================================

        If Regex.IsMatch(CodeLine, "\b(HttpOnly|IsHttpOnly)\s*=\s*false") Then
            frmMain.ListCodeIssue("Cookie Accessible To Client-Side Script", "HttpOnly has been explicitly disabled, so the cookie can be read by JavaScript. Any cross-site scripting flaw in the application then becomes a session-hijacking flaw.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\.\s*Secure\s*=\s*false") Or Regex.IsMatch(CodeLine, "requireSSL\s*=\s*""false""") Or Regex.IsMatch(CodeLine, "CookieSecurePolicy\s*\.\s*None") Then
            frmMain.ListCodeIssue("Cookie Transmitted Over Cleartext", "The Secure attribute is disabled, so the cookie will be sent over plain HTTP. A network attacker who can trigger a single cleartext request to the domain captures the session token.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "SameSite(Mode)?\s*(=|\.)\s*None") Then
            frmMain.ListCodeIssue("Cookie SameSite Attribute Set To None", "SameSite=None causes the cookie to be attached to cross-site requests, re-enabling classic cross-site request forgery. Use Lax or Strict unless a genuine cross-site flow requires otherwise, and always pair None with Secure.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "cookieless\s*=\s*""(UseUri|AutoDetect|true)""") Then
            frmMain.ListCodeIssue("Cookieless Sessions Enabled", "The session identifier is carried in the URL. URLs are logged by proxies and servers, appear in Referer headers and are shared by users, so the session token leaks readily.", FileName, CodeIssue.HIGH, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\bregenerateExpiredSessionId\s*=\s*""false""") Then
            frmMain.ListCodeIssue("Session Identifier Not Regenerated", "Expired session identifiers are reused rather than regenerated, which facilitates session fixation attacks.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

    End Sub

    Private Sub CheckCsrfProtection(CodeLine As String, FileName As String)
        ' Identify disabled cross-site request forgery defences
        '======================================================

        If Regex.IsMatch(CodeLine, "\bIgnoreAntiforgeryToken\b") Or Regex.IsMatch(CodeLine, "ValidateAntiForgeryToken\s*=\s*false") Then
            frmMain.ListCodeIssue("Anti-CSRF Token Validation Disabled", "Anti-forgery validation has been suppressed for this endpoint. A state-changing request can then be triggered from any origin using the victim's ambient credentials.", FileName, CodeIssue.HIGH, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "AntiForgeryConfig\s*\.\s*SuppressXFrameOptionsHeader\s*=\s*true") Then
            frmMain.ListCodeIssue("X-Frame-Options Header Suppressed", "Suppressing X-Frame-Options allows the application to be framed by third-party sites, enabling clickjacking against authenticated users. Set a Content-Security-Policy frame-ancestors directive instead of removing the protection entirely.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "SuppressXFrameOptionsHeader|X-Frame-Options""\s*\)\s*;") Then
            frmMain.ListCodeIssue("Clickjacking Protection Removed", "Framing protection appears to be removed. Confirm that a frame-ancestors policy is applied elsewhere.", FileName, CodeIssue.LOW, CodeLine)
        End If

    End Sub

    Private Sub CheckMassAssignment(CodeLine As String, FileName As String)
        ' Identify model binding which may permit over-posting
        '=====================================================

        If Regex.IsMatch(CodeLine, "\b(TryUpdateModel|UpdateModel)\s*(\(|<)") Then
            frmMain.ListCodeIssue("Potential Over-Posting / Mass Assignment", "The model is bound directly from the request without an explicit property allow-list. An attacker can submit additional form fields to set properties that were never rendered - typically IsAdmin, Role, Price or UserId - and escalate privilege or tamper with data. Bind to a purpose-built view model or supply the includeProperties parameter.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\[\s*Bind\s*\(\s*Exclude") Then
            frmMain.ListCodeIssue("Deny-List Based Model Binding", "Bind(Exclude=...) uses a deny-list, so any property added to the model in future is bound by default. Use Bind(Include=...) or a dedicated view model so the safe set is explicit.", FileName, CodeIssue.LOW, CodeLine)
        End If

    End Sub

    Private Sub CheckDynamicCodeExecution(CodeLine As String, FileName As String)
        ' Identify runtime code loading, reflection and compilation
        '==========================================================

        If Regex.IsMatch(CodeLine, "\bAssembly\s*\.\s*(Load|LoadFrom|LoadFile|LoadWithPartialName|UnsafeLoadFrom|ReflectionOnlyLoad)\s*\(") Then
            frmMain.ListCodeIssue("Dynamic Assembly Loading", "An assembly is loaded at runtime. Where the path or byte array is influenced by user input or by a writable location this yields arbitrary code execution in the process. Load only from trusted, non-writable paths and verify the strong name or Authenticode signature.", FileName, CodeIssue.HIGH, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\b(CSharpCodeProvider|VBCodeProvider|CompileAssemblyFromSource|CompileAssemblyFromFile|CSharpScript\s*\.\s*(Eval|Run|RunAsync)|ScriptEngine)\b") Then
            frmMain.ListCodeIssue("Runtime Code Compilation or Scripting", "The application compiles or evaluates source code at runtime. If any part of the compiled text derives from user input this is a direct remote code execution primitive.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\b(Activator\s*\.\s*CreateInstance|Type\s*\.\s*GetType|InvokeMember|MethodInfo\s*\.\s*Invoke)\s*\(") And IsUserInputCSharp(CodeLine) Then
            frmMain.ListCodeIssue("Reflection Driven By User Input", "A type name or member name used for reflection appears to originate from user input, allowing an attacker to instantiate arbitrary types or invoke arbitrary methods present in the loaded assemblies. Map the input to a fixed set of permitted types.", FileName, CodeIssue.HIGH, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\bDataTable\s*\.\s*Compute\s*\(") Or Regex.IsMatch(CodeLine, "\.\s*(Select|RowFilter)\s*=") And CodeLine.Contains("+") Then
            frmMain.ListCodeIssue("Potential Expression Injection In DataTable Filter", "A DataTable expression or RowFilter is built by concatenation. The expression language supports function calls and sub-queries, so unvalidated input can alter query semantics and disclose additional rows.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

    End Sub

    Private Sub CheckHardcodedSecrets(CodeLine As String, FileName As String)
        ' Identify credentials and API keys embedded in source
        '=====================================================

        '== Well-known key formats ==
        If Regex.IsMatch(CodeLine, "AKIA[0-9A-Z]{16}") Then
            frmMain.ListCodeIssue("Hard-Coded AWS Access Key", "A string matching the AWS access key ID format is present in source. Treat the key as compromised, revoke it immediately and move to instance roles or a secrets manager.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "(gh[pousr]_[A-Za-z0-9]{36}|xox[baprs]-[A-Za-z0-9\-]{10,}|sk_live_[0-9a-zA-Z]{24,}|AIza[0-9A-Za-z\-_]{35})") Then
            frmMain.ListCodeIssue("Hard-Coded Third-Party API Token", "A string matching the format of a GitHub, Slack, Stripe or Google API token is embedded in source. Anyone with read access to the repository or the compiled binary can use it.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "-----BEGIN\s+(RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE KEY") Then
            frmMain.ListCodeIssue("Private Key Embedded In Source", "A PEM-encoded private key is stored in source. The corresponding certificate or signing identity must be considered compromised.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If

        '== Connection strings and credential assignments ==
        If Regex.IsMatch(CodeLine, "(?i)(password|pwd)\s*=\s*[^""'&;\s\)\}]{4,}\s*;") And Regex.IsMatch(CodeLine, "(?i)(data\s+source|server|initial\s+catalog|uid|user\s+id|mongodb://|amqp://)") Then
            frmMain.ListCodeIssue("Hard-Coded Database Credentials In Connection String", "A connection string containing an inline password is present in source. Use integrated authentication, a managed identity, or read the connection string from a protected configuration section.", FileName, CodeIssue.HIGH, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "(?i)\b(string|var|const|readonly)\b[^=]*\b\w*(password|passwd|pwd|secret|apikey|api_key|token|privatekey|clientsecret)\w*\s*=\s*""[^""]{4,}""") Then
            frmMain.ListCodeIssue("Hard-Coded Secret Assigned To Variable", "A variable whose name indicates a credential is initialised with a literal string. Secrets in source survive in version control history indefinitely and are recoverable from the compiled assembly with any decompiler.", FileName, CodeIssue.HIGH, CodeLine)
        End If

        '== Basic authentication headers ==
        If Regex.IsMatch(CodeLine, """\s*Basic\s+[A-Za-z0-9\+/=]{8,}\s*""") Then
            frmMain.ListCodeIssue("Hard-Coded HTTP Basic Authentication Header", "A pre-computed Basic authentication header is embedded in source. Base64 is an encoding, not encryption - the credentials are recovered trivially.", FileName, CodeIssue.HIGH, CodeLine)
        End If

    End Sub

    Private Sub CheckRegexDoS(CodeLine As String, FileName As String)
        ' Identify regular expressions vulnerable to catastrophic backtracking
        '=====================================================================

        If Not Regex.IsMatch(CodeLine, "\b(Regex|RegularExpressionAttribute|ValidationExpression)\b") Then Exit Sub

        '== Nested quantifiers are the classic ReDoS signature ==
        If Regex.IsMatch(CodeLine, "\(\s*[^\)]*[\+\*]\s*\)\s*[\+\*]") Or Regex.IsMatch(CodeLine, "\(\s*[^\)]*\|\s*[^\)]*\)\s*[\+\*]") Then
            frmMain.ListCodeIssue("Potential Regular Expression Denial of Service (ReDoS)", "The expression contains a nested or alternating quantifier such as (a+)+ or (a|aa)+. On a non-matching input the .NET backtracking engine explores an exponential number of paths, so a short crafted string can consume a CPU core indefinitely. Rewrite the expression to remove ambiguity, or construct the Regex with an explicit matchTimeout.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

        '== Missing timeout on any Regex construction ==
        If Regex.IsMatch(CodeLine, "\bnew\s+Regex\s*\(") And Not CodeLine.Contains("TimeSpan") Then
            frmMain.ListCodeIssue("Regular Expression Constructed Without Timeout", "No matchTimeout is supplied. Without a timeout a pathological pattern or input will block the thread indefinitely. Pass a TimeSpan, or set AppDomain REGEX_DEFAULT_MATCH_TIMEOUT globally.", FileName, CodeIssue.LOW, CodeLine)
        End If

        '== Pattern built from user input ==
        If Regex.IsMatch(CodeLine, "\bnew\s+Regex\s*\(") And IsUserInputCSharp(CodeLine) Then
            frmMain.ListCodeIssue("Regular Expression Pattern Derived From User Input", "The pattern itself is user-controlled, allowing an attacker to supply an expression engineered for catastrophic backtracking and to deny service to the application.", FileName, CodeIssue.HIGH, CodeLine)
        End If

    End Sub

    Private Sub CheckInformationLeakage(CodeLine As String, FileName As String)
        ' Identify exception detail and diagnostic data returned to the client
        '=====================================================================

        If Regex.IsMatch(CodeLine, "\b(ex|e|exc|exception|error)\s*\.\s*(ToString\s*\(|StackTrace|InnerException|Message)\b") And _
           Regex.IsMatch(CodeLine, "\b(Response\s*\.\s*(Write|Output)|Content\s*\(|Ok\s*\(|BadRequest\s*\(|Json\s*\(|ViewBag|ViewData|innerHTML|Problem\s*\()") Then
            frmMain.ListCodeIssue("Exception Detail Returned To Client", "Exception text or a stack trace is written into the response. This discloses framework versions, file paths, SQL fragments and internal class names, which materially assists an attacker in mapping the application. Log the detail server-side and return a correlation identifier to the caller.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "\bUseDeveloperExceptionPage\s*\(") And Not Regex.IsMatch(CodeLine, "(IsDevelopment|IsEnvironment)") Then
            frmMain.ListCodeIssue("Developer Exception Page Enabled Unconditionally", "The developer exception page is registered without an environment guard. In production it exposes full stack traces, source snippets, request headers and cookies to any client that can trigger an unhandled exception.", FileName, CodeIssue.HIGH, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "\bcatch\s*\(\s*\w+(\s+\w+)?\s*\)\s*\{\s*\}") Or Regex.IsMatch(CodeLine, "\bcatch\s*\{\s*\}") Then
            frmMain.ListCodeIssue("Empty Exception Handler", "An exception is caught and silently discarded. Failures in security-relevant operations - signature verification, authorisation checks, cryptographic calls - then proceed as if they had succeeded, and no evidence is recorded for incident response.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

    End Sub

    Private Sub CheckAuthorisationWeakness(CodeLine As String, FileName As String)
        ' Identify weakened authentication and authorisation configuration
        '=================================================================

        If Regex.IsMatch(CodeLine, "\[\s*AllowAnonymous\s*\]") Then
            frmMain.ListCodeIssue("Endpoint Explicitly Marked AllowAnonymous", "Authorisation is bypassed for this action. Confirm that the endpoint genuinely serves public data and does not accept identifiers that would allow a caller to reach another user's records.", FileName, CodeIssue.LOW, CodeLine)
        End If
        '== Weak password policy in ASP.NET Core Identity ==
        If Regex.IsMatch(CodeLine, "Password\s*\.\s*Require(Digit|LowerCase|UpperCase|NonAlphanumeric)\s*=\s*false") Then
            frmMain.ListCodeIssue("Relaxed Password Complexity Requirement", "A password complexity rule has been switched off. Complexity rules alone are a weak control, but where they are removed without introducing a breached-password check and a minimum length of at least 12 characters the resulting policy is inadequate.", FileName, CodeIssue.LOW, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "Password\s*\.\s*RequiredLength\s*=\s*([0-9]|1[01])\b") Then
            frmMain.ListCodeIssue("Insufficient Minimum Password Length", "The minimum password length is set below 12 characters. NIST SP 800-63B recommends a minimum of 8 with a breached-password check; 12 or more is advisable where no such check exists.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "Lockout\s*\.\s*(AllowedForNewUsers\s*=\s*false|MaxFailedAccessAttempts\s*=\s*([2-9][0-9]|[1-9][0-9]{2,}))") Then
            frmMain.ListCodeIssue("Weak Or Absent Account Lockout", "Account lockout is disabled or the failure threshold is set very high, permitting sustained online password guessing against the authentication endpoint.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

        '== Impersonation and elevated execution ==
        If Regex.IsMatch(CodeLine, "\b(WindowsIdentity\s*\.\s*Impersonate|LogonUser|DuplicateToken|ImpersonateLoggedOnUser)\b") Then
            frmMain.ListCodeIssue("Thread Impersonation In Use", "The code impersonates another security principal. Confirm that the impersonation context is always reverted in a finally block, otherwise subsequent work on the pooled thread executes with the elevated identity.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

    End Sub

    Private Sub CheckXmlProcessing(CodeLine As String, FileName As String)
        ' Identify unsafe XML, XSLT and schema processing beyond the existing XXE checks
        '==============================================================================

        If Regex.IsMatch(CodeLine, "\bXslCompiledTransform\b") And Regex.IsMatch(CodeLine, "(XsltSettings\s*\.\s*TrustedXslt|EnableScript\s*=\s*true|EnableDocumentFunction\s*=\s*true)") Then
            frmMain.ListCodeIssue("XSLT Scripting Enabled", "The transform is configured to permit embedded script blocks or the document() function. A stylesheet from an untrusted source then executes arbitrary .NET code in the host process or reads arbitrary local files.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "ProhibitDtd\s*=\s*false") Or Regex.IsMatch(CodeLine, "DtdProcessing\s*\.\s*(Parse|Ignore)\b") Then
            frmMain.ListCodeIssue("DTD Processing Permitted", "DTD processing is enabled on an XML reader. This permits internal entity expansion (billion laughs) leading to memory exhaustion, and where an external resolver is present, external entity resolution and server-side request forgery. Set DtdProcessing to Prohibit and XmlResolver to Nothing.", FileName, CodeIssue.HIGH, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "XmlSchemaValidationFlags\s*\.\s*ProcessInlineSchema") Then
            frmMain.ListCodeIssue("Inline Schema Processing Enabled", "The validator accepts schemas embedded in the instance document, allowing an attacker to supply the very schema used to validate their input and to trigger schema-based resource exhaustion.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

    End Sub

    Private Sub CheckConcurrencyAndResource(CodeLine As String, FileName As String)
        ' Identify patterns which lead to resource exhaustion or deadlock
        '================================================================

        If Regex.IsMatch(CodeLine, "\.\s*(Result|GetAwaiter\s*\(\s*\)\s*\.\s*GetResult)\b") Or Regex.IsMatch(CodeLine, "\.\s*Wait\s*\(\s*\)") Then
            frmMain.ListCodeIssue("Blocking Wait On Asynchronous Operation", "Synchronously blocking on a Task can exhaust the thread pool under load and deadlocks where a synchronisation context is present. Sustained load against such an endpoint is an inexpensive denial-of-service vector. Await the task instead.", FileName, CodeIssue.LOW, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "\bnew\s+(HttpClient|SqlConnection|FileStream|StreamReader|StreamWriter|MemoryStream)\s*\(") And Not Regex.IsMatch(CodeLine, "\b(using|Dispose|await\s+using)\b") Then
            frmMain.ListCodeIssue("Disposable Resource Created Outside A Using Block", "An IDisposable is instantiated without an obvious using declaration. Where an exception occurs before disposal the handle, socket or connection leaks; repeated failures exhaust the connection pool or file handles. Note that HttpClient specifically should be pooled via IHttpClientFactory rather than disposed per request.", FileName, CodeIssue.LOW, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "\b(MaxRequestLength|MultipartBodyLengthLimit|MaxAllowedContentLength|ValueLengthLimit)\s*=\s*(int\s*\.\s*MaxValue|\d{9,})") Then
            frmMain.ListCodeIssue("Request Size Limit Effectively Removed", "An upload or request body limit has been raised to an extremely large value, allowing a single client to exhaust memory or disk on the server.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

    End Sub

    Private Sub CheckDeserializationExtended(CodeLine As String, FileName As String)
        ' Additional deserialization gadget surfaces not covered by the existing check
        '=============================================================================

        If Regex.IsMatch(CodeLine, "TypeNameHandling\s*\.\s*(All|Objects|Arrays|Auto)\b") Then
            frmMain.ListCodeIssue("Json.NET TypeNameHandling Enabled", "TypeNameHandling instructs Json.NET to instantiate the CLR type named in the $type property of the incoming document. An attacker who controls the JSON can therefore instantiate any type available to the process - ObjectDataProvider and similar gadgets convert this directly into command execution. Set TypeNameHandling to None, or supply a strict ISerializationBinder.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "\b(JavaScriptSerializer)\b") And Regex.IsMatch(CodeLine, "\b(SimpleTypeResolver|Deserialize)\b") Then
            frmMain.ListCodeIssue("JavaScriptSerializer With Type Resolver", "A JavaScriptSerializer constructed with a SimpleTypeResolver resolves arbitrary type names from the input document and is a known remote code execution sink.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "\b(LosFormatter|ObjectStateFormatter|NetDataContractSerializer|SoapFormatter|BinaryFormatter)\b") Then
            frmMain.ListCodeIssue("Use of Unsafe .NET Formatter", "BinaryFormatter, SoapFormatter, NetDataContractSerializer, LosFormatter and ObjectStateFormatter all reconstruct arbitrary object graphs including type information and cannot be used safely on untrusted input. BinaryFormatter is removed in .NET 9. Migrate to System.Text.Json or a contract-based serialiser.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "enableViewStateMac\s*=\s*""false""") Or Regex.IsMatch(CodeLine, "EnableViewStateMac\s*=\s*false") Then
            frmMain.ListCodeIssue("ViewState MAC Validation Disabled", "Without a message authentication code the ViewState blob can be replaced by the client. Since ViewState is deserialised with ObjectStateFormatter this yields remote code execution on the web server.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "(validationKey|decryptionKey)\s*=\s*""[0-9A-Fa-f]{16,}""") Then
            frmMain.ListCodeIssue("Hard-Coded Machine Key", "A static machineKey is present in configuration. Where this key is shared, published or recovered, an attacker can forge ViewState, forms authentication tickets and anti-forgery tokens for the application.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If

    End Sub

    Private Sub CheckHeaderInjection(CodeLine As String, FileName As String)
        ' Identify response splitting and host header trust issues
        '=========================================================

        If Regex.IsMatch(CodeLine, "Response\s*\.\s*(AddHeader|AppendHeader|Headers\s*\.\s*(Add|Append)|Redirect|Cookies\s*\.\s*Add)") And IsUserInputCSharp(CodeLine) Then
            frmMain.ListCodeIssue("Potential HTTP Response Header Injection", "A response header value appears to be built from user input. Where carriage return and line feed characters are not stripped an attacker can inject additional headers or an entire second response body, enabling cache poisoning and reflected cross-site scripting.", FileName, CodeIssue.HIGH, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "Request\s*\.\s*(Headers\s*\[\s*""Host""|Url\s*\.\s*Host|Host\b)") Then
            frmMain.ListCodeIssue("Reliance On The Host Header", "The Host header is attacker-controlled unless the web server enforces a host allow-list. Using it to construct absolute URLs leads to password-reset poisoning and cache poisoning. Use a configured canonical hostname instead.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

    End Sub
End Module
