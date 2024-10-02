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
        CheckProcessInjection(CodeLine, FileName)       ' Check for potential process injection or hollowing techniques
        CheckMisconfiguredRoutes(CodeLine, FileName)    ' Check for potential misconfigured routes or connection strings

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

    Public Sub CheckProcessInjection(CodeLine As String, FileName As String)
        ' Check for potential process injection or hollowing techniques
        '=========================================================================

        Dim blnIsFound As Boolean
        blnIsFound = False

        ' List of keywords related to process injection/hollowing
        If Regex.IsMatch(CodeLine.ToLower(), "createremotethread|writeprocessmemory|virtualallocex|ntunmapviewofsection|setthreadcontext|resumethread|rtlcreateprocessreflection|ntgetnextprocess") Then
            ' Check for potential code injection patterns
            For Each strVar In ctCodeTracker.InputVars
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
                frmMain.ListCodeIssue("Process Injection Technique Detected",
                "The code contains potential process injection/hollowing techniques. Manual review required to check for misuse.",
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

End Module
