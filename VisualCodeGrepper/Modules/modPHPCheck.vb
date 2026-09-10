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

Module modPHPCheck

    ' Specific checks for PHP code
    '=============================

    Public Sub CheckPHPCode(CodeLine As String, FileName As String)
        ' Carry out any specific checks for the language in question
        '===========================================================

        CheckSQLInjection(CodeLine, FileName)               ' Check for SQLi
        CheckXSS(CodeLine, FileName)                        ' Check for XSS
        CheckLogDisplay(CodeLine, FileName)                 ' Is data sanitised before being written to logs?
        CheckRandomisation(CodeLine, FileName)              ' Locate any use of randomisation functions that are not cryptographically secure
        CheckFileValidation(CodeLine, FileName)             ' Find any unsafe file validation (checks against data from the HTTP request *instead of* the actual file
        CheckFileInclusion(CodeLine, FileName)              ' Locate any include files with unsafe extensions
        CheckExecutable(CodeLine, FileName)                 ' Check for unvalidated variables being executed via cmd line/system calls
        CheckBackTick(CodeLine, FileName)                   ' Check for user-supplied variables being executed on the cmdline due to backtick usage
        CheckRegisterGlobals(CodeLine, FileName)            ' Check for usage or simulation of register_globals
        CheckParseStr(CodeLine, FileName)                   ' Check for any unsafe usage of parse_str
        CheckInsecureDeserialization(CodeLine, FileName)    ' Check for insecure deserialization vulnerabilities
        CheckXXE(CodeLine, FileName)                        ' Check for potential XXE vulnerabilities 
        CheckStreamFilters(CodeLine, FileName)              ' Check for unsafe usage of stream filters like zlib.inflate and dechunk

        '== Extended ruleset ==
        CheckPHPWeakCrypto(CodeLine, FileName)              ' Broken hashes, mcrypt/ECB, timing-unsafe comparison, weak PRNG
        CheckPHPTypeJuggling(CodeLine, FileName)            ' Magic hashes, in_array/strcmp and switch coercion issues
        CheckPHPSSRF(CodeLine, FileName)                    ' User-controlled outbound requests and disabled TLS verification
        CheckPHPFileHandling(CodeLine, FileName)            ' Path traversal, upload metadata trust, Zip Slip and phar://
        CheckPHPHeaderInjection(CodeLine, FileName)         ' Response splitting, open redirect and mail header injection
        CheckPHPSessionSecurity(CodeLine, FileName)         ' Session fixation and insecure session/cookie configuration
        CheckPHPCodeInjection(CodeLine, FileName)           ' assert/create_function, dynamic callbacks, extract, /e modifier
        CheckPHPCommandArguments(CodeLine, FileName)        ' Incomplete shell escaping and argument injection
        CheckPHPFrameworkIssues(CodeLine, FileName)         ' Raw query builders, unescaped templates, debug mode, mass assignment
        CheckPHPHardcodedSecrets(CodeLine, FileName)        ' API keys, private keys and credentials embedded in source
        CheckPHPCorsAndHeaders(CodeLine, FileName)          ' Permissive or reflected CORS configuration

        '== Check for passwords being handled in a case-insensitive manner ==
        If Regex.IsMatch(CodeLine, "(strtolower|strtoupper)\s*\(\s*\S*(Password|password|pwd|PWD|Pwd|Passwd|passwd)") Then
            frmMain.ListCodeIssue("Unsafe Password Management", "The application appears to handle passwords in a case-insensitive manner. This can greatly increase the likelihood of successful brute-force and/or dictionary attacks.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

    End Sub

    Private Sub CheckStreamFilters(CodeLine As String, FileName As String)
        ' Check for unsafe usage of stream filters like zlib.inflate and dechunk
        '=========================================================

        ' Check for the presence of zlib.inflate
        If Regex.IsMatch(CodeLine, "\bzlib\.inflate\b", RegexOptions.IgnoreCase) Then
            frmMain.ListCodeIssue("Unsafe Usage of zlib.inflate", "The application uses zlib.inflate, which may lead to heap manipulation and buffer overflows if not handled properly.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If

        ' Check for the presence of dechunk
        If Regex.IsMatch(CodeLine, "\bdechunk\b", RegexOptions.IgnoreCase) Then
            frmMain.ListCodeIssue("Unsafe Usage of dechunk", "The application uses dechunk, which may lead to potential vulnerabilities if not validated or sanitized appropriately.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If

        ' Additional checks can be added here for any other stream filters if necessary.
    End Sub


    Private Sub CheckSQLInjection(CodeLine As String, FileName As String)
        ' Check for any SQL injection problems 
        '=====================================
        Dim strVarName As String = ""   ' Holds the variable name for the dynamic SQL statement

        '== Only check unvalidated code ==
        If ctCodeTracker.HasValidator = True Then Exit Sub

        '== Is unsanitised dynamic SQL statement prepared beforehand? ==
        If CodeLine.Contains("=") AndAlso
           (CodeLine.ToLower.Contains("sql") OrElse
            CodeLine.ToLower.Contains("query") OrElse
            CodeLine.ToLower.Contains("stmt") OrElse
            CodeLine.ToLower.Contains("query")) AndAlso
           (CodeLine.Contains("""") AndAlso (CodeLine.Contains("$") OrElse CodeLine.Contains("+"))) Then
            '== Extract variable name from assignment statement ==
            strVarName = GetVarName(CodeLine)
            ctCodeTracker.HasVulnSQLString = True
            If Regex.IsMatch(strVarName, "^\$[a-zA-Z0-9_]*$") AndAlso Not ctCodeTracker.SQLStatements.Contains(strVarName) Then
                ctCodeTracker.SQLStatements.Add(strVarName)
            End If
        End If

        ' Check for sanitization methods
        If Regex.IsMatch(CodeLine, "validate|encode|sanitize|sanitise", RegexOptions.IgnoreCase) Then
            '== Remove any variables which have been sanitised from the list of vulnerable variables ==  
            RemoveSanitisedVars(CodeLine)
        ElseIf Regex.IsMatch(CodeLine, "(mysql_query|mssql_query|pg_query)\s*\(", RegexOptions.IgnoreCase) AndAlso Not Regex.IsMatch(CodeLine, "mysql_real_escape_string", RegexOptions.IgnoreCase) Then

            If ctCodeTracker.HasVulnSQLString = True Then
                '== Check for use of pre-prepared statements ==
                For Each strVar In ctCodeTracker.SQLStatements
                    If Regex.IsMatch(CodeLine, strVar) Then
                        frmMain.ListCodeIssue("Potential SQL Injection", "The application appears to allow SQL injection via a pre-prepared dynamic SQL statement.", FileName, CodeIssue.CRITICAL, CodeLine)
                        Exit For
                    End If
                Next
            ElseIf CodeLine.Contains("$") Then
                '== Dynamic SQL built into connection/update ==
                frmMain.ListCodeIssue("Potential SQL Injection", "The application appears to allow SQL injection via dynamic SQL statements.", FileName, CodeIssue.CRITICAL, CodeLine)
            End If
        End If

        ' New rules for additional SQL injection patterns
        If Regex.IsMatch(CodeLine, "\->(query|exec)\(\s*""[^""]*""\s*\)", RegexOptions.IgnoreCase) Then
            frmMain.ListCodeIssue("Potential SQL Injection", "The application appears to allow SQL injection via dynamic method calls.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "query\((.*?)\)", RegexOptions.IgnoreCase) Then
            frmMain.ListCodeIssue("Potential SQL Injection", "The application appears to allow SQL injection via direct query execution.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "query\(.*\)\s*=", RegexOptions.IgnoreCase) Then
            frmMain.ListCodeIssue("Potential SQL Injection", "The application appears to allow SQL injection via assignment to a query.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "sql\(.*\)\s*=", RegexOptions.IgnoreCase) Then
            frmMain.ListCodeIssue("Potential SQL Injection", "The application appears to allow SQL injection via assignment to SQL statements.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If
    End Sub


    Private Sub CheckXSS(CodeLine As String, FileName As String)
        ' Check for any XSS problems 
        '===========================
        Dim strVarName As String = ""
        Dim blnIsFound As Boolean = False
        '== Only check unvalidated code ==
        If ctCodeTracker.HasValidator = True Then Exit Sub


        If Regex.IsMatch(CodeLine, "validate|encode|sanitize|sanitise") Then
            '== Remove any variables which have been sanitised from the list of vulnerable variables ==  
            RemoveSanitisedVars(CodeLine)
        ElseIf Regex.IsMatch(CodeLine, "\$\w+\s*\=\s*\$_(Get|POST|COOKIE|REQUEST|SERVER)") Then
            '== Extract variable name from assignment statement ==
            strVarName = GetVarName(CodeLine)
            If Regex.IsMatch(strVarName, "^\\\$[a-zA-Z0-9_]*$") And Not ctCodeTracker.InputVars.Contains(strVarName) Then ctCodeTracker.InputVars.Add(strVarName)
        ElseIf Regex.IsMatch(CodeLine, "\b(print|echo|print_r)\b") And CodeLine.Contains("$") And Not Regex.IsMatch(CodeLine, "strip_tags") Then
            CheckUserVarXSS(CodeLine, FileName)
        ElseIf Regex.IsMatch(CodeLine, "\b(print|echo|print_r)\b\s*\$_(GET|POST|COOKIE|REQUEST|SERVER)") And Not Regex.IsMatch(CodeLine, "strip_tags") Then
            frmMain.ListCodeIssue("Potential XSS", "The application appears to reflect a user-supplied variable to the screen with no apparent validation or sanitisation.", FileName, CodeIssue.HIGH, CodeLine)
        End If

        '== Check for DOM-based XSS in .php pages ==
        If FileName.ToLower.EndsWith(".php") Or FileName.ToLower.EndsWith(".html") And Not Regex.IsMatch(CodeLine, "validate|encode|sanitize|sanitise|strip_tags") Then
            If Regex.IsMatch(CodeLine, "\s+var\s+\w+\s*=\s*""\s*\<\?\s*\=\s*\w+\s*\?\>""\;") Then
                '== Extract variable name from assignment statement ==
                strVarName = GetVarName(CodeLine)
                If Regex.IsMatch(strVarName, "^[a-zA-Z0-9_]*$") And Not ctCodeTracker.SQLStatements.Contains(strVarName) Then ctCodeTracker.InputVars.Add(strVarName)
            ElseIf ((CodeLine.Contains("document.write(") And CodeLine.Contains("+") And CodeLine.Contains("""")) Or Regex.IsMatch(CodeLine, ".innerHTML\s*\=\s*\w+;")) Then
                For Each strVar In ctCodeTracker.InputVars
                    If Regex.IsMatch(CodeLine, strVar) Then
                        frmMain.ListCodeIssue("Potential DOM-Based XSS", "The application appears to allow XSS via an unencoded/unsanitised input variable.", FileName, CodeIssue.HIGH, CodeLine)
                        Exit For
                    End If
                Next
            ElseIf Regex.IsMatch(CodeLine, "\)\s*\.innerHTML\s*=\s*(\'|\"")\s*\<\s*\?\s*echo\s*\$_(GET|POST|COOKIE|SERVER|REQUEST)\s*\[") Then
                frmMain.ListCodeIssue("Potential DOM-Based XSS", "The application appears to allow XSS via an unencoded/unsanitised input variable.", FileName, CodeIssue.HIGH, CodeLine)
            End If
        End If

    End Sub

    Private Sub CheckLogDisplay(CodeLine As String, FileName As String)
        ' Check output written to logs is sanitised first
        '================================================

        '== Only check unvalidated code ==
        If Regex.IsMatch(CodeLine, "validate|encode|sanitize|sanitise") And Not CodeLine.ToLower.Contains("password") Then
            RemoveSanitisedVars(CodeLine)
        ElseIf Regex.IsMatch(CodeLine, "AddLog|error_log") And CodeLine.ToLower.Contains("password") Then
            If (InStr(CodeLine.ToLower, "log") < InStr(CodeLine.ToLower, "password")) Then frmMain.ListCodeIssue("Application Appears to Log User Passwords", "The application appears to write user passwords to logfiles or the screen, creating a risk of credential theft.", FileName, CodeIssue.HIGH, CodeLine)
        ElseIf Regex.IsMatch(CodeLine, "AddLog|error_log") And Not CodeLine.ToLower.Contains("strip_tags") Then
            For Each strVar In ctCodeTracker.InputVars
                If Regex.IsMatch(CodeLine, strVar) Then
                    frmMain.ListCodeIssue("Unsanitized Data Written to Logs", "The application appears to write unsanitized data to its logfiles. If logs are viewed by a browser-based application this exposes risk of XSS attacks.", FileName, CodeIssue.MEDIUM, CodeLine)
                    Exit For
                End If
            Next
        End If

    End Sub

    Private Sub CheckRandomisation(CodeLine As String, FileName As String)
        ' Check for any random functions that are not cryptographically secure
        '=====================================================================

        '== Check for time or non-time-based seed ==
        If Regex.IsMatch(CodeLine, "\$\w+\s*\=\s*\bopenssl_random_pseudo_bytes\b\s*\(\s*\S+\s*\,\s*(0|false|False|FALSE)") Then
            frmMain.ListCodeIssue("Use of Deterministic Pseudo-Random Values", "The code appears to use the function with the 'secure' value deliberately set to 'false'. The resulting values, while appearing random to a casual observer, are predictable and may be enumerated by a skilled and determined attacker.", FileName, CodeIssue.MEDIUM, CodeLine)
        ElseIf Regex.IsMatch(CodeLine, "\$\w+\s*\=\s*\b(mt_rand|smt_rand)\b\s*\(\s*\)") Or Regex.IsMatch(CodeLine, "\b(mt_rand|smt_rand)\b\s*\(\w*(T|t)ime\w*\)") Then
            frmMain.ListCodeIssue("Use of Deterministic Pseudo-Random Values", "The code appears to use the mt_rand and/or smt_rand functions without a seed to generate pseudo-random values. The resulting values, while appearing random to a casual observer, are predictable and may be enumerated by a skilled and determined attacker.", FileName, CodeIssue.MEDIUM, CodeLine)
        ElseIf Regex.IsMatch(CodeLine, "\b(mt_rand|smt_rand)\b\s*\(\s*\S+\s*\)") Then
            frmMain.ListCodeIssue("Use of Deterministic Pseudo-Random Values", "The code appears to use the mt_rand function. The resulting values, while appearing random to a casual observer, are predictable and may be enumerated by a skilled and determined attacker, although this is partly mitigated by a seed that does not appear to be time-based.", FileName, CodeIssue.STANDARD, CodeLine)
        End If

    End Sub

    Private Sub CheckFileValidation(CodeLine As String, FileName As String)
        ' Check for any decisions based on characteristics of the $_FILES array
        '======================================================================

        '== Identify relevant 'if' statements ==
        If Regex.IsMatch(CodeLine, "\bif\b\s*\(\s*\$_FILES\s*\[\s*\$\w+\s*\]\s*\[\s*\'") Or Regex.IsMatch(CodeLine, "\bif\b\s*\(\s*\!?\s*isset\s*\(?\s*\$_FILES\s*\[\s*\$\w+\s*\]\s*\[\s*\'") Then
            frmMain.ListCodeIssue("Unsafe Processing of $_FILES Array", "The code appears to use data within the $_FILES array in order to make to decisions. this is obtained direct from the HTTP request and may be modified by the client to cause unexpected behaviour.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

    End Sub

    Private Sub CheckFileInclusion(CodeLine As String, FileName As String)
        ' Check for any user-defined variables being used to name include files
        '======================================================================
        Dim blnIsFound As Boolean = False

        '== Identify relevant 'include' statements ==
        If Regex.IsMatch(CodeLine, "\b(file_include|include_once|require_once)\b\s*\(\s*\$") Then
            '== Check for use of user-defined variables ==
            For Each strVar In ctCodeTracker.InputVars
                If Regex.IsMatch(CodeLine, "\b(file_include|include_once|require_once)\b\s*\(\s*" & strVar) Or Regex.IsMatch(CodeLine, "\b(file_include|include_once|require_once)\b\s*\(\s*\w+\s*\.\s*" & strVar) Then
                    frmMain.ListCodeIssue("File Inclusion Vulnerability", "The code appears to use a user-controlled variable as a parameter for an include statement which could lead to a file include vulnerability.", FileName, CodeIssue.HIGH, CodeLine)
                    blnIsFound = True
                    Exit For
                End If
            Next
            If blnIsFound = False Then
                frmMain.ListCodeIssue("Variable Used as FileName", "The application appears to use a variable name in order to define a filename used by the application. It is unclear whether this variable can be controlled by the user - carry out a manual inspection to confirm.", FileName, CodeIssue.LOW, CodeLine)
            End If
        ElseIf Regex.IsMatch(CodeLine, "\b(file_include|include_once|require_once)\b\s*\(\s*(\'|\"")\w+\.(inc|txt|dat)") Then
            '== Check for use of unsafe extensions ==
            frmMain.ListCodeIssue("File Inclusion Vulnerability", "The code appears to use an unsafe file extension for an include statement which could allow an attacker to download it directly and read the uncompiled code.", FileName, CodeIssue.HIGH, CodeLine)
        End If

        '== Check for file read/write vulnerabilities ==
        Dim fileReadWriteFunctions As String = "fwrite|file_get_contents|fopen|glob|popen|file_put_contents|fgets|fputs"

        If Regex.IsMatch(CodeLine, "\b(" & fileReadWriteFunctions & ")\b\s*\(\s*\$") Then
            '== Check for use of user-defined variables ==
            For Each strVar In ctCodeTracker.InputVars
                If Regex.IsMatch(CodeLine, "\b(" & fileReadWriteFunctions & ")\b\s*\(\s*" & strVar) Or Regex.IsMatch(CodeLine, "\b(" & fileReadWriteFunctions & ")\b\s*\(\s*\w+\s*\.\s*" & strVar) Then
                    frmMain.ListCodeIssue("File Access Vulnerability", "The code appears to use a user-controlled variable as a parameter when accessing the filesystem. This could lead to a system compromise.", FileName, CodeIssue.HIGH, CodeLine)
                    blnIsFound = True
                    Exit For
                End If
            Next
            If blnIsFound = False Then
                frmMain.ListCodeIssue("Variable Used as FileName", "The application appears to use a variable name in order to define a filename used by the application. It is unclear whether this variable can be controlled by the user - carry out a manual inspection to confirm.", FileName, CodeIssue.LOW, CodeLine)
            End If
        End If

    End Sub

    Private Sub CheckExecutable(CodeLine As String, FileName As String)
        ' Check for unvalidated variables being executed via cmd line/system calls
        '=========================================================================
        Dim blnIsFound As Boolean = False

        ' Skip if any validation functions are present
        If Regex.IsMatch(CodeLine, "validate|encode|sanitize|sanitise") Then Exit Sub

        ' Check for unsafe function calls with consideration for false positives
        If Regex.IsMatch(CodeLine, "\b(exec|shell_exec|proc_open|eval|system|popen|passthru|pcntl_exec|assert)\b") And Not Regex.IsMatch(CodeLine, "escapeshellcmd") Then
            For Each strVar In ctCodeTracker.InputVars
                If Regex.IsMatch(CodeLine, strVar) Then
                    frmMain.ListCodeIssue("User Controlled Variable Used on System Command Line", "The application appears to allow the use of an unvalidated user-controlled variable when executing a command.", FileName, CodeIssue.HIGH, CodeLine)
                    blnIsFound = True
                    Exit For
                End If
            Next
            If blnIsFound = False And CodeLine.Contains("$") Then
                frmMain.ListCodeIssue("Application Variable Used on System Command Line", "The application appears to allow the use of an unvalidated variable when executing a command. Carry out a manual check to determine whether the variable is user-controlled.", FileName, CodeIssue.MEDIUM, CodeLine)
            End If
        End If

        ' Additional checks for specific functions that could cause RCE vulnerabilities
        If Regex.IsMatch(CodeLine, "\b(SoapClient|Imagick)\b") Then
            frmMain.ListCodeIssue("Potential RCE Vulnerability", "The application may use SoapClient() or Imagick() without proper validation, which could lead to Remote Code Execution vulnerabilities.", FileName, CodeIssue.HIGH, CodeLine)
        End If
    End Sub

    Private Sub CheckBackTick(CodeLine As String, FileName As String)
        ' Check for user-supplied variables being executed on the cmdline due to backtick usage
        '======================================================================================
        Dim blnIsFound As Boolean = False


        If Regex.IsMatch(CodeLine, "`\s*\S*\s*\$_(GET|POST|COOKIE|REQUEST|SERVER)") Then
            frmMain.ListCodeIssue("User Controlled Variable Used on System Command Line", "The application appears to allow the use of a HTTP request variable within backticks, allowing commandline execution.", FileName, CodeIssue.HIGH, CodeLine)
        ElseIf Regex.IsMatch(CodeLine, "`\s*\S*\s*\$\w+") Then
            For Each strVar In ctCodeTracker.InputVars
                If Regex.IsMatch(CodeLine, strVar) Then
                    frmMain.ListCodeIssue("User Controlled Variable Used on System Command Line", "The application appears to allow the use of a user-controlled variable within backticks, allowing commandline execution.", FileName, CodeIssue.HIGH, CodeLine)
                    blnIsFound = True
                    Exit For
                End If
            Next
            If blnIsFound = False Then
                frmMain.ListCodeIssue("Application Variable Used on System Command Line", "The application appears to allow the use of a variable within backticks, allowing commandline execution. Carry out a manual check to determine whether the variable is user-controlled.", FileName, CodeIssue.MEDIUM, CodeLine)
            End If
        End If

    End Sub

    Private Sub CheckPHPEvaluation(CodeLine As String, FileName As String)
        ' Check for unvalidated variables being executed via cmd line/system calls
        '=========================================================================
        Dim blnIsFound As Boolean = False


        If Regex.IsMatch(CodeLine, "validate|encode|sanitize|sanitise") Then Exit Sub

        If Regex.IsMatch(CodeLine, "\b(preg_replace|create_function)\b") And Not Regex.IsMatch(CodeLine, "strip_tags") Then
            For Each strVar In ctCodeTracker.InputVars
                If Regex.IsMatch(CodeLine, strVar) Then
                    frmMain.ListCodeIssue("Function May Evaluate PHP Code Contained in User Controlled Variable", "The application appears to allow the use of an unvalidated user-controlled variable in conjunction with a function that will evaluate PHP code.", FileName, CodeIssue.HIGH, CodeLine)
                    blnIsFound = True
                    Exit For
                End If
            Next
            If blnIsFound = False And CodeLine.Contains("$") Then
                frmMain.ListCodeIssue("Function May Evaluate PHP Code", "The application appears to allow the use of an unvalidated variable in conjunction with a function that will evaluate PHP code. Carry out a manual check to determine whether the variable is user-controlled.", FileName, CodeIssue.MEDIUM, CodeLine)
            End If
        End If

    End Sub

    Private Sub CheckRegisterGlobals(CodeLine As String, FileName As String)
        ' Check for any unsafe use of Global Variables
        '=============================================
        Dim arrFragments As String()

        If ctCodeTracker.IsRegisterGlobals = True Then Exit Sub

        If ctCodeTracker.IsArrayMerge = False Then

            If Regex.IsMatch(CodeLine, "\bini_set\b\s*\(\s*(\'|\"")register_globals(\'|\"")\s*\,\s*(1|true|TRUE|True|\$\w+)") Then
                ' Is it being re-enabled?
                frmMain.ListCodeIssue("Use of 'register_globals'", "The application appears to re-activate the use of the dangerous 'register_globals' facility. Anything passed via GET or POST or COOKIE is automatically assigned as a global variable in the code, with potentially serious consequences.", FileName, CodeIssue.CRITICAL, CodeLine)

            ElseIf Regex.IsMatch(CodeLine, "\$\w+\s*\=\s*\barray_merge\b\s*\(\s*\$_(GET|POST|COOKIE|REQUEST|SERVER)\s*\,\s*\$_(GET|POST|COOKIE|REQUEST|SERVER)") Then
                ' Is it being simulated?
                ctCodeTracker.IsArrayMerge = True
                ' Get name of the array of input parameters
                arrFragments = Regex.Split(CodeLine, "\=\s*\barray_merge\b\s*\(\s*\$_(GET|POST|COOKIE|REQUEST|SERVER)\s*\,")
                ctCodeTracker.GlobalArrayName = GetLastItem(arrFragments.First())
                frmMain.ListCodeIssue("Indiscriminate Merging of Input Variables", "The application appears to incorporate all incoming GET and POST data into a single array. This can facilitate GET to POST conversion and may result in unexpected behaviour or unintentionally change variables.", FileName, CodeIssue.HIGH, CodeLine)
            End If

        ElseIf ctCodeTracker.IsArrayMerge = True Then
            If Regex.IsMatch(CodeLine, "\bglobal\b") And Regex.IsMatch(CodeLine, ctCodeTracker.GlobalArrayName) Then
                ctCodeTracker.IsRegisterGlobals = True
                frmMain.ListCodeIssue("Use of 'register_globals'", "The application appears to attempt to simulate the use of the dangerous 'register_globals' facility. Anything passed via GET or POST or COOKIE is automatically assigned as a global variable in the code, with potentially serious consequences.", FileName, CodeIssue.CRITICAL, CodeLine)
            End If
        End If

    End Sub

    Private Sub CheckParseStr(CodeLine As String, FileName As String)
        ' Check for any unsafe use of parse_str which offers similar dangers to Global Variables
        '=======================================================================================
        Dim blnIsFound = False


        '== Identify unssafe usage of parse_str, with an input var, but no destination array ==
        If Regex.IsMatch(CodeLine, "\bparse_str\b\s*\(\s*\$\w+\s*\)") Then

            For Each strVar In ctCodeTracker.InputVars
                If Regex.IsMatch(CodeLine, "\bparse_str\b\s*\(\s*" & strVar & "\s*\)") Then
                    frmMain.ListCodeIssue("Use of 'parse_str' with User Controlled Variable", "The application appears to use parse_str in an unsafe manner in combination with a user-controlled variable. Anything passed as part of the input string is automatically assigned as a global variable in the code, with potentially serious consequences.", FileName, CodeIssue.CRITICAL, CodeLine)
                    blnIsFound = True
                    Exit For
                End If
            Next
            If blnIsFound = False Then
                frmMain.ListCodeIssue("Use of 'parse_str'", "The application appears to use parse_str in an unsafe manner. Anything passed as part of the input string is automatically assigned as a global variable in the code, with potentially serious consequences. Carry out a manual check to determine whether the variable is user-controlled.", FileName, CodeIssue.MEDIUM, CodeLine)
            End If
        End If

    End Sub

    Public Sub CheckPhpIni(CodeLine As String, FileName As String)
        ' Check config file for unsafe settings
        '======================================

        ' Ignore any comments
        If CodeLine.Trim().StartsWith(";") Then
            rtResultsTracker.OverallCommentCount += 1
            rtResultsTracker.CommentCount += 1
        ElseIf CodeLine.Trim() = "" Then
            rtResultsTracker.OverallWhitespaceCount += 1
            rtResultsTracker.WhitespaceCount += 1
        Else
            ' Check for dangerous settings
            If Regex.IsMatch(CodeLine, "\bregister_globals\b\s*=\s*\b(on|ON|On)\b") Then
                frmMain.ListCodeIssue("Use of 'register_globals'", "The application appears to activate the use of the dangerous 'register_globals' facility. Anything passed via GET or POST or COOKIE is automatically assigned as a global variable in the code, with potentially serious consequences.", FileName, CodeIssue.CRITICAL, CodeLine)

            ElseIf Regex.IsMatch(CodeLine, "\bsafe_mode\b\s*=\s*\b(off|OFF|Off)\b") Then
                frmMain.ListCodeIssue("De-Activation of 'safe_mode'", "The application appears to de-activate the use of 'safe_mode', which can increase risks for any CGI-based applications.", FileName, CodeIssue.MEDIUM, CodeLine)

            ElseIf Regex.IsMatch(CodeLine, "\b(magic_quotes_gpc|magic_quotes_runtime|magic_quotes_sybase)\b\s*=\s*\b(off|OFF|Off)\b") Then
                frmMain.ListCodeIssue("De-Activation of 'magic_quotes'", "The application appears to de-activate the use of 'magic_quotes', greatly increasing the risk of SQL injection.", FileName, CodeIssue.HIGH, CodeLine)

            ElseIf Regex.IsMatch(CodeLine, "\bdisable_functions\b\s*=\s*([\w, ]+)", RegexOptions.IgnoreCase) Then
                Dim disabledFunctions As String = Regex.Match(CodeLine, "\bdisable_functions\b\s*=\s*([\w, ]+)").Groups(1).Value
                If Not disabledFunctions.Contains("phpinfo") AndAlso Not disabledFunctions.Contains("system") Then
                    frmMain.ListCodeIssue("Inadequate 'disable_functions'", "Consider adding 'phpinfo' and 'system' to disable_functions to enhance security.", FileName, CodeIssue.MEDIUM, CodeLine)
                End If

            ElseIf Regex.IsMatch(CodeLine, "\bmysql.default_user\b\s*=\s*\broot\b") Then
                frmMain.ListCodeIssue("Log in to MySQL as 'root'", "The application appears to log in to MySQL as 'root', greatly increasing the consequences of a successful SQL injection attack.", FileName, CodeIssue.HIGH, CodeLine)

            ElseIf Regex.IsMatch(CodeLine, "\b(expose_php)\b\s*=\s*\b(on|ON|On)\b") Then
                frmMain.ListCodeIssue("Exposure of PHP info", "The application appears to expose PHP version information. Set 'expose_php' to Off to increase security.", FileName, CodeIssue.MEDIUM, CodeLine)

            ElseIf Regex.IsMatch(CodeLine, "\b(display_errors)\b\s*=\s*\b(on|ON|On)\b") Then
                frmMain.ListCodeIssue("Displaying errors to users", "Displaying errors to end-users can leak sensitive information. Set 'display_errors' to Off.", FileName, CodeIssue.HIGH, CodeLine)

            ElseIf Regex.IsMatch(CodeLine, "\bfile_uploads\b\s*=\s*\b(on|ON|On)\b") Then
                frmMain.ListCodeIssue("Allowing file uploads", "File uploads should be turned Off if not used by the application. This reduces the risk of file upload vulnerabilities.", FileName, CodeIssue.MEDIUM, CodeLine)

            ElseIf Regex.IsMatch(CodeLine, "\ballow_url_fopen\b\s*=\s*\b(on|ON|On)\b") Then
                frmMain.ListCodeIssue("Remote file access", "Enabling 'allow_url_fopen' can lead to Local File Inclusion (LFI) vulnerabilities. Consider setting it to Off.", FileName, CodeIssue.HIGH, CodeLine)

            ElseIf Regex.IsMatch(CodeLine, "\bmax_execution_time\b\s*=\s*\d+") Then
                Dim executionTime As Integer = Integer.Parse(Regex.Match(CodeLine, "\bmax_execution_time\b\s*=\s*(\d+)").Groups(1).Value)
                If executionTime > 30 Then
                    frmMain.ListCodeIssue("Excessive max_execution_time", "Consider reducing 'max_execution_time' to a maximum of 30 seconds to prevent denial of service attacks.", FileName, CodeIssue.MEDIUM, CodeLine)
                End If

            ElseIf Regex.IsMatch(CodeLine, "\bmemory_limit\b\s*=\s*[\d]+M") Then
                Dim memoryLimit As Integer = Integer.Parse(Regex.Match(CodeLine, "\bmemory_limit\b\s*=\s*(\d+)M").Groups(1).Value)
                If memoryLimit > 8 Then
                    frmMain.ListCodeIssue("High memory_limit", "Consider lowering 'memory_limit' to 8M for better resource management.", FileName, CodeIssue.MEDIUM, CodeLine)
                End If

                ' New checks for session-related settings
            ElseIf Regex.IsMatch(CodeLine, "\bsession.cookie_httponly\b\s*=\s*\b(off|OFF|Off)\b") Then
                frmMain.ListCodeIssue("HTTPOnly Cookies", "Consider setting 'session.cookie_httponly' to 1 to prevent access to cookies via JavaScript.", FileName, CodeIssue.MEDIUM, CodeLine)

            ElseIf Regex.IsMatch(CodeLine, "\bsession.use_strict_mode\b\s*=\s*\b(off|OFF|Off)\b") Then
                frmMain.ListCodeIssue("Session Fixation Protection", "Consider setting 'session.use_strict_mode' to 1 to protect against session fixation attacks.", FileName, CodeIssue.MEDIUM, CodeLine)

            ElseIf Regex.IsMatch(CodeLine, "\bsession.cookie_secure\b\s*=\s*\b(off|OFF|Off)\b") Then
                frmMain.ListCodeIssue("Secure Cookies", "Consider setting 'session.cookie_secure' to 1 to ensure cookies are transmitted only over HTTPS.", FileName, CodeIssue.MEDIUM, CodeLine)

            ElseIf Regex.IsMatch(CodeLine, "\bsession.cookie_samesite\b\s*=\s*[^Strict]") Then
                frmMain.ListCodeIssue("SameSite Cookies", "Consider setting 'session.cookie_samesite' to 'Strict' to help prevent cross-origin attacks.", FileName, CodeIssue.MEDIUM, CodeLine)

            ElseIf Regex.IsMatch(CodeLine, "\bsession.use_trans_sid\b\s*=\s*\b(on|ON|On)\b") Then
                frmMain.ListCodeIssue("Trans SID Usage", "Setting 'session.use_trans_sid' to 1 can expose your application to security risks. Set it to 0.", FileName, CodeIssue.MEDIUM, CodeLine)

            ElseIf Regex.IsMatch(CodeLine, "\bsession.sid_length\b\s*=\s*\d+") Then
                Dim sidLength As Integer = Integer.Parse(Regex.Match(CodeLine, "\bsession.sid_length\b\s*=\s*(\d+)").Groups(1).Value)
                If sidLength < 128 Then
                    frmMain.ListCodeIssue("Short Session ID Length", "Consider increasing 'session.sid_length' to at least 128 to enhance security.", FileName, CodeIssue.MEDIUM, CodeLine)
                End If

            ElseIf Regex.IsMatch(CodeLine, "\bsession.sid_bits_per_character\b\s*=\s*\d+") Then
                Dim sidBits As Integer = Integer.Parse(Regex.Match(CodeLine, "\bsession.sid_bits_per_character\b\s*=\s*(\d+)").Groups(1).Value)
                If sidBits < 6 Then
                    frmMain.ListCodeIssue("Low SID Bits per Character", "Consider increasing 'session.sid_bits_per_character' to at least 6 to improve randomness.", FileName, CodeIssue.MEDIUM, CodeLine)
                End If

            End If

            rtResultsTracker.OverallCodeCount += 1
            rtResultsTracker.CodeCount += 1
        End If

        rtResultsTracker.OverallLineCount += 1
        rtResultsTracker.LineCount += 1
    End Sub

    Private Sub CheckInsecureDeserialization(CodeLine As String, FileName As String)
        ' Check for insecure deserialization vulnerabilities
        '==================================================

        ' Define patterns for PHP deserialization methods
        Dim deserializationPatterns As New List(Of String) From {
        "unserialize\(",
        "json_decode\(",
        "xml_decode\("
    }

        ' Check for actual use of insecure deserialization APIs (not just imports)
        If deserializationPatterns.Any(Function(p) System.Text.RegularExpressions.Regex.IsMatch(CodeLine, p)) Then
            ' Ensure input validation exists before deserialization
            If Not ctCodeTracker.HasInputValidation Then
                frmMain.ListCodeIssue("Potential Insecure Deserialization",
                               "Using deserialization methods or APIs without apparent input validation.",
                               FileName,
                               CodeIssue.MEDIUM) ' Changed to Medium severity
            End If
        End If

        ' Check for custom deserialization methods
        If Regex.IsMatch(CodeLine, "function\s+customDeserialize\(") Then
            frmMain.ListCodeIssue("Custom Deserialization Implementation",
                           "Detected custom deserialization methods. Ensure input validation and type checking.",
                           FileName,
                           CodeIssue.MEDIUM)
        End If

        ' Check for use of unserialize() with user-controlled data
        If Regex.IsMatch(CodeLine, "unserialize\(\s*\$") Then
            frmMain.ListCodeIssue("Use of unserialize()",
                           "unserialize() may lead to code execution if data is user-controlled.",
                           FileName,
                           CodeIssue.HIGH)
        End If

        ' Check for gadget chains in deserialization
        Dim gadgetPatterns As New List(Of String) From {
        "var_dump\(",         ' Example of a potential gadget
        "system\(",          ' Command execution function
        "shell_exec\(",      ' Command execution via shell
        "eval\("             ' Execution of PHP code
    }

        If gadgetPatterns.Any(Function(p) CodeLine.Contains(p)) Then
            frmMain.ListCodeIssue("Potential Gadget Chain",
                           "Detected potential gadget chain that may lead to security issues. Validate function calls thoroughly.",
                           FileName,
                           CodeIssue.MEDIUM)
        End If

        ' Update input validation status based on content
        If CodeLine.Contains("isset(") Or
       CodeLine.Contains("empty(") Or
       CodeLine.Contains("filter_input(") Then
            ctCodeTracker.HasInputValidation = True
        End If
    End Sub

    Private Sub CheckXXE(CodeLine As String, FileName As String)
        ' Check for potential XXE vulnerabilities 
        '=========================================

        ' Only check unvalidated code
        If ctCodeTracker.HasValidator = True Then Exit Sub

        ' Check for the use of XML parsing functions
        If Regex.IsMatch(CodeLine, "\b(simplexml_load_string|SimpleXMLElement|DOMDocument|xml_parse)\s*\(") Then
            ' Check if external entities are disabled
            If Not Regex.IsMatch(CodeLine, "libxml_disable_entity_loader\(\s*true\s*\)") AndAlso
               Not Regex.IsMatch(CodeLine, "->loadXML\(\s*[^)]*\s*false\s*") AndAlso
               Not Regex.IsMatch(CodeLine, "simplexml_load_string\(\s*[^,]*,\s*null\s*,\s*LIBXML_NOCDATA\s*\)") AndAlso
               Not Regex.IsMatch(CodeLine, "new\s+SimpleXMLElement\s*\(\s*[^,]*,\s*null\s*,\s*LIBXML_NOCDATA\s*\)") Then
                frmMain.ListCodeIssue("Potential XXE Vulnerability", "The application appears to parse XML input without disabling external entity loading, which could lead to XXE attacks.", FileName, CodeIssue.HIGH, CodeLine)
            End If
        End If

        ' Check for file_get_contents with XML
        If Regex.IsMatch(CodeLine, "file_get_contents\s*\(\s*[^)]*\.xml\s*") Then
            frmMain.ListCodeIssue("Potential XXE Vulnerability", "The application appears to load XML data from a file without proper validation, which may allow XXE attacks.", FileName, CodeIssue.HIGH, CodeLine)
        End If
    End Sub



    '======================================================================================
    '== EXTENDED RULESET                                                                 ==
    '== Additional checks appended without altering any pre-existing logic.              ==
    '======================================================================================

    Private Function IsUserInputPHP(CodeLine As String) As Boolean
        ' Return True where the line appears to reference a tainted (user-controlled) source
        '==================================================================================

        If Regex.IsMatch(CodeLine, "\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER|ENV)\b") Then Return True
        If Regex.IsMatch(CodeLine, "\b(file_get_contents\s*\(\s*['""]php://input|getallheaders|apache_request_headers|filter_input)\b") Then Return True
        If Regex.IsMatch(CodeLine, "->\s*(input|query|get|post|all|request)\s*\(") Then Return True
        If Regex.IsMatch(CodeLine, "\bRequest::\s*(input|query|get|all|post)\b") Then Return True

        For Each strVar In ctCodeTracker.InputVars
            If strVar <> "" AndAlso CodeLine.Contains(strVar) Then Return True
        Next

        Return False

    End Function

    Private Sub CheckPHPWeakCrypto(CodeLine As String, FileName As String)
        ' Identify broken hashing, obsolete ciphers and weak password storage
        '====================================================================

        '== Broken hash algorithms ==
        If Regex.IsMatch(CodeLine, "\b(md5|sha1|crc32|crc32b)\s*\(") Or Regex.IsMatch(CodeLine, "\bhash\s*\(\s*['""]\s*(md2|md4|md5|sha1|crc32b?)\s*['""]") Then
            If Regex.IsMatch(CodeLine, "(?i)\$?\w*(password|passwd|pwd|secret|token|salt|auth)\w*") Then
                frmMain.ListCodeIssue("Password or Token Hashed With A Broken Algorithm", "MD5 and SHA-1 are fast, unsalted and collision-prone. A commodity GPU tests tens of billions of MD5 candidates per second, so any password database hashed this way should be regarded as cleartext. Use password_hash() with PASSWORD_ARGON2ID or PASSWORD_BCRYPT and verify with password_verify().", FileName, CodeIssue.HIGH, CodeLine)
            Else
                frmMain.ListCodeIssue("Use of Broken Hashing Algorithm", "MD5, SHA-1 and CRC32 are unsuitable for any security purpose. Practical collisions exist for MD5 and SHA-1, and CRC32 is a checksum with no cryptographic properties at all.", FileName, CodeIssue.MEDIUM, CodeLine)
            End If
        End If

        '== Obsolete crypto extensions and ciphers ==
        If Regex.IsMatch(CodeLine, "\bmcrypt_\w+\s*\(") Then
            frmMain.ListCodeIssue("Use of Removed mcrypt Extension", "mcrypt was deprecated in PHP 7.1 and removed in 7.2. It defaults to zero-padding, has no authenticated modes and its 'rijndael-256' is not AES-256. Use OpenSSL with aes-256-gcm or libsodium.", FileName, CodeIssue.HIGH, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "openssl_(encrypt|decrypt)\s*\([^\)]*['""]\s*(des|des-ede3|rc2|rc4|bf|aes-\d+-ecb|[a-z0-9\-]*ecb)\s*['""]") Then
            frmMain.ListCodeIssue("Broken Cipher Or ECB Mode Selected", "DES, RC2, RC4, Blowfish and any ECB mode are unsuitable. ECB in particular leaks plaintext structure because identical blocks map to identical ciphertext. Use aes-256-gcm, which additionally provides integrity.", FileName, CodeIssue.HIGH, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "openssl_(encrypt|decrypt)\s*\(") And Not Regex.IsMatch(CodeLine, "(gcm|ccm|poly1305|chacha)") Then
            frmMain.ListCodeIssue("Unauthenticated Encryption", "The cipher suite provides confidentiality without integrity. An attacker who can modify ciphertext may be able to alter the decrypted plaintext undetected, and CBC padding errors frequently expose a padding oracle. Use an AEAD mode or apply Encrypt-then-MAC with hash_hmac and a separate key.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

        '== Predictable IV or key ==
        If Regex.IsMatch(CodeLine, "openssl_(encrypt|decrypt)\s*\([^\)]*['""][A-Za-z0-9\+/=]{8,}['""]") Then
            frmMain.ListCodeIssue("Hard-Coded Key Or IV", "Key or IV material appears as a literal in the call. Recovery of the source or the deployed file yields the key, so the encryption provides no confidentiality. Generate IVs with random_bytes() per message and load keys from the environment or a secrets manager.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If

        '== Non-constant-time comparison of secrets ==
        If Regex.IsMatch(CodeLine, "(?i)(if|while|return|elseif)\s*\(?[^;]*\$?\w*(password|token|hash|hmac|signature|secret|apikey)\w*[^;]*(===|==|!=|!==)") And Not CodeLine.Contains("hash_equals") Then
            frmMain.ListCodeIssue("Non Constant-Time Comparison Of A Secret", "Comparing a token, signature or hash with == or === exits at the first differing byte. The resulting timing difference allows an attacker to recover the expected value one byte at a time over many requests. Use hash_equals().", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

        '== Predictable randomness ==
        If Regex.IsMatch(CodeLine, "\b(rand|mt_rand|uniqid|shuffle|str_shuffle|array_rand|lcg_value)\s*\(") And _
           Regex.IsMatch(CodeLine, "(?i)\$?\w*(token|session|nonce|salt|key|password|otp|secret|csrf|reset|id)\w*") Then
            frmMain.ListCodeIssue("Predictable Random Value Used For Security Purpose", "rand(), mt_rand() and uniqid() are not cryptographically secure. mt_rand uses Mersenne Twister, whose entire internal state is recoverable from 624 consecutive outputs; uniqid is derived from the system clock and is trivially predictable. Use random_bytes() or random_int().", FileName, CodeIssue.HIGH, CodeLine)
        End If

    End Sub

    Private Sub CheckPHPTypeJuggling(CodeLine As String, FileName As String)
        ' Identify loose comparison issues affecting authentication logic
        '================================================================

        If Regex.IsMatch(CodeLine, "(md5|sha1|hash|crypt)\s*\([^\)]*\)\s*==[^=]") Or Regex.IsMatch(CodeLine, "==\s*(md5|sha1|hash)\s*\(") Then
            frmMain.ListCodeIssue("Loose Comparison Of Hash Values (Type Juggling)", "PHP's == operator applies type coercion. Two hashes that both begin '0e' followed only by digits are treated as floating-point zero and compare equal - the 'magic hash' attack, which permits authentication bypass. Always compare hashes with === or hash_equals().", FileName, CodeIssue.HIGH, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "\bin_array\s*\(") And Not Regex.IsMatch(CodeLine, ",\s*true\s*\)") Then
            frmMain.ListCodeIssue("in_array() Without Strict Comparison", "Without the third argument set to true, in_array performs loose comparison. The string '1abc' matches the integer 1, and the value 0 matches any non-numeric string in older PHP versions, allowing allow-list checks to be bypassed.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "\bstrcmp\s*\([^\)]*\)\s*==\s*0") Or Regex.IsMatch(CodeLine, "\b(strcmp|strcasecmp)\s*\(") And IsUserInputPHP(CodeLine) Then
            frmMain.ListCodeIssue("strcmp() Result Used In Loose Comparison", "Passing an array where strcmp expects a string returns NULL, and NULL == 0 evaluates to true. Supplying param[]= in the query string therefore satisfies a strcmp-based password check. Validate the parameter type before comparison and use ===.", FileName, CodeIssue.HIGH, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "\bswitch\s*\(") And IsUserInputPHP(CodeLine) Then
            frmMain.ListCodeIssue("Switch Statement On User Input", "PHP's switch uses loose comparison, so a numeric string or a leading-numeric string may match an unintended case label. Where the switch implements an authorisation decision this can be abused. Normalise and validate the value first.", FileName, CodeIssue.LOW, CodeLine)
        End If

    End Sub

    Private Sub CheckPHPSSRF(CodeLine As String, FileName As String)
        ' Identify outbound requests whose destination is user-controlled
        '================================================================

        If Regex.IsMatch(CodeLine, "\b(curl_setopt|curl_init|file_get_contents|fopen|readfile|get_headers|fsockopen|stream_context_create|simplexml_load_file|DOMDocument)\b") Then
            If IsUserInputPHP(CodeLine) Then
                frmMain.ListCodeIssue("Potential Server-Side Request Forgery (SSRF)", "The destination of an outbound request is derived from user input. PHP stream wrappers make this especially dangerous: as well as reaching internal services and cloud metadata endpoints, the file://, php:// and gopher:// wrappers permit local file disclosure and crafted requests to arbitrary TCP services. Validate the scheme and host against an allow-list and reject private address ranges after resolution.", FileName, CodeIssue.HIGH, CodeLine)
            End If
        End If

        If Regex.IsMatch(CodeLine, "CURLOPT_SSL_VERIFY(PEER|HOST)\s*,\s*(0|false|FALSE)") Then
            frmMain.ListCodeIssue("cURL TLS Verification Disabled", "Certificate or hostname verification has been switched off, so any certificate is accepted and the connection offers no protection against active interception. Note that CURLOPT_SSL_VERIFYHOST must be set to 2, not 1 - the value 1 is meaningless and is treated as an error in current libcurl.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "CURLOPT_FOLLOWLOCATION\s*,\s*(1|true|TRUE)") Then
            frmMain.ListCodeIssue("cURL Redirect Following Enabled", "Following redirects automatically allows an allow-listed host to redirect the request to an internal address, bypassing SSRF filtering. Disable it and validate each hop, or set CURLOPT_PROTOCOLS and CURLOPT_REDIR_PROTOCOLS to restrict schemes.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

    End Sub

    Private Sub CheckPHPFileHandling(CodeLine As String, FileName As String)
        ' Identify path traversal, unrestricted upload and archive extraction issues
        '===========================================================================

        If Regex.IsMatch(CodeLine, "\b(fopen|file_get_contents|file_put_contents|readfile|unlink|rename|copy|mkdir|rmdir|scandir|glob|opendir|file|highlight_file|show_source)\s*\(") And IsUserInputPHP(CodeLine) Then
            frmMain.ListCodeIssue("Potential Path Traversal Or Local File Disclosure", "A filesystem path is built from request data. Traversal sequences allow arbitrary file read or write; note that PHP also resolves stream wrappers here, so an input beginning 'php://filter/convert.base64-encode/resource=' returns the source of any readable file. Use basename() plus realpath() and confirm the resolved path remains under the intended directory.", FileName, CodeIssue.HIGH, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "\bmove_uploaded_file\s*\(") Then
            frmMain.ListCodeIssue("File Upload Handling", "An uploaded file is written to disk. Confirm that the destination filename is generated server-side rather than taken from $_FILES['name'], that the extension is validated against an allow-list, that the storage directory is outside the web root or has script execution disabled, and that the MIME type reported by the client is not trusted.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\$_FILES\s*\[[^\]]*\]\s*\[\s*['""](name|type)['""]\s*\]") Then
            frmMain.ListCodeIssue("Reliance On Client-Supplied Upload Metadata", "The filename and MIME type in $_FILES are supplied by the client and are trivially forged. Determine the type server-side with finfo_file and generate the stored filename yourself.", FileName, CodeIssue.HIGH, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "\b(ZipArchive|PharData|extractTo)\b") Then
            frmMain.ListCodeIssue("Potential Zip Slip During Archive Extraction", "extractTo() writes entries using the names stored in the archive. Traversal sequences in an entry name allow files to be written outside the destination directory. Enumerate entries and validate each resolved path before extraction.", FileName, CodeIssue.HIGH, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "['""]phar://") Then
            frmMain.ListCodeIssue("Phar Stream Wrapper In Use", "Any filesystem function operating on a phar:// path deserialises the archive metadata, invoking __wakeup and __destruct on arbitrary classes. This turns an apparently harmless file operation into an object injection sink. Register a phar stream wrapper guard or disable phar in production.", FileName, CodeIssue.HIGH, CodeLine)
        End If

    End Sub

    Private Sub CheckPHPHeaderInjection(CodeLine As String, FileName As String)
        ' Identify response splitting, open redirect and mail header injection
        '=====================================================================

        If Regex.IsMatch(CodeLine, "\bheader\s*\(") And IsUserInputPHP(CodeLine) Then
            If Regex.IsMatch(CodeLine, "(?i)header\s*\(\s*['""]\s*location") Then
                frmMain.ListCodeIssue("Potential Open Redirect", "The redirect target is built from user input. An attacker can send victims to a site under their control while the initial link points at the trusted domain, which is highly effective in phishing and is also used to steal OAuth authorisation codes. Redirect only to relative paths, or match the target against an allow-list.", FileName, CodeIssue.MEDIUM, CodeLine)
            Else
                frmMain.ListCodeIssue("Potential HTTP Response Header Injection", "A header value contains user input. Where carriage return and line feed are not stripped an attacker injects further headers or a complete second response, enabling cache poisoning and reflected cross-site scripting. Modern PHP blocks bare newlines in header(), but encoded variants and framework wrappers are not always protected.", FileName, CodeIssue.HIGH, CodeLine)
            End If
        End If

        If Regex.IsMatch(CodeLine, "\bmail\s*\(") And IsUserInputPHP(CodeLine) Then
            frmMain.ListCodeIssue("Potential Mail Header Or Argument Injection", "User input reaches mail(). Newlines in the subject or additional-headers parameter allow injection of Bcc and Cc headers, turning the application into an open relay for spam. The fifth parameter is passed to sendmail as command-line arguments, so unvalidated input there permits arbitrary file write via the -X option.", FileName, CodeIssue.HIGH, CodeLine)
        End If

    End Sub

    Private Sub CheckPHPSessionSecurity(CodeLine As String, FileName As String)
        ' Identify session fixation and insecure session configuration
        '=============================================================

        If Regex.IsMatch(CodeLine, "\bsession_id\s*\(\s*\$") Then
            frmMain.ListCodeIssue("Session Identifier Set From A Variable", "The session identifier is assigned from a variable. Where that value originates from the request an attacker can fix a known session identifier in the victim's browser and then reuse it after the victim authenticates - classic session fixation.", FileName, CodeIssue.HIGH, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "session\.use_(only_)?cookies\s*['""]?\s*,\s*['""]?\s*0") Or Regex.IsMatch(CodeLine, "session\.use_trans_sid\s*['""]?\s*,\s*['""]?\s*1") Then
            frmMain.ListCodeIssue("Session Identifier Permitted In The URL", "Transparent session identifiers place the token in URLs, where it leaks through Referer headers, browser history, proxy logs and shared links.", FileName, CodeIssue.HIGH, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "session\.cookie_(httponly|secure)\s*['""]?\s*,\s*['""]?\s*(0|false|off)") Or _
           Regex.IsMatch(CodeLine, "setcookie\s*\([^\)]*,\s*(false|0)\s*,\s*(false|0)\s*\)") Then
            frmMain.ListCodeIssue("Session Cookie Missing Secure Or HttpOnly Flag", "Without HttpOnly the session cookie is readable by JavaScript, so any cross-site scripting flaw becomes session theft; without Secure it is transmitted over plain HTTP and can be captured on the network.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "\bsession_start\s*\(") And Not Regex.IsMatch(CodeLine, "session_regenerate_id") Then
            frmMain.ListCodeIssue("Session Started - Confirm Identifier Regeneration", "Confirm that session_regenerate_id(true) is called immediately after any privilege change, in particular after successful authentication. Failure to regenerate leaves the application open to session fixation.", FileName, CodeIssue.LOW, CodeLine)
        End If

    End Sub

    Private Sub CheckPHPCodeInjection(CodeLine As String, FileName As String)
        ' Identify additional dynamic evaluation and callback sinks
        '==========================================================

        If Regex.IsMatch(CodeLine, "\b(assert|create_function)\s*\(") Then
            frmMain.ListCodeIssue("Use of assert() Or create_function()", "Both functions evaluate their string argument as PHP code. assert() with a string argument is deprecated in PHP 7.2 and removed in 8; create_function() was removed in PHP 8. Where any part of the argument is user-controlled this is direct remote code execution.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "\b(call_user_func|call_user_func_array|array_map|usort|uasort|uksort|array_filter|array_walk|register_shutdown_function|set_error_handler|preg_replace_callback)\s*\(") And IsUserInputPHP(CodeLine) Then
            frmMain.ListCodeIssue("User Controlled Callback Function", "The callable passed to this function appears to derive from user input. PHP will invoke any named function, including system, exec and assert, giving arbitrary code execution. Map the input to a fixed set of permitted callbacks.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "preg_replace\s*\(\s*['""][^'""]*['""][eimsuxADSUXJ]*e[imsuxADSUXJ]*['""]") Then
            frmMain.ListCodeIssue("preg_replace() With The /e Modifier", "The /e modifier evaluates the replacement string as PHP code. It was removed in PHP 7 but remains a reliable code execution sink in legacy deployments.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "\$\s*\$\w+|\$\{\s*\$") Then
            frmMain.ListCodeIssue("Variable Variable In Use", "Variable variables resolve a name at runtime. Where the name derives from request data an attacker can overwrite arbitrary variables in scope, including those holding authentication state or configuration.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "\b(extract|import_request_variables|compact)\s*\(") Then
            frmMain.ListCodeIssue("Variable Extraction From An Array", "extract() creates variables from array keys. Applied to request data it lets an attacker overwrite any variable in the current scope - a well-known authentication bypass technique. Use explicit assignment with EXTR_SKIP at minimum.", FileName, CodeIssue.HIGH, CodeLine)
        End If

    End Sub

    Private Sub CheckPHPCommandArguments(CodeLine As String, FileName As String)
        ' Identify incomplete escaping around shell invocation
        '=====================================================

        If Regex.IsMatch(CodeLine, "\b(system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(") Then
            If Regex.IsMatch(CodeLine, "\bescapeshellcmd\s*\(") And Not Regex.IsMatch(CodeLine, "\bescapeshellarg\s*\(") Then
                frmMain.ListCodeIssue("escapeshellcmd() Used Where escapeshellarg() Is Required", "escapeshellcmd escapes shell metacharacters but leaves whitespace and quotes intact, so an attacker can still introduce additional arguments to the invoked program - for example adding an output-file or configuration switch. Wrap each individual argument in escapeshellarg().", FileName, CodeIssue.HIGH, CodeLine)
            End If
            If Regex.IsMatch(CodeLine, "escapeshellarg\s*\([^\)]*\)\s*\.") And Regex.IsMatch(CodeLine, "['""]\s*-") Then
                frmMain.ListCodeIssue("Argument Injection Despite Escaping", "escapeshellarg prevents command chaining but not argument injection: a value beginning with '-' is still interpreted as an option by the target program. Where the argument is a filename, prefix it with './' or terminate option parsing with '--'.", FileName, CodeIssue.MEDIUM, CodeLine)
            End If
        End If

    End Sub

    Private Sub CheckPHPFrameworkIssues(CodeLine As String, FileName As String)
        ' Identify framework-specific insecure constructs
        '================================================

        '== Raw query builders ==
        If Regex.IsMatch(CodeLine, "\b(DB::raw|whereRaw|orWhereRaw|havingRaw|orderByRaw|selectRaw|groupByRaw|->raw\s*\()") And CodeLine.Contains("$") Then
            frmMain.ListCodeIssue("Raw SQL Fragment With Interpolated Variable", "Raw query-builder helpers pass the string straight to the database. Interpolating a variable into the fragment reintroduces SQL injection despite the ORM. Use bound parameters via the second argument.", FileName, CodeIssue.HIGH, CodeLine)
        End If

        '== Unescaped template output ==
        If Regex.IsMatch(CodeLine, "\{!!.*!!\}") Or Regex.IsMatch(CodeLine, "\|\s*raw\b") Then
            frmMain.ListCodeIssue("Unescaped Template Output", "Blade's {!! !!} and Twig's |raw filter emit the value without HTML encoding. Where the value contains user input this is a direct cross-site scripting sink.", FileName, CodeIssue.HIGH, CodeLine)
        End If

        '== Debug and environment exposure ==
        If Regex.IsMatch(CodeLine, "(APP_DEBUG|display_errors)\s*[=:]\s*['""]?\s*(true|on|1)") Then
            frmMain.ListCodeIssue("Debug Mode Enabled", "Debug output exposes stack traces, environment variables and often database credentials to any client that triggers an error. In Laravel the Ignition debug page has additionally been the vehicle for remote code execution (CVE-2021-3129).", FileName, CodeIssue.HIGH, CodeLine)
        End If

        '== Mass assignment ==
        If Regex.IsMatch(CodeLine, "\$guarded\s*=\s*\[\s*\]") Or Regex.IsMatch(CodeLine, "\bunguard\s*\(|forceFill\s*\(") Then
            frmMain.ListCodeIssue("Eloquent Mass Assignment Protection Disabled", "An empty $guarded array, unguard() or forceFill() allows every attribute to be set from request input. An attacker adds fields such as is_admin or user_id to the request body and escalates privilege. Define an explicit $fillable allow-list.", FileName, CodeIssue.HIGH, CodeLine)
        End If

        '== Object injection through unserialize on cookies ==
        If Regex.IsMatch(CodeLine, "\bunserialize\s*\(") And IsUserInputPHP(CodeLine) Then
            frmMain.ListCodeIssue("unserialize() On User-Controlled Data", "unserialize reconstructs arbitrary objects and invokes their magic methods (__wakeup, __destruct, __toString). Combined with the classes available in the application or its dependencies this yields PHP object injection and frequently remote code execution. Use json_decode, or pass the allowed_classes option set to false.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If

    End Sub

    Private Sub CheckPHPHardcodedSecrets(CodeLine As String, FileName As String)
        ' Identify credentials and API keys embedded in source
        '=====================================================

        If Regex.IsMatch(CodeLine, "AKIA[0-9A-Z]{16}") Then
            frmMain.ListCodeIssue("Hard-Coded AWS Access Key", "A string matching the AWS access key ID format is present in source. Revoke the key and move to an instance role or secrets manager.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "(gh[pousr]_[A-Za-z0-9]{36}|xox[baprs]-[A-Za-z0-9\-]{10,}|sk_live_[0-9a-zA-Z]{24,}|AIza[0-9A-Za-z\-_]{35})") Then
            frmMain.ListCodeIssue("Hard-Coded Third-Party API Token", "A GitHub, Slack, Stripe or Google API token appears to be embedded in source.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "-----BEGIN\s+(RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE KEY") Then
            frmMain.ListCodeIssue("Private Key Embedded In Source", "A PEM-encoded private key is stored in the repository and must be treated as compromised.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "(?i)(\$\w*(password|passwd|pwd|secret|apikey|api_key|token|salt)\w*|'(password|secret|key|token)')\s*(=|=>)\s*['""][^'""]{4,}['""]") Then
            frmMain.ListCodeIssue("Hard-Coded Secret Assigned To Variable", "A variable or configuration key whose name indicates a credential is initialised with a literal string. Move it to an environment variable or secrets manager and rotate the value, since it persists in version control history.", FileName, CodeIssue.HIGH, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\b(mysqli_connect|new\s+mysqli|new\s+PDO|pg_connect)\s*\([^\)]*['""][^'""]{3,}['""]\s*\)") Then
            frmMain.ListCodeIssue("Database Credentials In Connection Call", "Connection credentials appear inline in the source. Where the file is served as plain text because of a misconfiguration or a backup extension, the credentials are disclosed directly.", FileName, CodeIssue.HIGH, CodeLine)
        End If

    End Sub

    Private Sub CheckPHPCorsAndHeaders(CodeLine As String, FileName As String)
        ' Identify permissive CORS and missing security headers
        '======================================================

        If Regex.IsMatch(CodeLine, "Access-Control-Allow-Origin\s*:\s*\*") Then
            frmMain.ListCodeIssue("Overly Permissive CORS Policy", "Any origin may read responses from this endpoint. Where the endpoint returns user-specific data this exposes it to every site the victim visits.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "Access-Control-Allow-Origin\s*:\s*[""']?\s*\.?\s*\$") Then
            frmMain.ListCodeIssue("CORS Origin Reflected From The Request", "The Origin header is echoed back without validation. Combined with Access-Control-Allow-Credentials this allows any website to make authenticated cross-origin requests and read the responses.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "Access-Control-Allow-Credentials\s*:\s*true") And Regex.IsMatch(CodeLine, "Access-Control-Allow-Origin\s*:\s*(\*|[""']?\s*\.?\s*\$)") Then
            frmMain.ListCodeIssue("CORS Credentials Permitted With Wildcard Or Reflected Origin", "This combination allows arbitrary sites to issue authenticated cross-origin requests with the victim's cookies and read the responses.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If

    End Sub
End Module
