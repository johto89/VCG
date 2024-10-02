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


End Module
