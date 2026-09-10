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

Module modPlSqlCheck

    ' Specific checks for PL/SQL code
    '================================

    Public Sub CheckPLSQLCode(CodeLine As String, FileName As String)
        ' Carry out any specific checks for the language in question
        '===========================================================


        CheckCrypto(CodeLine, FileName)         ' Check for use Oracle encryption packages for sensitive data
        CheckSqlInjection(CodeLine, FileName)   ' Check usage of EXECUTE IMMEDIATE and OPEN FOR
        CheckPrivs(CodeLine, FileName)          ' Check privilege assignments for packages
        CheckTransControl(CodeLine, FileName)   ' Check potential for data corruption for inappropriate use of COMMIT/ROLLBACK
        CheckErrorHandling(CodeLine, FileName)  ' Identify error handling via return values instead of raising an exception
        CheckViewFormat(CodeLine, FileName)     ' Identify any data formatting within views   

        '== Extended ruleset ==
        CheckWeakCrypto(CodeLine, FileName)             ' Obsolete DBMS_CRYPTO algorithms, ECB, hard-coded keys, DBMS_RANDOM
        CheckDefinerRights(CodeLine, FileName)          ' AUTHID handling and autonomous transactions
        CheckPrivilegeGrants(CodeLine, FileName)        ' Grants to PUBLIC, ANY privileges and inline passwords
        CheckNetworkPackages(CodeLine, FileName)        ' UTL_HTTP/UTL_FILE/scheduler exfiltration and OS command paths
        CheckDynamicSqlAssertion(CodeLine, FileName)    ' Dynamic SQL without bind variables or DBMS_ASSERT
        CheckExceptionSuppression(CodeLine, FileName)   ' WHEN OTHERS handlers that discard or leak errors
        CheckAuditAndSensitiveData(CodeLine, FileName)  ' Audit reduction, wrapping and sensitive output

    End Sub

    Private Sub CheckCrypto(CodeLine As String, FileName As String)
        ' Check for use Oracle encryption packages for sensitive data such as passwords
        '==============================================================================

        '== Do not perform this check for SQL*Plus files ==
        If FileName.EndsWith(".sql") Then Exit Sub

        '== Check for use of DBMS_CRYPTO package (reversible encryption) or DBMS_OBFUSCATION_TOOLKIT (hashes) for anything that appears to deal with passwords ==
        If ctCodeTracker.IsOracleEncrypt = False And (CodeLine.Contains("DBMS_CRYPTO") Or CodeLine.Contains("DBMS_OBFUSCATION_TOOLKIT")) Then
            ctCodeTracker.IsOracleEncrypt = True
        End If
        If ctCodeTracker.IsOracleEncrypt = False And CodeLine.Contains("PASSWORD") And Not CodeLine.Contains("ACCEPT") Then
            frmMain.ListCodeIssue("Code Appears to Process Passwords Without the Use of a Standard Oracle Encryption Module", "The code contains references to 'password'. The absence of any hashing or decryption functions indicates that the password may be stored as plaintext.", FileName, CodeIssue.HIGH)
        End If

    End Sub

    Private Sub CheckSqlInjection(CodeLine As String, FileName As String)
        ' Check for use of EXECUTE IMMEDIATE or OPEN FOR in combination with user-supplied data 
        '======================================================================================
        Dim strVarName As String = ""   ' Holds the variable name for the dynamic SQL statement
        Dim arrFragments As String()


        '== Is unsanitised dynamic SQL statement prepared beforehand? ==
        If ctCodeTracker.IsInsideSQLVarDec = True Then
            If Regex.IsMatch(CodeLine, "(\'|\"")\s*(SELECT|UPDATE|DELETE|INSERT|MERGE|CREATE|SAVEPOINT|ROLLBACK|DROP)") Then
                If Not ctCodeTracker.SQLStatements.Contains(ctCodeTracker.CurrentVar) Then ctCodeTracker.SQLStatements.Add(ctCodeTracker.CurrentVar)
                ctCodeTracker.IsInsideSQLVarDec = False
            ElseIf CodeLine.Contains(";") Then
                ctCodeTracker.IsInsideSQLVarDec = False
            End If
        Else
            If Regex.IsMatch(CodeLine, "\bPROCEDURE\b\s+\w+") Then
                '== Check if we are inside a procedure so we can extract any input variables ==
                ctCodeTracker.IsInsideProcDec = True
            ElseIf ctCodeTracker.IsInsideProcDec = True Then
                '== Get any varnames that are passed in to a procedure ==
                If Regex.IsMatch(CodeLine, "\w+\s+\bIN\b") Then
                    arrFragments = Regex.Split(CodeLine, "\bIN\b")
                    strVarName = GetLastItem(arrFragments.First)
                    ctCodeTracker.InputVars.Add(strVarName)
                End If
                If CodeLine.Contains(")") Then ctCodeTracker.IsInsideProcDec = False
            ElseIf (CodeLine.Contains(":=") And Regex.IsMatch(CodeLine, "(\'|\"")\s*(SELECT|UPDATE|DELETE|INSERT|MERGE|CREATE|SAVEPOINT|ROLLBACK|DROP)")) Or _
                (Regex.IsMatch(CodeLine, "(SQL|QRY|QUERY)\w*\s*\:\=")) Then
                '== Extract variable name from assignment statement ==
                arrFragments = CodeLine.Split(":")
                strVarName = arrFragments.First.Trim
                If Not ctCodeTracker.SQLStatements.Contains(strVarName) Then ctCodeTracker.SQLStatements.Add(strVarName)
            ElseIf Regex.IsMatch(CodeLine, "\:\=\s*$") Then
                '== Declaration starts on next line ==
                ctCodeTracker.IsInsideSQLVarDec = True
                '== Extract variable name from assignment statement ==
                arrFragments = CodeLine.Split(":")
                ctCodeTracker.CurrentVar = arrFragments.First.Trim
            End If
        End If

        '== Check for misuse of sql statements ==
        If ctCodeTracker.IsInsidePlSqlExecuteStmt = False Then
            If (CodeLine.Contains("EXECUTE IMMEDIATE") Or CodeLine.Contains("OPEN FOR")) And (Regex.IsMatch(CodeLine, "(\'\"")\s*\|\|\s*\w+") Or Regex.IsMatch(CodeLine, "\w+\s*\|\|\s*(\'\"")\s*\|\|")) Then
                frmMain.ListCodeIssue("Variable concatenated with dynamic SQL statement.", "Statement is potentially vulnerable to SQL injection, depending on the origin of input variables and opportunities for an attacker to modify them before they reach the procedure.", FileName, CodeIssue.CRITICAL, CodeLine)
            ElseIf (CodeLine.Contains("EXECUTE IMMEDIATE") Or CodeLine.Contains("OPEN FOR")) And Not (CodeLine.Contains("'") Or CodeLine.Contains("""")) Then
                For Each strVar In ctCodeTracker.SQLStatements
                    If CodeLine.Contains(strVar) Then
                        frmMain.ListCodeIssue("Potential SQL Injection", "The application appears to allow SQL injection through use of an input variable within a query, depending on the origin of input variables and opportunities for an attacker to modify them before they reach the procedure.", FileName, CodeIssue.CRITICAL, CodeLine)
                        Exit For
                    End If
                Next
            ElseIf (CodeLine.Contains("EXECUTE IMMEDIATE") Or CodeLine.Contains("OPEN FOR")) And Not CodeLine.Contains(";") Then
                ctCodeTracker.IsInsidePlSqlExecuteStmt = True
            End If

        Else
            If (Regex.IsMatch(CodeLine, "(\'\"")\s*\|\|\s*\w+") Or Regex.IsMatch(CodeLine, "\w+\s*\|\|\s*(\'\"")")) Then
                frmMain.ListCodeIssue("Variable concatenated with dynamic SQL statement.", "Statement is potentially vulnerable to SQL injection, depending on the origin of input variables and opportunities for an attacker to modify them before they reach the procedure.", FileName, CodeIssue.CRITICAL, CodeLine)
            ElseIf Not (CodeLine.Contains("'") Or CodeLine.Contains("""")) Then
                For Each strVar In ctCodeTracker.SQLStatements
                    If CodeLine.Contains(strVar) Then
                        frmMain.ListCodeIssue("Potential SQL Injection", "The application appears to allow SQL injection through use of an input variable within a query, depending on the origin of input variables and opportunities for an attacker to modify them before they reach the procedure.", FileName, CodeIssue.CRITICAL, CodeLine)
                        Exit For
                    End If
                Next
            End If
            If CodeLine.Contains(";") Then ctCodeTracker.IsInsidePlSqlExecuteStmt = False
        End If

    End Sub

    Private Sub CheckPrivs(CodeLine As String, FileName As String)
        ' Check privilege assignments for packages and highlight anything too liberal
        '============================================================================


        '== Check for 'CREATE OR REPLACE PACKAGE BODY' without 'AUTHID CURRENT_USER' ==
        If ctCodeTracker.IsNewPackage = False And (CodeLine.Contains("CREATE OR REPLACE PACKAGE BODY") Or CodeLine.Contains("CREATE PACKAGE BODY")) Then ctCodeTracker.IsNewPackage = True

        '== Check the privs for any new package ==
        If ctCodeTracker.IsNewPackage = True Then
            If Regex.IsMatch(CodeLine, "\bAUTHID\b\s+\bCURRENT_USER\b") Then
                ' If package is running as current user there's no problem - set to false and carry on
                ctCodeTracker.IsNewPackage = False
            ElseIf Regex.IsMatch(CodeLine, "\bAUTHID\b\s+\bDEFINER\b") Then
                ' If package is running as definer then give a warning
                frmMain.ListCodeIssue("Package Running Under Potentially Excessive Permissions", "The use of AUTHID DEFINER allows a user to run functions from this package in the role of the definer (usually a developer or administrator).", FileName)
                ctCodeTracker.IsNewPackage = False
            End If
            If ctCodeTracker.IsNewPackage = True And Regex.IsMatch(CodeLine, "\b(AS|IS)\b") Then
                ' If we've reached this point then the package has been defined with no specified privileges and so is running as definer
                frmMain.ListCodeIssue("Package Running Under Potentially Excessive Permissions", "The failure to use AUTHID CURRENT_USER allows a user to run functions from this package in the role of the definer (usually a developer or administrator).", FileName, CodeIssue.STANDARD, "1")
                ctCodeTracker.IsNewPackage = False
            End If
        End If

    End Sub

    Private Sub CheckTransControl(CodeLine As String, FileName As String)
        ' Check potential for data corruption for inappropriate use of COMMIT/ROLLBACK
        '=============================================================================

        '== Do not perform this check for SQL*Plus files ==
        If FileName.EndsWith(".sql") Then Exit Sub

        '== Check for transactional control in non-autonomous procedures ==
        If CodeLine.Contains("PRAGMA AUTONOMOUS_TRANSACTION") Then ctCodeTracker.IsAutonomousProcedure = True

        '== If the procedure is not autonomous identify any transactional controls ==
        If ctCodeTracker.IsAutonomousProcedure = False And (CodeLine.Contains("COMMIT") Or CodeLine.Contains("ROLLBACK")) Then
            frmMain.ListCodeIssue("Stored Procedure Contains COMMIT and/or ROLLBACK Statements in Procedures/Functions, Without the Use of PRAGMA AUTONOMOUS_TRANSACTION.", "This can result in data corruption, since rolling back or committing will split a wider logical transaction into two possibly conflicting sub-transactions. Exceptions to this include auditing procedures and long-running worker procedures.", FileName, CodeIssue.LOW)
        End If

    End Sub

    Private Sub CheckErrorHandling(CodeLine As String, FileName As String)
        ' Identify error handling via return values instead of raising an exception due to 
        ' risk of data corruption and implications for maintenance and bugs
        '=================================================================================

        '== Check for error handling with output parameters and magic numbers ==
        If CodeLine.Contains("ERROR") And CodeLine.Contains("OUT") And CodeLine.Contains("NUMBER") Then
            frmMain.ListCodeIssue("Error Handling With Output Parameters.", "The code appears to use output parameter(s) which implicitly signal an error by returning a special value, rather than raising an exception. This can make code harder to maintain and more error prone and can result in unexpected behaviour and data corruption.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

    End Sub

    Private Sub CheckViewFormat(CodeLine As String, FileName As String)
        ' Identify any data formatting within views due to risk of DoS and data corruption
        '=================================================================================


        '== Check for data formatting within views ==
        If ctCodeTracker.IsView = False And CodeLine.Contains("CREATE OR REPLACE VIEW") Then ctCodeTracker.IsView = True

        If ctCodeTracker.IsView = True Then
            If CodeLine.Contains("\") And ((InStr(CodeLine, "\*") <> InStr(CodeLine, "\")) And (InStr(CodeLine, "\\") <> InStr(CodeLine, "\"))) Then
                ctCodeTracker.IsView = False
            ElseIf CodeLine.Contains("TO_CHAR") Or CodeLine.Contains("TRIM(") Or CodeLine.Contains("TO_NUMBER") Or CodeLine.Contains("UPPER(") Or CodeLine.Contains("LOWER(") Then
                frmMain.ListCodeIssue("Data Formatting Within VIEW.", "This can can result in performance issues and can facilitate DoS attacks in any situation where any attacker manages to cause repeated queries against the view. There is also a possibility of data corruption due to mismatch between views and underlying tables.", FileName, CodeIssue.STANDARD, CodeLine)
            End If
        End If

    End Sub


    '======================================================================================
    '== EXTENDED RULESET                                                                 ==
    '== Additional checks appended without altering any pre-existing logic.              ==
    '== Note: modMain passes PL/SQL lines to this module already converted to upper case. ==
    '======================================================================================

    Private Sub CheckWeakCrypto(CodeLine As String, FileName As String)
        ' Identify obsolete algorithms and hard-coded key material in DBMS_CRYPTO calls
        '=============================================================================

        If Regex.IsMatch(CodeLine, "\b(DES_CBC_PKCS5|DES_CBC_NONE|DES_ECB|DES3_ECB|ENCRYPT_DES|ENCRYPT_3DES|ENCRYPT_3DES_2KEY|ENCRYPT_RC4)\b") Then
            frmMain.ListCodeIssue("Obsolete Encryption Algorithm Selected", "DES, Triple-DES and RC4 are obsolete: DES has a 56-bit effective key, Triple-DES has a 64-bit block and is subject to Sweet32 birthday attacks, and RC4 leaks plaintext through keystream bias. Use ENCRYPT_AES256 with an authenticated construction, or Transparent Data Encryption where the requirement is at-rest protection.", FileName, CodeIssue.HIGH, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\b(CHAIN_ECB|ENCRYPT_\w*_ECB)\b") Then
            frmMain.ListCodeIssue("ECB Chaining Mode Selected", "ECB encrypts each block independently, so identical plaintext blocks produce identical ciphertext. Column values that repeat - status codes, national identifiers, small enumerations - are therefore distinguishable in the encrypted column without any key. Use CHAIN_CBC with a random IV, or CHAIN_GCM where available.", FileName, CodeIssue.HIGH, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\b(HASH_MD4|HASH_MD5|HMAC_MD5|HASH_SH1|HMAC_SH1)\b") Then
            frmMain.ListCodeIssue("Broken Hash Algorithm Selected", "MD4, MD5 and SHA-1 are collision-vulnerable and unsuitable for integrity verification or password storage. Use HASH_SH256 or better; for passwords, a fast hash is inappropriate regardless of the algorithm.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\bDBMS_OBFUSCATION_TOOLKIT\b") Then
            frmMain.ListCodeIssue("Use of DBMS_OBFUSCATION_TOOLKIT", "This package is deprecated and offers only DES and Triple-DES. It also has no facility for secure key management. Replace with DBMS_CRYPTO using AES-256, or with Transparent Data Encryption.", FileName, CodeIssue.HIGH, CodeLine)
        End If

        '== Hard-coded key material ==
        If Regex.IsMatch(CodeLine, "\b(KEY|KEY_BYTES|ENCRYPTION_KEY|IV|INITIALIZATION_VECTOR)\b\s*(:=|=>)\s*(UTL_RAW\.CAST_TO_RAW\s*\(\s*')|'[0-9A-F]{16,}'") Then
            frmMain.ListCodeIssue("Hard-Coded Cryptographic Key Or IV", "Key material is embedded in the package body. Any account with SELECT on ALL_SOURCE or DBA_SOURCE - or the ability to read an unwrapped source file - recovers the key and can decrypt every protected column. Store keys outside the database, or use a wallet-backed mechanism such as TDE.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If

        '== Predictable randomness ==
        If Regex.IsMatch(CodeLine, "\bDBMS_RANDOM\b") Then
            frmMain.ListCodeIssue("Use of DBMS_RANDOM For A Security Value", "DBMS_RANDOM is not a cryptographically secure generator and its seed is frequently derived from predictable values. Where the output is used for passwords, tokens, salts or identifiers it is guessable. Use DBMS_CRYPTO.RANDOMBYTES.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

    End Sub

    Private Sub CheckDefinerRights(CodeLine As String, FileName As String)
        ' Identify privilege model issues in stored program units
        '========================================================

        If Regex.IsMatch(CodeLine, "\bCREATE\s+(OR\s+REPLACE\s+)?(PROCEDURE|FUNCTION|PACKAGE|TYPE)\b") And Not Regex.IsMatch(CodeLine, "\bAUTHID\b") Then
            frmMain.ListCodeIssue("Program Unit Defaults To Definer's Rights", "Without an explicit AUTHID clause the unit executes with the privileges of its owner, not the caller. Any SQL injection flaw inside the unit therefore executes with the owner's privileges - typically a schema owner or, in the worst case, SYS. Where the unit builds dynamic SQL, declare AUTHID CURRENT_USER so injected statements run with the caller's lower privilege.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\bAUTHID\s+DEFINER\b") And Regex.IsMatch(CodeLine, "\b(EXECUTE\s+IMMEDIATE|DBMS_SQL|OPEN\s+\w+\s+FOR)\b") Then
            frmMain.ListCodeIssue("Definer's Rights Combined With Dynamic SQL", "A definer's-rights unit which constructs dynamic SQL is the standard Oracle privilege escalation pattern: an injection flaw in the concatenated statement executes with the owner's privileges. Use bind variables, and DBMS_ASSERT for identifiers that cannot be bound.", FileName, CodeIssue.HIGH, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "\bPRAGMA\s+AUTONOMOUS_TRANSACTION\b") Then
            frmMain.ListCodeIssue("Autonomous Transaction Declared", "An autonomous transaction commits independently of the caller. This is legitimate for audit logging, but it also allows a unit to persist changes that the calling transaction subsequently rolls back, which can be used to bypass business-rule validation and to defeat transactional integrity controls.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

    End Sub

    Private Sub CheckPrivilegeGrants(CodeLine As String, FileName As String)
        ' Identify excessive privilege grants
        '====================================

        If Regex.IsMatch(CodeLine, "\bGRANT\b[^;]*\bTO\s+PUBLIC\b") Then
            frmMain.ListCodeIssue("Privilege Granted To PUBLIC", "A grant to PUBLIC extends the privilege to every database account, including low-privileged application and reporting users. Grant to a named role instead and assign the role explicitly.", FileName, CodeIssue.HIGH, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\bGRANT\b[^;]*\b(DBA|ALL\s+PRIVILEGES|SYSDBA|SYSOPER|EXECUTE\s+ANY\s+PROCEDURE|SELECT\s+ANY\s+TABLE|CREATE\s+ANY\s+\w+|ALTER\s+ANY\s+\w+|DROP\s+ANY\s+\w+|BECOME\s+USER|GRANT\s+ANY\s+\w+)\b") Then
            frmMain.ListCodeIssue("Excessive System Privilege Granted", "An ANY-class or administrative privilege is granted. These privileges cross schema boundaries: SELECT ANY TABLE reads every table in the database including audit tables, and CREATE ANY PROCEDURE combined with a definer's-rights unit is a direct route to SYS. Grant object-level privileges to a role instead.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\bWITH\s+(GRANT|ADMIN)\s+OPTION\b") Then
            frmMain.ListCodeIssue("Privilege Granted With Delegation Rights", "The grantee can pass the privilege on to other accounts, so the effective privilege graph cannot be reasoned about from the original grant and revocation cascades unpredictably.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\bIDENTIFIED\s+BY\s+\w+") And Not Regex.IsMatch(CodeLine, "\bIDENTIFIED\s+BY\s+VALUES\b") Then
            frmMain.ListCodeIssue("Hard-Coded Account Password In Script", "A password appears in a CREATE USER, ALTER USER or CONNECT statement. Scripts of this kind end up in version control, in shell history and in the V$SQL views, where the password is readable by anyone with SELECT on the dictionary.", FileName, CodeIssue.HIGH, CodeLine)
        End If

    End Sub

    Private Sub CheckNetworkPackages(CodeLine As String, FileName As String)
        ' Identify outbound network access and data exfiltration primitives
        '==================================================================

        If Regex.IsMatch(CodeLine, "\b(UTL_HTTP|UTL_TCP|UTL_SMTP|UTL_INADDR|UTL_URL|DBMS_LDAP|HTTPURITYPE)\b") Then
            frmMain.ListCodeIssue("Outbound Network Access From The Database", "These packages allow the database to originate arbitrary network connections. In an injection scenario they are the standard exfiltration channel - UTL_HTTP.REQUEST with a concatenated query result sends data straight to an attacker-controlled host, and UTL_INADDR does the same over DNS. Revoke EXECUTE from PUBLIC and restrict access with a network ACL.", FileName, CodeIssue.HIGH, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\b(UTL_FILE|DBMS_LOB\.FILEOPEN|BFILENAME)\b") Then
            frmMain.ListCodeIssue("Server-Side File Access", "The database reads or writes files on the server filesystem with the privileges of the Oracle software owner. Where the path or directory object is influenced by user input this permits arbitrary file read and write on the host. Restrict the directory objects and never build the filename from unvalidated data.", FileName, CodeIssue.HIGH, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\b(DBMS_SCHEDULER|DBMS_JOB|CREATE_JOB|SUBMIT)\b") And Regex.IsMatch(CodeLine, "\b(EXECUTABLE|EXTERNAL_SCRIPT|BACKUP_SCRIPT|SQL_SCRIPT)\b") Then
            frmMain.ListCodeIssue("Operating System Command Execution Via The Scheduler", "A scheduler job of type EXECUTABLE or EXTERNAL_SCRIPT runs an operating system command on the database host. This is a well-established privilege escalation path from database access to host compromise. Restrict CREATE JOB and the credential objects used by such jobs.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\b(DBMS_JAVA|JAVA_ADMIN|DBMS_JAVA_TEST|SYS\.KUPP\$PROC|DBMS_XMLGEN\.GETXML|DBMS_XMLQUERY)\b") Then
            frmMain.ListCodeIssue("Use of a Package With Known Escalation Potential", "DBMS_JAVA can grant filesystem and socket permissions to the invoking user, and DBMS_XMLGEN/DBMS_XMLQUERY execute SQL supplied as a string and have been used to escalate privilege from a definer's-rights context. Confirm that EXECUTE on this package is not granted to application accounts.", FileName, CodeIssue.HIGH, CodeLine)
        End If

    End Sub

    Private Sub CheckDynamicSqlAssertion(CodeLine As String, FileName As String)
        ' Identify dynamic SQL that lacks input validation
        '=================================================

        If Regex.IsMatch(CodeLine, "\bDBMS_SQL\.(PARSE|EXECUTE)\b") And Not Regex.IsMatch(CodeLine, "\bBIND_VARIABLE\b") Then
            frmMain.ListCodeIssue("DBMS_SQL Statement Parsed Without Bind Variables", "The statement is parsed without any accompanying BIND_VARIABLE call on this line. Concatenated values are then interpreted as SQL, permitting injection. Bind every value; identifiers that cannot be bound must be passed through DBMS_ASSERT.", FileName, CodeIssue.HIGH, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "\b(EXECUTE\s+IMMEDIATE|OPEN\s+\w+\s+FOR)\b") And CodeLine.Contains("||") And Not Regex.IsMatch(CodeLine, "\bDBMS_ASSERT\b") Then
            frmMain.ListCodeIssue("Concatenated Dynamic SQL Without DBMS_ASSERT", "The statement is assembled with the concatenation operator and no DBMS_ASSERT call is present. Where any concatenated element originates outside the unit this is SQL injection. Use bind variables for values, and DBMS_ASSERT.SIMPLE_SQL_NAME, QUALIFIED_SQL_NAME or ENQUOTE_LITERAL for identifiers and literals.", FileName, CodeIssue.HIGH, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "\bDBMS_ASSERT\.NOOP\b") Then
            frmMain.ListCodeIssue("DBMS_ASSERT.NOOP Provides No Validation", "NOOP returns its argument unchanged and exists only to document that validation was consciously skipped. It offers no protection whatsoever against injection.", FileName, CodeIssue.HIGH, CodeLine)
        End If

    End Sub

    Private Sub CheckExceptionSuppression(CodeLine As String, FileName As String)
        ' Identify exception handlers that discard failures
        '==================================================

        If Regex.IsMatch(CodeLine, "\bWHEN\s+OTHERS\s+THEN\b") And Regex.IsMatch(CodeLine, "\b(NULL\s*;|RETURN\s*;)") Then
            frmMain.ListCodeIssue("Exception Silently Discarded", "A WHEN OTHERS handler which does nothing but return suppresses every error, including constraint violations, privilege failures and cryptographic errors. The unit then reports success while having performed no work, and no evidence remains for incident response. Log the error with SQLERRM and DBMS_UTILITY.FORMAT_ERROR_BACKTRACE, then re-raise.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\bWHEN\s+OTHERS\s+THEN\b") And Not Regex.IsMatch(CodeLine, "\b(RAISE|RAISE_APPLICATION_ERROR)\b") Then
            frmMain.ListCodeIssue("WHEN OTHERS Handler Without Re-Raise", "The handler catches every exception. Confirm that it re-raises or converts the error rather than allowing the caller to proceed as though the operation had succeeded.", FileName, CodeIssue.LOW, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\bRAISE_APPLICATION_ERROR\b") And Regex.IsMatch(CodeLine, "\b(SQLERRM|DBMS_UTILITY\.FORMAT_ERROR)\b") Then
            frmMain.ListCodeIssue("Internal Error Detail Returned To The Caller", "SQLERRM output frequently contains object names, constraint names and fragments of the failing statement. Returning it to a client discloses schema structure that assists an attacker in constructing injection payloads. Return a generic message and log the detail server-side.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

    End Sub

    Private Sub CheckAuditAndSensitiveData(CodeLine As String, FileName As String)
        ' Identify sensitive data handling and audit trail issues
        '========================================================

        If Regex.IsMatch(CodeLine, "\bDBMS_OUTPUT\.PUT_LINE\b") And Regex.IsMatch(CodeLine, "\b\w*(PASSWORD|PASSWD|PWD|SECRET|TOKEN|SSN|CARD|CVV|ACCOUNT_NO)\w*\b") Then
            frmMain.ListCodeIssue("Sensitive Value Written To DBMS_OUTPUT", "The value is written to the server output buffer, where it is visible to any client attached to the session and is frequently captured into deployment logs.", FileName, CodeIssue.HIGH, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\b(NOAUDIT|AUDIT\s+\w+\s+BY\s+\w+\s+WHENEVER\s+NOT\s+SUCCESSFUL)\b") Then
            frmMain.ListCodeIssue("Audit Coverage Reduced", "The statement removes or narrows audit coverage. Auditing only unsuccessful attempts hides the actions of an attacker who has already obtained valid credentials, which is the case in most real incidents.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\bWRAP\b") Or Regex.IsMatch(CodeLine, "\bDBMS_DDL\.(WRAP|CREATE_WRAPPED)\b") Then
            frmMain.ListCodeIssue("Source Code Obfuscation In Use", "Wrapped PL/SQL is obfuscated, not encrypted, and unwrapping tools are freely available. Wrapping must not be relied upon to protect embedded credentials or business logic, and it prevents security review of the unit.", FileName, CodeIssue.LOW, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\bALTER\s+SESSION\s+SET\s+(SQL_TRACE|EVENTS|CURRENT_SCHEMA)\b") Then
            frmMain.ListCodeIssue("Session Attribute Modified At Runtime", "Altering the current schema changes name resolution for every subsequent unqualified object reference, which can silently redirect statements to attacker-created objects. Enabling tracing writes bind values, including credentials, to trace files on the server.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

    End Sub
End Module
