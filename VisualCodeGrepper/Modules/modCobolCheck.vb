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

Module modCobolCheck

    ' Specific checks for COBOL code
    '===============================

    Public Sub CheckCobolCode(CodeLine As String, FileName As String)
        ' Carry out any specific checks for the language in question
        '===========================================================

        CheckIdentificationDivision(CodeLine, FileName) ' Check that filename matches program identifier
        TrackVarAssignments(CodeLine, FileName)         ' Check for matching new/delete, etc.
        CheckCICS(CodeLine, FileName)                   ' Determine whether inside or outside of CICS block and examine any operations inside the block
        CheckSQL(CodeLine, FileName)                    ' Determine whether inside or outside of SQL block and examine any operations inside the block
        CheckBuffer(CodeLine, FileName)                 ' Track buffer sizes and check for overflows
        CheckSigned(CodeLine, FileName)                 ' Check for signed/unsigned integer comparisons
        CheckInputValidation(CodeLine, FileName)        ' How is input being handled before display/storage?
        CheckFileAccess(CodeLine, FileName)             ' Are sensitive variables stored insecurely?
        CheckLogDisplay(CodeLine, FileName)             ' Is data sanitised before being written to logs?
        CheckFileRace(CodeLine, FileName)               ' Check for race conditions and TOCTOU vulns
        CheckRandomisation(CodeLine, FileName)          ' Locate any use of randomisation functions that are not cryptographically secure
        CheckUnsafeTempFiles(CodeLine, FileName)        ' Check for static/obvious filenames for temp files
        CheckDynamicCall(CodeLine, FileName)            ' Identify any user controlled variables used for dynamic function calls

        '== Extended ruleset ==
        CheckCobolHardcodedCredentials(CodeLine, FileName)  ' Credentials in WORKING-STORAGE, MOVE and SQL CONNECT
        CheckCobolDynamicSql(CodeLine, FileName)           ' PREPARE/EXECUTE IMMEDIATE and STRING-built statements
        CheckCobolCicsSecurity(CodeLine, FileName)         ' Dynamic LINK/XCTL/START, spool interface, storage and RESP
        CheckCobolDataHandling(CodeLine, FileName)         ' REDEFINES, SIZE ERROR, reference modification, OCCURS DEPENDING
        CheckCobolFileStatus(CodeLine, FileName)           ' File operations without inline status checking
        CheckCobolSensitiveDisplay(CodeLine, FileName)     ' Sensitive fields written to logs, terminals and reports
        CheckCobolSystemInterface(CodeLine, FileName)      ' System service calls, dynamic CALL and ACCEPT sources

        If Regex.IsMatch(CodeLine, "(LOWER|UPPER)\-CASE\s*\(\S*(Password|password|PASSWORD|pwd|PWD|passwd|PASSWD)") Then
            frmMain.ListCodeIssue("Unsafe Password Management", "The application appears to handle passwords in a case-insensitive manner. This can greatly increase the likelihood of successful brute-force and/or dictionary attacks.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

    End Sub

    Private Sub CheckIdentificationDivision(CodeLine As String, FileName As String)
        ' The Identification Division of a COBOL program should ideally contain only one PROGRAM-ID for maintainability
        '==============================================================================================================
        Dim arrFragments As String() = {}
        Dim strID As String = ""
        Dim strFile As String = ""
        Dim strExtension As String = ""


        ' Do we have a PROGRAM-ID?
        If ((ctCodeTracker.ProgramId = "") And (Regex.IsMatch(CodeLine, "PROGRAM-ID\.\s+\w+") Or Regex.IsMatch(CodeLine, "PROGRAM-ID\s+\w+"))) Then

            ' Record the ID
            If Regex.IsMatch(CodeLine, "PROGRAM-ID\.\s+\w+") Then
                arrFragments = Regex.Split(CodeLine, "PROGRAM-ID\.\s+")
            ElseIf Regex.IsMatch(CodeLine, "PROGRAM-ID\s+\w+") Then
                arrFragments = Regex.Split(CodeLine, "PROGRAM-ID\s+")
            End If

            If arrFragments.Length = 0 Then
                Exit Sub
            ElseIf arrFragments.Length = 1 Then
                strID = GetFirstItem(arrFragments.Last)
                ctCodeTracker.ProgramId = strID.Trim(".")
            ElseIf arrFragments.Length > 1 Then
                strID = GetFirstItem(arrFragments(1))
                ctCodeTracker.ProgramId = strID.Trim(".")
            End If


            ' Does the ID match the filename?
            arrFragments = FileName.Split(".")
            strFile = arrFragments.First
            strExtension = arrFragments.Last
            arrFragments = strFile.Split("\")
            strFile = arrFragments.Last
            If strFile.ToLower <> ctCodeTracker.ProgramId.ToLower Then

                ' Has the filename been used as the ID?
                If ctCodeTracker.ProgramId.Contains(".") And (strFile.ToLower + "." + strExtension.ToLower = ctCodeTracker.ProgramId.ToLower) Then
                    frmMain.ListCodeIssue("PROGRAM-ID Includes File Extension", "The PROGRAM-ID is the filename plus its extension. This is a slight violation of convention as the filename should be based on the PROGRAM-ID, not the reverse.", FileName, CodeIssue.LOW, CodeLine)
                Else
                    frmMain.ListCodeIssue("Filename Does Not Match PROGRAM-ID", "The filename does not match PROGRAM-ID which can make code more difficult to read and maintain.", FileName, CodeIssue.LOW, CodeLine)
                End If

            End If
        ElseIf ctCodeTracker.ProgramId <> "" And Regex.IsMatch(CodeLine, "\bPROGRAM-ID\b") Then
            ' Report any instance of multiple IDs
            frmMain.ListCodeIssue("Multiple Use of PROGRAM-ID", "The code has more than one PROGRAM-ID which can make code more difficult to read and maintain (Original ID:" & ctCodeTracker.ProgramId & ").", FileName, CodeIssue.LOW, CodeLine)
        End If

    End Sub

    Private Sub CheckCICS(CodeLine As String, FileName As String)
        ' Track any interaction with CICS applications on z/OS
        '=====================================================
        Dim strItem As String = ""


        '== Only perform these checks if user has specified IBM zOS code ==
        If Not asAppSettings.IsZOS Then Exit Sub

        '== Check if we already inside an EXEC CICS block ==
        If ctCodeTracker.IsInsideCICS Then
            If Regex.IsMatch(CodeLine, "\bEND\b\-\bEXEC\b\s*\.") Then
                ctCodeTracker.IsInsideCICS = False
            ElseIf (Regex.IsMatch(CodeLine, "s+\bSEND\b\s+") And Regex.IsMatch(CodeLine, "s+\b(MAP|FROM|CURSOR)\b")) Then
                frmMain.ListCodeIssue("Redirection of Output From CICS Application", "The code appears to send output to an external CICS application. Manually check to ensure that no privacy violation is occurring.", FileName, CodeIssue.HIGH, CodeLine)
            ElseIf (Regex.IsMatch(CodeLine, "s+\bSEND\b\s+")) Then
                For Each strItem In ctCodeTracker.DicPICs.Keys
                    If (strItem <> "" And (Regex.IsMatch(CodeLine, "s+\b" + strItem + "\b\s+"))) Then
                        frmMain.ListCodeIssue("Redirection of Output From CICS Application", "The code appears to send program data to an external CICS application. Manually check to ensure that no privacy violation is occurring.", FileName, CodeIssue.HIGH, CodeLine)
                    End If
                Next
            ElseIf Regex.IsMatch(CodeLine, "\s+(ACCEPT|LOSE|DELETE|DISPLAY\s+UPON\s+CONSOLE|DISPLAY\s+UPON\s+SYSPUNCH|MERGE|OPEN|READ|RERUN|REWRITE|START|WRITE)\s+") Then
                frmMain.ListCodeIssue("Use of Unsafe Command within CICS", "The code appears to use a command which is unsafe when running under CICS (See IBM references).", FileName, CodeIssue.STANDARD, CodeLine)
            Else
                For Each strVar In ctCodeTracker.InputVars
                    If CodeLine.Contains(strVar) Then
                        frmMain.ListCodeIssue("User Controlled Variable Used within CICS Block", "The code appears to allow the use of a variable from JCL or user input, when interacting with an external CICS application: " & strVar & ". Manually check to ensure the parameter is used safely.", FileName, CodeIssue.MEDIUM, CodeLine)
                    End If
                Next
            End If
        Else
            ' Check if entering a CICS block and change status if necessary
            If Regex.IsMatch(CodeLine, "\bEXEC\b\s+\bCICS\b") Then
                ctCodeTracker.IsInsideCICS = True
            End If
        End If

    End Sub

    Private Sub CheckSQL(CodeLine As String, FileName As String)
        ' Track any use of user defined variables in SQL statements
        '==========================================================

        '== Check if we already inside an EXEC SQL block ==
        If ctCodeTracker.IsInsideSQL Then
            If Regex.IsMatch(CodeLine, "\bEND\b\-\bEXEC\b\s*\.") Then
                ctCodeTracker.IsInsideSQL = False
            Else
                For Each strVar In ctCodeTracker.InputVars
                    If CodeLine.Contains(strVar) Then
                        frmMain.ListCodeIssue("User Controlled Variable Used within SQL Statement", "The code appears to allow the use of a variable from JCL or user input, when executing a SQL statement: " & strVar & ". Manually check to ensure the parameter is used safely.", FileName, CodeIssue.HIGH, CodeLine)
                    End If
                Next
            End If
        Else
            ' Check if entering an EXEC SQL block and change status if necessary
            If Regex.IsMatch(CodeLine, "\bEXEC\b\s+\bSQL\b") Then
                ctCodeTracker.IsInsideSQL = True
            End If
        End If

    End Sub

    Private Sub TrackVarAssignments(CodeLine As String, FileName As String)
        ' Track the input and allocation of user-supplied variables
        '==========================================================
        Dim strVar As String = ""
        Dim strCalc As String = ""
        Dim strVarCollections As String = ""
        Dim strTemp As String = ""

        Dim strAssignments As String()
        Dim strFragments As String()


        '== Keep track of variables and constants to help with detection of buffer overflows, mis-matched types, etc. ==
        If (Regex.IsMatch(CodeLine, "[\w-]+\s+\bPIC\b") And Not Regex.IsMatch(CodeLine, "\bFILLER\b\s+\bPIC\b")) Then

            '== Track PIC variables ==
            ctCodeTracker.AddPIC(CodeLine)

        ElseIf Regex.IsMatch(CodeLine, "\bACCEPT\b\s+\w+") Then

            '== Extract variable name from any line that gets user input ==
            strAssignments = Regex.Split(CodeLine, "\bACCEPT\b")

            If strAssignments.Length > 1 Then
                strTemp = strAssignments(1).TrimEnd(".")

                '== Track user-controlled variables ==
                strVar = GetFirstItem(strTemp)
                If Regex.IsMatch(strVar, "^[a-zA-Z0-9_-]+$") And Not ctCodeTracker.InputVars.Contains(strVar) Then ctCodeTracker.InputVars.Add(strVar)
            End If
        ElseIf Regex.IsMatch(CodeLine, "\bCOMPUTE\b\s+\w+\s*=\s*\w+") Then

            ' If a new variable is allocated then check if it is derived from any user-supplied variables
            strAssignments = Regex.Split(CodeLine, "\bCOMPUTE\b\s+\w+\s*=")
            strVarCollections = strAssignments.Last.Trim

            If strVarCollections = "" Then Exit Sub

            ' Cycle though input vars to see if they're on the right side of the = sign
            For Each strItem In ctCodeTracker.InputVars
                If Regex.IsMatch(strVarCollections, "\b" & strItem & "\b") Then
                    ' If we have an input var then extract the left of the = sign
                    strFragments = Regex.Split(CodeLine, "=")
                    strVar = GetLastItem(strFragments.First)
                    strCalc = strFragments.Last.Trim()
                    If strCalc.Contains(strItem) Then
                        If Regex.IsMatch(strVar, "^[a-zA-Z0-9_-]+$") And Not ctCodeTracker.InputVars.Contains(strVar) Then ctCodeTracker.InputVars.Add(strVar)
                    End If
                    Exit For
                End If
            Next

        End If

    End Sub

    Private Sub CheckBuffer(CodeLine As String, FileName As String)
        ' Keep record of pointer/buffer assignments and add to the CodeTracker dictionary for checking
        ' Check any pointer and buffer manipulation fo overflows, out-of-bounds reads, etc.
        '=============================================================================================
        Dim strSourceVar As String = ""
        Dim strDestVar As String = ""

        Dim intSourceLength As Integer = 0

        Dim strFragments As String()

        If Regex.IsMatch(CodeLine, "\bPOINTER\b") Then

        ElseIf Regex.IsMatch(CodeLine, "\bSET\b") Then

        ElseIf Regex.IsMatch(CodeLine, "\bMOVE\b\s+[\w-]+\s+\bTO\b\s+[\w-]+") Then

            '== Check whether we are moving one PIC variable to another ==
            strFragments = Regex.Split(CodeLine, "\s+\bTO\b\s+")
            strSourceVar = GetLastItem(strFragments(0))
            strDestVar = GetFirstItem(strFragments(1))

        ElseIf Regex.IsMatch(CodeLine, "\bMOVE\b\s+\w+\s*\(\s*[\w-]+\s*\:\s*[\w-]+\s*\)\s*\bTO\b\s+[\w-]+") Then

        ElseIf Regex.IsMatch(CodeLine, "\bMOVE\b\s+[\w-]+\s*\bTO\b\s+\w+\s*\(\s*[\w-]+\s*\:\s*[\w-]+\s*\)") Then

            '== Check whether string is longer than destination ==
            strFragments = Regex.Split(CodeLine, "\s+\bTO\b\s+")
            strSourceVar = GetLastItem(strFragments(0))
            If strSourceVar.Length() >= 2 Then intSourceLength = strSourceVar.Length() - 2
            strDestVar = GetFirstItem(strFragments(1))

        ElseIf Regex.IsMatch(CodeLine, "\bMOVE\b\s+('|"")[\w-]+('|"")\s*\bTO\b\s+[\w-]+") Then



        End If

        If (intSourceLength > 0 And strDestVar <> "") Then
            If intSourceLength > ctCodeTracker.DicPICs(strDestVar).Length Then
                frmMain.ListCodeIssue("PIC Length Mismatch", "The code appears to copy a PIC variable to a destination that is shorter than the source PIC. This can cause unexpected behaviour or results.", FileName, CodeIssue.HIGH, CodeLine)
            End If
        ElseIf (strSourceVar <> "" And strDestVar <> "") Then

            If (ctCodeTracker.DicPICs.ContainsKey(strSourceVar) And (ctCodeTracker.DicPICs.ContainsKey(strDestVar))) Then
                If ctCodeTracker.DicPICs(strSourceVar).Length > ctCodeTracker.DicPICs(strDestVar).Length Then
                    frmMain.ListCodeIssue("PIC Length Mismatch", "The code appears to copy a PIC variable to a destination that is shorter than the source PIC. This can cause unexpected behaviour or results.", FileName, CodeIssue.HIGH, CodeLine)
                End If
            End If
        End If

    End Sub

    Private Sub CheckSigned(CodeLine As String, FileName As String)
        ' Keep record of unsigned int assignments and add to CodeTracker dictionary
        ' Identify any signed/unsigned comparisons
        '==========================================================================
        Dim strSourceVar As String = ""
        Dim strDestVar As String = ""
        Dim strFragments As String()


        '== Identify any unsigned integers ==
        If Regex.IsMatch(CodeLine, "\bUNSIGNED\b") Then
            ctCodeTracker.AddUnsigned(CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "\bMOVE\b\s+[\w-]+\s+\bTO\b\s+[\w-]+") Then

            '== Check whether we are moving one PIC variable to another ==
            strFragments = Regex.Split(CodeLine, "\s\bTO\b\s")
            strSourceVar = GetLastItem(strFragments(0))
            strDestVar = GetFirstItem(strFragments(1))

            If (strSourceVar <> "" And strDestVar <> "") Then

                If (ctCodeTracker.DicPICs.ContainsKey(strSourceVar) And (ctCodeTracker.DicPICs.ContainsKey(strDestVar))) Then
                    If ctCodeTracker.DicPICs(strSourceVar).IsSigned And Not ctCodeTracker.DicPICs(strDestVar).IsSigned Then
                        frmMain.ListCodeIssue("PIC Sign Mismatch", "The code appears to copy a PIC variable to a destination PIC variable but only one of them is signed. This can cause unexpected behaviour or results.", FileName, CodeIssue.HIGH, CodeLine)
                    ElseIf (Not ctCodeTracker.DicPICs(strSourceVar).IsNumeric) And ctCodeTracker.DicPICs(strDestVar).IsNumeric Then
                        frmMain.ListCodeIssue("PIC Mismatch", "The code appears to copy an alphanumeric PIC variable to a numeric PIC variable. This can cause a loss of sign for types intended to be signed numeric, and unexpected behaviour or results.", FileName, CodeIssue.HIGH, CodeLine)
                    End If
                End If
            End If

        ElseIf (CodeLine.Contains("=") Or CodeLine.Contains("<") Or CodeLine.Contains(">") Or CodeLine.Contains(" NE ")) Then
            '== Check for signed/unsigned integer comparisons ==
            If ctCodeTracker.CheckCOBOLSignedComp(CodeLine) Then frmMain.ListCodeIssue("Signed/Unsigned Comparison", "The code appears to compare a signed numeric value with an unsigned numeric value. This behaviour can return unexpected results as negative numbers will be forcibly cast to large positive numbers.", FileName, CodeIssue.HIGH, CodeLine)
        End If

    End Sub

    Public Sub AddUnsigned(CodeLine As String)
        ' Take the variable name and its details and add them to the list
        '================================================================
        Dim strDescription As String = ""
        Dim strVarType As String = "unsigned"

    End Sub

    Private Sub CheckInputValidation(CodeLine As String, FileName As String)

    End Sub

    Private Sub CheckFileAccess(CodeLine As String, FileName As String)
        ' Check whether user input is being used to open files
        '=====================================================
        Dim strVar As String = ""

        If Regex.IsMatch(CodeLine, "\bOPEN\b\s+\w+") Then
            ' Cycle though input vars to see if they're on the right side of the = sign
            For Each strItem In ctCodeTracker.InputVars
                If Regex.IsMatch(CodeLine, "\bOPEN\b\s+\w*" & strItem) Then
                    frmMain.ListCodeIssue("User Controlled File/Directory Name", "The code uses a user-controlled value when opening a file/directory. Manually inspect the code to ensure safe usage.", FileName, CodeIssue.LOW, CodeLine)
                    Exit For
                End If
            Next
        End If

    End Sub

    Private Sub CheckLogDisplay(CodeLine As String, FileName As String)
        ' Check output written to logs is sanitised first and check for logged passwords
        '===============================================================================
        Dim strLogCodeLine As String = CodeLine

        strLogCodeLine = strLogCodeLine.ToLower

        If Regex.IsMatch(strLogCodeLine, "validate|encode|sanitize|sanitise") And Not strLogCodeLine.Contains("password") Then Exit Sub

        If Regex.IsMatch(CodeLine, "logerror|logger|logging|\blog\b") And CodeLine.Contains("password") Then
            If (InStr(strLogCodeLine, "log") < InStr(strLogCodeLine, "password")) Then frmMain.ListCodeIssue("Application Appears to Log User Passwords", "The application appears to write user passwords to logfiles creating a risk of credential theft.", FileName, CodeIssue.HIGH, CodeLine)
        ElseIf Regex.IsMatch(strLogCodeLine, "logerror|logger|logging|\blog\b") Then
            For Each strVar In ctCodeTracker.InputVars
                If CodeLine.Contains(strVar) Then
                    frmMain.ListCodeIssue("Unsanitized Data Written to Logs", "The application appears to write unsanitized data to its logfiles. If logs are viewed by a browser-based application this exposes risk of XSS attacks.", FileName, CodeIssue.MEDIUM, CodeLine)
                    Exit For
                End If
            Next
        End If

    End Sub

    Private Sub CheckFileRace(CodeLine As String, FileName As String)
        ' Check for potential TOCTOU/race conditions
        '===========================================

        Dim intSeverity As Integer = 0  ' For TOCTOU vulns, severity will be modified according to length of time between check and usage.


        '== Check for TOCTOU (Time Of Check, Time Of Use) vulnerabilities==
        If (Not ctCodeTracker.IsLstat) And (Regex.IsMatch(CodeLine, "\bCALL\b\s+'CBL_CHECK_FILE_EXIST'")) Then
            ' Check has taken place - begin monitoring for use of the file/dir
            ctCodeTracker.IsLstat = True
        ElseIf ctCodeTracker.IsLstat Then
            ' Increase line count while monitoring
            If CodeLine.Trim <> "" Then
                ctCodeTracker.TocTouLineCount += 1
            End If

            If ctCodeTracker.TocTouLineCount < 2 And Regex.IsMatch(CodeLine, "\bOPEN\b") Then
                ' Usage takes place almost immediately so no problem
                ctCodeTracker.IsLstat = False
            ElseIf ctCodeTracker.TocTouLineCount > 1 And Regex.IsMatch(CodeLine, "\bOPEN\b") Then
                ' Usage takes place sometime later. Set severity accordingly and notify user
                ctCodeTracker.IsLstat = False
                If ctCodeTracker.TocTouLineCount > 5 Then intSeverity = 2
                frmMain.ListCodeIssue("Potential TOCTOU (Time Of Check, Time Of Use) Vulnerability", "The check for the file's existence occurs " & ctCodeTracker.TocTouLineCount & " lines before the file/directory is accessed. The longer the time between the check and the OPEN call, the greater the likelihood that the check will no longer be valid.", FileName)
            End If
        End If

    End Sub

    Private Sub CheckRandomisation(CodeLine As String, FileName As String)
        ' Check for any random functions that are not cryptographically secure
        '=====================================================================

        '== Check for unsafe functions ==
        If (Regex.IsMatch(CodeLine, "\bRANDOM\b") And Not (Regex.IsMatch(CodeLine, "\bIS\b\s+\bRANDOM\b")) And Not (Regex.IsMatch(CodeLine, "\-RANDOM")) And Not (Regex.IsMatch(CodeLine, "RANDOM\-"))) Then
            frmMain.ListCodeIssue("Use of Deterministic Pseudo-Random Values", "The code appears to use the RANDOM function. The resulting values, while appearing random to a casual observer, are predictable and may be enumerated by a skilled and determined attacker.", FileName, CodeIssue.STANDARD, CodeLine)
        End If

    End Sub

    Private Sub CheckUnsafeTempFiles(CodeLine As String, FileName As String)
        ' Check for attempts to open temp files with obvious names
        '=========================================================

        '== Check for unsafe functions ==
        If Regex.IsMatch(CodeLine, "\bOPEN\b\s+\w+\s+\S*(?i)temp") Then
            frmMain.ListCodeIssue("Unsafe Temporary File Allocation", "The application appears to create a temporary file with a static, hard-coded name. This causes security issues in the form of a classic race condition (an attacker or other application creates a file with the same name between the application's creation and attempted usage).", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

    End Sub

    Private Sub CheckDynamicCall(CodeLine As String, FileName As String)
        ' Check for dynamic function calls
        '=================================
        Dim blnIsFound As Boolean = False


        '== Check for sanitisation of variables ==
        'If Regex.IsMatch(CodeLine, "validate|encode|sanitize|sanitise") Then Exit Sub

        '== Check for function calls ==
        If Regex.IsMatch(CodeLine, ".\bCALL\b\s+('|"")\w+('|"")\s+\bUSING\b") Then

            ' If it's a static call check for user-supplied arguments
            For Each strVar In ctCodeTracker.InputVars
                If CodeLine.Contains(strVar) Then
                    frmMain.ListCodeIssue("User Controlled Variable Used as Parameter for Application Call", "The code appears to allow the use of an unvalidated user-controlled variable when executing an application call: " & strVar & ". Manually check to ensure the parameter is used safely.", FileName, CodeIssue.LOW, CodeLine)
                End If
            Next

        ElseIf Regex.IsMatch(CodeLine, ".\bCALL\b\s+\w+\s+\bUSING\b") Then

            ' If it's a dynamic function call check for user controlled function name
            For Each strVar In ctCodeTracker.InputVars
                If Regex.IsMatch(CodeLine, ".\bCALL\b\s+" & strVar & "\s+\bUSING\b") Then
                    frmMain.ListCodeIssue("User Controlled Variable From JCL Used for Dynamic Function Call", "The code appears to allow the use of an unvalidated user-controlled variable when executing a dynamic application call.", FileName, CodeIssue.HIGH, CodeLine)
                    blnIsFound = True
                    Exit For
                End If
            Next
            If blnIsFound = False Then
                frmMain.ListCodeIssue("Dynamic Function Call", "The code appears to allow the use of an unvalidated variable when executing a dynamic application call. Carry out a manual check to determine whether the variable is user-controlled.", FileName, CodeIssue.MEDIUM, CodeLine)
            End If
        End If
    End Sub


    '======================================================================================
    '== EXTENDED RULESET                                                                 ==
    '== Additional checks appended without altering any pre-existing logic.              ==
    '======================================================================================

    Private Sub CheckCobolHardcodedCredentials(CodeLine As String, FileName As String)
        ' Identify credentials embedded in WORKING-STORAGE or MOVE statements
        '====================================================================

        If Regex.IsMatch(CodeLine, "(?i)\b(MOVE|VALUE)\b[^\.]*['""][^'""]{3,}['""][^\.]*\bTO\b[^\.]*\b\w*(PASSWORD|PASSWD|PWD|USERID|USER-ID|SECRET|KEY|TOKEN|CREDENTIAL)\w*\b") Or _
           Regex.IsMatch(CodeLine, "(?i)\b\w*(PASSWORD|PASSWD|PWD|SECRET|APIKEY|TOKEN)\w*\b[^\.]*\bVALUE\b\s*['""][^'""]{3,}['""]") Then
            frmMain.ListCodeIssue("Hard-Coded Credential In Source", "A credential appears as a literal in WORKING-STORAGE or in a MOVE statement. Literals are retained in the compiled load module and are recoverable with a straightforward dump or browse of the module, so anyone with read access to the load library obtains the credential. Source credentials from a security product such as RACF, ACF2 or Top Secret, or from an external key store.", FileName, CodeIssue.HIGH, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "(?i)\bEXEC\s+SQL\b[^\.]*\bCONNECT\b[^\.]*\bUSING\b") Then
            frmMain.ListCodeIssue("Database Connection Credentials In Source", "An EXEC SQL CONNECT ... USING statement supplies a password. Where the password is a literal or a WORKING-STORAGE item initialised with VALUE it is embedded in the load module; where it is passed in, confirm the source is a protected store and that the field is cleared after use.", FileName, CodeIssue.HIGH, CodeLine)
        End If

    End Sub

    Private Sub CheckCobolDynamicSql(CodeLine As String, FileName As String)
        ' Identify dynamic SQL construction in embedded DB2
        '==================================================

        If Regex.IsMatch(CodeLine, "(?i)\bEXEC\s+SQL\b[^\.]*\b(PREPARE|EXECUTE\s+IMMEDIATE)\b") Then
            frmMain.ListCodeIssue("Dynamic SQL In Embedded DB2", "PREPARE and EXECUTE IMMEDIATE build the statement text at runtime. Where that text is assembled with STRING from input fields rather than parameterised with host variables and placeholders, the input is interpreted as SQL. Use static SQL where the statement shape is fixed, and parameter markers with a bound SQLDA where it is not.", FileName, CodeIssue.HIGH, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "(?i)\bSTRING\b[^\.]*\bDELIMITED\b") And Regex.IsMatch(CodeLine, "(?i)\b\w*(SQL|STMT|STATEMENT|QUERY|WHERE|SELECT)\w*\b") Then
            frmMain.ListCodeIssue("SQL Statement Assembled With STRING", "A statement buffer is built by concatenation. Any input field placed into the buffer without validation alters the statement structure. The absence of quoting helpers in COBOL makes this particularly error-prone; prefer static SQL with host variables.", FileName, CodeIssue.HIGH, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "(?i)\bEXEC\s+SQL\b[^\.]*\bWITH\s+UR\b") Then
            frmMain.ListCodeIssue("Uncommitted Read Isolation Level", "WITH UR reads rows that other units of work have modified but not committed. Where the value read is used for an authorisation or balance decision the decision may be based on data that is subsequently rolled back.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

    End Sub

    Private Sub CheckCobolCicsSecurity(CodeLine As String, FileName As String)
        ' Identify CICS commands with security implications beyond the existing checks
        '============================================================================

        If Regex.IsMatch(CodeLine, "(?i)\bEXEC\s+CICS\b[^\.]*\b(LINK|XCTL|START)\b") And Regex.IsMatch(CodeLine, "(?i)\bPROGRAM\s*\(\s*[A-Z0-9\-]+\s*\)") And Not Regex.IsMatch(CodeLine, "(?i)PROGRAM\s*\(\s*['""]") Then
            frmMain.ListCodeIssue("Dynamic Program Invocation In CICS", "The program name passed to LINK, XCTL or START is held in a variable. Where that variable can be influenced by terminal input or by a communication area supplied by another transaction, an attacker selects which program executes - within the same task and therefore with the same authority. Validate the name against a fixed table of permitted programs.", FileName, CodeIssue.HIGH, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "(?i)\bEXEC\s+CICS\b[^\.]*\b(SPOOLOPEN|SPOOLWRITE|SPOOLCLOSE)\b") Then
            frmMain.ListCodeIssue("CICS Spool Interface In Use", "The spool interface can submit JCL to the internal reader. A transaction that writes attacker-influenced data to the spool may therefore submit arbitrary batch work, executing under the CICS region's authority rather than the end user's. Restrict the transaction and validate every field written.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "(?i)\bEXEC\s+CICS\b[^\.]*\b(ADDRESS|GETMAIN|FREEMAIN)\b") Then
            frmMain.ListCodeIssue("Direct Storage Manipulation In CICS", "ADDRESS and GETMAIN expose raw storage addresses. Combined with an unchecked length or an index derived from input this permits reads and writes outside the intended area, which in a shared region can corrupt or disclose another transaction's data.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "(?i)\bEXEC\s+CICS\b[^\.]*\b(READ|WRITE|REWRITE|DELETE|STARTBR)\b") And Not Regex.IsMatch(CodeLine, "(?i)\bRESP\s*\(|\bNOHANDLE\b") Then
            frmMain.ListCodeIssue("CICS File Operation Without Response Checking", "No RESP option is present, so the outcome of the file operation is not examined on this line. Where the operation fails - because of a security violation, a missing record or a locked file - processing continues on stale or uninitialised data.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "(?i)\bEXEC\s+CICS\b[^\.]*\bSYNCPOINT\s+ROLLBACK\b") Then
            frmMain.ListCodeIssue("Explicit Rollback Issued", "Confirm that the rollback covers every resource updated in the unit of work. A partial rollback leaves related files inconsistent, which in a financial context is exploitable as well as incorrect.", FileName, CodeIssue.LOW, CodeLine)
        End If

    End Sub

    Private Sub CheckCobolDataHandling(CodeLine As String, FileName As String)
        ' Identify truncation, redefinition and arithmetic issues
        '========================================================

        If Regex.IsMatch(CodeLine, "(?i)\bREDEFINES\b") Then
            frmMain.ListCodeIssue("REDEFINES Clause In Use", "REDEFINES reinterprets the same storage under a different picture. Where the two definitions have incompatible types - alphanumeric over packed decimal, for example - reading through the wrong definition produces values that never underwent validation and may cause an S0C7 abend or silently corrupt a numeric field. Confirm that the active interpretation is always determined by a validated discriminator field.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "(?i)\b(COMPUTE|ADD|SUBTRACT|MULTIPLY|DIVIDE)\b") And Not Regex.IsMatch(CodeLine, "(?i)\b(ON\s+SIZE\s+ERROR|NOT\s+ON\s+SIZE\s+ERROR)\b") Then
            frmMain.ListCodeIssue("Arithmetic Without ON SIZE ERROR", "No size-error clause is present. When a result exceeds the receiving field's picture the high-order digits are discarded silently, so a large amount becomes a small one with no diagnostic. In financial processing this is both a correctness defect and an abuse vector where the input value is externally supplied.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "(?i)\bDIVIDE\b") And Not Regex.IsMatch(CodeLine, "(?i)\bON\s+SIZE\s+ERROR\b") Then
            frmMain.ListCodeIssue("Division Without Divide-By-Zero Protection", "A DIVIDE without ON SIZE ERROR abends with S0CB when the divisor is zero. Where the divisor derives from input this is a denial-of-service condition reachable by any user of the transaction.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "(?i)\bEVALUATE\b") And Not Regex.IsMatch(CodeLine, "(?i)\bWHEN\s+OTHER\b") Then
            frmMain.ListCodeIssue("EVALUATE Without A WHEN OTHER Branch", "Confirm that a WHEN OTHER branch exists for this EVALUATE. Without one, an unexpected value - including one supplied by a user or received from an upstream system - falls through with no action taken, leaving the program in an undefined state while appearing to succeed.", FileName, CodeIssue.LOW, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "(?i)\bMOVE\b[^\.]*\bREFERENCE\s+MODIFICATION\b") Or Regex.IsMatch(CodeLine, "\w+\s*\(\s*\w+\s*:\s*\w+\s*\)") Then
            frmMain.ListCodeIssue("Reference Modification With Variable Offset Or Length", "Reference modification of the form FIELD(OFFSET:LENGTH) is not bounds-checked by default. A variable offset or length derived from input reads or writes outside the field, which is the closest COBOL equivalent of a buffer overflow. Compile with SSRANGE for testing and validate the subscripts explicitly.", FileName, CodeIssue.HIGH, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "(?i)\bOCCURS\b[^\.]*\bDEPENDING\s+ON\b") Then
            frmMain.ListCodeIssue("Variable-Length Table (OCCURS DEPENDING ON)", "The table length is controlled by another field. Where that field is populated from an input record without range validation the program addresses storage beyond the table, producing corruption or an abend. Validate the controlling field against the declared minimum and maximum before use.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

    End Sub

    Private Sub CheckCobolFileStatus(CodeLine As String, FileName As String)
        ' Identify unchecked file operations
        '===================================

        If Regex.IsMatch(CodeLine, "(?i)^\s*(\d+\s+)?\b(OPEN|CLOSE|READ|WRITE|REWRITE|DELETE|START)\b") And Not Regex.IsMatch(CodeLine, "(?i)\b(EXEC\s+CICS|INVALID\s+KEY|AT\s+END|NOT\s+AT\s+END)\b") Then
            frmMain.ListCodeIssue("File Operation Without An Inline Status Check", "No INVALID KEY or AT END phrase is present on this statement. Unless the FILE STATUS field is examined immediately afterwards, a failed open or read leaves the record area holding the previous record - or uninitialised storage - and processing continues on data that was never read. Declare FILE STATUS on the FD and test it after every operation.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "(?i)\bOPEN\s+(I-O|EXTEND|OUTPUT)\b") Then
            frmMain.ListCodeIssue("File Opened For Update", "The file is opened for write access. Confirm that the dataset is protected by an appropriate RACF profile, that the program genuinely requires update access, and that concurrent access is controlled - COBOL does not serialise access for you.", FileName, CodeIssue.LOW, CodeLine)
        End If

    End Sub

    Private Sub CheckCobolSensitiveDisplay(CodeLine As String, FileName As String)
        ' Identify sensitive data written to logs, terminals or reports
        '==============================================================

        If Regex.IsMatch(CodeLine, "(?i)\b(DISPLAY|EXEC\s+CICS\s+SEND|WRITE)\b") And _
           Regex.IsMatch(CodeLine, "(?i)\b\w*(PASSWORD|PASSWD|PWD|SECRET|TOKEN|PIN|CVV|CARD-NO|CARDNO|ACCT-NO|SSN|NATIONAL-ID)\w*\b") Then
            frmMain.ListCodeIssue("Sensitive Field Written To Output", "A field whose name indicates sensitive content is written to the terminal, the job log or a report. Job logs are retained on spool, are frequently readable by operations staff and are archived to tape, so the exposure extends far beyond the original transaction. Mask the value or omit it.", FileName, CodeIssue.HIGH, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "(?i)\bDISPLAY\b") And Regex.IsMatch(CodeLine, "(?i)\bUPON\s+(CONSOLE|SYSOUT)\b") Then
            frmMain.ListCodeIssue("Output Written To The System Console", "Console messages are visible to all operations staff and are captured in SYSLOG. Confirm that no business data is written to the console.", FileName, CodeIssue.LOW, CodeLine)
        End If

    End Sub

    Private Sub CheckCobolSystemInterface(CodeLine As String, FileName As String)
        ' Identify calls into system services and other programs
        '=======================================================

        If Regex.IsMatch(CodeLine, "(?i)\bCALL\b\s+['""](SYSTEM|BPXWDYN|IEFBR14|IKJEFT01|SYSTEMFUNC|SH)['""]") Then
            frmMain.ListCodeIssue("Call To A System Service", "The program invokes a system service capable of allocating datasets, issuing TSO commands or running a shell. Where any parameter is derived from input this permits arbitrary dataset access or command execution under the job's authority. Validate every parameter against a fixed allow-list.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "(?i)\bCALL\b\s+\w+\s*(USING|$)") And Not Regex.IsMatch(CodeLine, "(?i)\bCALL\b\s*['""]") Then
            frmMain.ListCodeIssue("Dynamic CALL With A Variable Program Name", "The called program is named by a variable, so the target is resolved at runtime from the load library concatenation. An attacker who can influence the variable, or who can place a module earlier in the concatenation, controls which code executes. Validate the name against a fixed table and confirm the load libraries are RACF-protected against update.", FileName, CodeIssue.HIGH, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "(?i)\bCALL\b[^\.]*\b(RACROUTE|IRRSEQ00|IRRSDL00)\b") Then
            frmMain.ListCodeIssue("Direct Security Product Interface", "The program calls the security manager interface directly. Confirm that the return and reason codes are examined for every call - a common defect is to treat any non-abend return as success, which grants access when the check has in fact failed.", FileName, CodeIssue.HIGH, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "(?i)\bACCEPT\b[^\.]*\bFROM\b") Then
            frmMain.ListCodeIssue("Data Accepted From An External Source", "ACCEPT reads from the console, SYSIN or an environment variable. The value is unvalidated and untyped at this point; confirm it is range-checked and class-tested (NUMERIC/ALPHABETIC) before it is used in arithmetic, as a subscript or in a file operation.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

    End Sub
End Module
