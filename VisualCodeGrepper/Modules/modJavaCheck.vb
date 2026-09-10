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

Module modJavaCheck

    Private ctCodeTracker As New CodeTracker()

    ' Specific checks for Java code
    '==============================

    Public Sub CheckJavaCode(CodeLine As String, FileName As String)
        ' Carry out any specific checks for the language in question
        '===========================================================

        ' Is there a struts validator or similar framework in place?
        If ctCodeTracker.HasValidator = False And FileName.ToLower.EndsWith(".xml") And CodeLine.ToLower.Contains("<plug-in") And CodeLine.ToLower.Contains(".validator") Then ctCodeTracker.HasValidator = True

        CheckServlet(CodeLine, FileName)                    ' Check for any issues specific to servlets
        CheckSQLiValidation(CodeLine, FileName)             ' Check for potential SQLi
        CheckXSSValidation(CodeLine, FileName)              ' Check for potential XSS
        CheckRunTime(CodeLine, FileName)                    ' Check use of java.lang.Runtime.exec
        CheckIsHttps(CodeLine, FileName)                    ' Check any URLs being used are not http
        CheckClone(CodeLine, FileName)                      ' Check for unsafe cloning implementation
        CheckSerialize(CodeLine, FileName)                  ' Check for unsafe serialization implementation
        IdentifyServlets(CodeLine)                          ' List any servlet instantiations for the thread checks
        CheckModifiers(CodeLine, FileName)                  ' Check for public variables in classes
        CheckThreadIssues(CodeLine, FileName)               ' Check for good/bad thread management
        CheckUnsafeTempFiles(CodeLine, FileName)            ' Check for temp files with obvious names
        CheckPrivileged(CodeLine, FileName)                 ' Check for potential user access to code with system privileges
        CheckRequestDispatcher(CodeLine, FileName)          ' Check for user control of request dispatcher
        CheckXXE(CodeLine, FileName)               ' Check for safe/unsafe XML expansion
        CheckOverflow(CodeLine, FileName)                   ' Check use of primitive types and any operations upon them
        CheckResourceRelease(CodeLine, FileName)            ' Are file resources safely handled in try ... catch blocks
        CheckInsecureDeserialization(CodeLine, FileName)    ' Check for insecure deserialization vulnerabilities

        '== Extended ruleset ==
        CheckJavaWeakCrypto(CodeLine, FileName)             ' Broken hashes/ciphers, ECB, hard-coded keys, weak randomness
        CheckJavaTrustManager(CodeLine, FileName)           ' Permissive TrustManager/HostnameVerifier and obsolete TLS
        CheckJavaPathTraversal(CodeLine, FileName)          ' User-controlled filesystem paths and Zip Slip
        CheckJavaSSRF(CodeLine, FileName)                   ' User-controlled outbound request destinations
        CheckJavaExpressionInjection(CodeLine, FileName)    ' SpEL/OGNL/MVEL, scripting engines and template injection
        CheckJavaJndiInjection(CodeLine, FileName)          ' JNDI lookups and Log4Shell indicators
        CheckJavaLdapXPath(CodeLine, FileName)              ' LDAP and XPath queries built by concatenation
        CheckSpringSecurityConfig(CodeLine, FileName)       ' CSRF disabled, permitAll, CORS, password encoders, actuators
        CheckJavaJwt(CodeLine, FileName)                    ' Unsigned tokens, 'none' algorithm, hard-coded signing secrets
        CheckJavaDeserializationExtended(CodeLine, FileName) ' XStream, Jackson default typing, SnakeYAML, BeanUtils
        CheckJavaHardcodedSecrets(CodeLine, FileName)       ' API keys, private keys and credentials embedded in source
        CheckJavaLogging(CodeLine, FileName)                ' Sensitive data and unsanitised input written to logs
        CheckAndroidComponentSecurity(CodeLine, FileName)   ' WebView, storage, exported components and PendingIntent flags

        ' Identify any nested classes (if required by user)
        If asAppSettings.IsInnerClassCheck Then CheckInnerClasses(CodeLine, FileName)

        ' Carry out any Android-specific checks
        If asAppSettings.IsAndroid = True Then
            CheckAndroidStaticCrypto(CodeLine, FileName)
            CheckAndroidIntent(CodeLine, FileName)
        End If

    End Sub

    Private Sub CheckServlet(CodeLine As String, FileName As String)
        ' Determine whether or not the module contains code for a servlet
        ' Check for any problems specific to servlets if necessary
        '================================================================
        Dim arrFragments As String()
        Dim strServletName As String = ""


        '== Determine whether this is a servlet in order to check for servlet-specific problems ==
        If ctCodeTracker.IsServlet = False And (CodeLine.Contains("extends HttpServlet") Or CodeLine.Contains("implements Servlet")) Then
            ctCodeTracker.IsServlet = True

            '== Store servlet name for thread-saftey checks ==
            arrFragments = Regex.Split(CodeLine, "(extends\s+HttpServlet|implements\s+Servlet)")
            strServletName = GetLastItem(arrFragments.First)

            If strServletName = "" Then Exit Sub

            ctCodeTracker.ServletName = strServletName
            If (Not ctCodeTracker.ServletNames.Contains(strServletName)) Then ctCodeTracker.ServletNames.Add(strServletName)

        End If

        '== Check for Thread.sleep() in servlet ==
        If ctCodeTracker.IsServlet = True And CodeLine.Contains("Thread.sleep") Then
            frmMain.ListCodeIssue("Use of Thread.sleep() within a Java servlet", "The use of Thread.sleep() within Java servlets is discouraged", FileName)
        End If

        '== List any getter and setter methods for the servlet's instance variables so that we can check these are handled in a thread-safe manner ==
        If ctCodeTracker.IsServlet = True Then IdentifyGetAndSet(CodeLine)

    End Sub

    Private Sub CheckSQLiValidation(CodeLine As String, FileName As String)
        ' Check for any SQL injection problems 
        '=====================================
        Dim strVarName As String = ""   ' Holds the variable name for the dynamic SQL statement


        '== Only check unvalidated code ==
        If ctCodeTracker.HasValidator = True Then Exit Sub


        '== Is unsanitised dynamic SQL statement prepared beforehand? ==
        If CodeLine.Contains("=") And (CodeLine.ToLower.Contains("sql") Or CodeLine.ToLower.Contains("query")) And (CodeLine.Contains("""") And CodeLine.Contains("+")) Then
            '== Extract variable name from assignment statement ==
            strVarName = GetVarName(CodeLine)
            ctCodeTracker.HasVulnSQLString = True
            If Not ctCodeTracker.SQLStatements.Contains(strVarName) And
                (Not (strVarName.Contains("(") Or strVarName.Contains(")") Or strVarName.Contains("[") Or strVarName.Contains("]") Or strVarName.Contains(" ") Or strVarName.Contains("+") Or strVarName.Contains("*"))) Then ctCodeTracker.SQLStatements.Add(strVarName)
        End If


        If Regex.IsMatch(CodeLine, "validate|encode|sanitize|sanitise") Then

            '== Remove any variables which have been sanitised from the list of vulnerable variables ==  
            If ctCodeTracker.SQLStatements.Count > 0 Then
                For Each strVar In ctCodeTracker.SQLStatements

                    If Regex.IsMatch(CodeLine, strVar & "\s*\=\s*\S*validate|encode|sanitize|sanitise\S*\(" & strVar) Then
                        ctCodeTracker.SQLStatements.Remove(strVar)
                        Exit For
                    End If
                Next
            End If
        ElseIf Regex.IsMatch(CodeLine, "\S*\.(prepareStatement|executeQuery|query|queryForObject|queryForList|queryForInt|queryForMap|update|getQueryString|executeQuery|createNativeQuery|createQuery)\s*\(") Then

            '== Check usage of java.sql.Statement.executeQuery, etc. ==
            If CodeLine.Contains("""") And CodeLine.Contains("+") Then
                '== Dynamic SQL built into connection/update ==
                frmMain.ListCodeIssue("Potential SQL Injection", "The application appears to allow SQL injection via dynamic SQL statements. No validator plug-ins were located in the application's XML files.", FileName, CodeIssue.CRITICAL, CodeLine)
            ElseIf ctCodeTracker.HasVulnSQLString = True Then
                '== Otherwise check for use of pre-prepared statements ==
                For Each strVar In ctCodeTracker.SQLStatements
                    If CodeLine.Contains(strVar) Then
                        frmMain.ListCodeIssue("Potential SQL Injection", "The application appears to allow SQL injection via a pre-prepared dynamic SQL statement. No validator plug-ins were located in the application's XML files.", FileName, CodeIssue.CRITICAL, CodeLine)
                        Exit For
                    End If
                Next
            End If
        End If

    End Sub

    Private Sub CheckXSSValidation(CodeLine As String, FileName As String)
        ' Check for any XSS problems 
        '===========================

        Dim arrFragments As String()    ' Holds the parts of any line containing HttpRequest var assignments
        Dim strVarName As String = ""   ' Holds the variable name assigned to any HttpRequest data


        '== Only check unvalidated code ==
        If ctCodeTracker.HasValidator = True Then Exit Sub


        '== Identify any HttpRequest variables in servlets ==
        If CodeLine.Contains("HttpServletRequest ") And Not CodeLine.Contains("import ") Then

            arrFragments = Regex.Split(CodeLine, "HttpServletRequest ")
            strVarName = arrFragments.Last.Trim

            If strVarName <> "" Then
                '== Variable name should be immediately followed by either whitespace, a comma, an equals sign or a semi-colon
                arrFragments = Regex.Split(strVarName, "[,;=\s+]")
                strVarName = arrFragments.First.Trim
                ctCodeTracker.HasHttpRequestData = True
                ctCodeTracker.HttpRequestVar = strVarName
            End If

        ElseIf FileName.ToLower.EndsWith(".jsp") And Regex.IsMatch(CodeLine, "\s*\S*\s*={1}?\s*\S*\s*\brequest\b\.\bgetParameter\b") Then

            '== Identify any GET parameters assigned to variables ==
            strVarName = GetVarName(CodeLine, True)

            ' Add variable to dictionary if it's alphanumeric (we have not accidentally caught an expression)
            ctCodeTracker.HasGetVariables = True
            If Regex.IsMatch(strVarName, "^[a-zA-Z0-9_]*$") And Not ctCodeTracker.SQLStatements.Contains(strVarName) Then ctCodeTracker.GetVariables.Add(strVarName)

        ElseIf FileName.ToLower.EndsWith(".jsp") And Regex.IsMatch(CodeLine, "\<\%\=\s*\w+\.getParameter\s*\(") Then
            frmMain.ListCodeIssue("Potential XSS", "The application appears to reflect a HTTP request parameter to the screen with no apparent validation or sanitisation.", FileName, CodeIssue.HIGH, CodeLine)

        ElseIf FileName.ToLower.EndsWith(".jsp") And ctCodeTracker.GetVariables.Count > 0 And (CodeLine.ToLower.Contains("validate") Or CodeLine.ToLower.Contains("encode") Or CodeLine.ToLower.Contains("sanitize") Or CodeLine.ToLower.Contains("sanitise")) Then

            '== Check for sanitisation of any GET/POST params and remove from dictionary ==
            If ctCodeTracker.GetVariables.Count > 0 Then
                For Each strVar In ctCodeTracker.GetVariables
                    If Not (strVar.contains("(") Or strVar.contains(")") Or strVar.contains("[") Or strVar.contains("]") Or strVar.contains(" ") Or strVar.contains("+") Or strVar.contains("*")) Then
                        If Regex.IsMatch(CodeLine, strVar & "\s*\=\s*\S*validate|encode|sanitize|sanitise\S*\(" & strVar) Then
                            ctCodeTracker.GetVariables.Remove(strVar)
                            Exit For
                        End If
                    End If
                Next
            End If

        ElseIf ctCodeTracker.HasHttpRequestData = True And CodeLine.Contains(ctCodeTracker.HttpRequestVar) Then

            '== If sanitisation takes place reset all HttpRequest variables ==
            If CodeLine.ToLower.Contains("validate") Or CodeLine.ToLower.Contains("encode") Or CodeLine.ToLower.Contains("sanitize") Or CodeLine.ToLower.Contains("sanitise") Then
                ctCodeTracker.HasHttpRequestData = False
                ctCodeTracker.HttpRequestVar = ""
            ElseIf (CodeLine.Contains("getCookies") Or CodeLine.Contains("getHeader") Or CodeLine.Contains("getPart") Or CodeLine.Contains("getQueryString") Or CodeLine.Contains("getParameter") Or CodeLine.Contains("getRequestUR")) Then

                '== If this point has been reached then variables probably used without sanitisation ==
                If FileName.ToLower.EndsWith(".jsp") Then
                    frmMain.ListCodeIssue("Potential XSS", "The application appears to use data contained in the HttpServletRequest without validation or sanitisation. No validator plug-ins were located in the application's XML files.", FileName, CodeIssue.HIGH, CodeLine)
                Else
                    frmMain.ListCodeIssue("Poor Input Validation", "The application appears to use data contained in the HttpServletRequest without validation or sanitisation. No validator plug-ins were located in the application's XML files.", FileName, CodeIssue.HIGH, CodeLine)
                End If

            End If

        ElseIf (FileName.ToLower.EndsWith(".jsp") And Regex.IsMatch(CodeLine, "<%=\s*\S*\bsession\b\.\bgetAttribute\b\s*\(")) Then
            '== Check JSPs for session variables being reflected back to page ==
            frmMain.ListCodeIssue("Potential XSS", "The JSP displays a session variable directly to the screen. No validator plug-ins were located in the application's XML files.", FileName, CodeIssue.HIGH, CodeLine)

        ElseIf FileName.ToLower.EndsWith(".jsp") And ctCodeTracker.GetVariables.Count > 0 And CodeLine.Contains("<%=") Then

            '== Check for get params being reflected to page without sanitisation ==
            For Each strVar In ctCodeTracker.GetVariables
                If Not (strVar.contains("(") Or strVar.contains(")") Or strVar.contains("[") Or strVar.contains("]") Or strVar.contains(" ") Or strVar.contains("+") Or strVar.contains("*")) Then
                    If Regex.IsMatch(CodeLine, "<%=\s*\S*\s*\b" & strVar & "\b") Then
                        frmMain.ListCodeIssue("Potential XSS", "The JSP displays directly a user-supplied parameter directly to the screen. No validator plug-ins were located in the application's XML files.", FileName, CodeIssue.HIGH, CodeLine)
                    End If
                End If
            Next

        ElseIf FileName.ToLower.EndsWith(".jsp") And Regex.IsMatch(CodeLine, "<c:\bout\b\s*\S*\s*=\s*['""]\s*\$\{\s*\S*\}\s*['""]\s*\bescapeXML\b\s*=\s*['""]\bfalse\b['""]\s*/>") Then
            '== Check JSPs for variables being reflected back to page without XML encoding ==
            frmMain.ListCodeIssue("Potential XSS", "The JSP displays application data without applying XML encoding. No validator plug-ins were located in the application's XML files.", FileName, CodeIssue.HIGH, CodeLine)
        End If

    End Sub

    Private Sub CheckRunTime(CodeLine As String, FileName As String)
        ' Determine whether or not the module uses java.lang.Runtime.exec
        ' Check for any any unsafe usage if necessary
        '================================================================

        '== Check for use of java.lang.Runtime ==
        If CodeLine.Contains("Runtime.") Then ctCodeTracker.IsRuntime = True

        '== Check for unsafe use of java.lang.Runtime.exec ==
        If ctCodeTracker.IsRuntime And (CodeLine.Contains(".exec ") Or CodeLine.Contains(".exec(")) And (Not CodeLine.Contains("""")) Then
            frmMain.ListCodeIssue("java.lang.Runtime.exec Gets Path from Variable", "The pathname used in the call appears to be loaded from a variable. Check the code manually to ensure that malicious filenames cannot be submitted by an attacker.", FileName, CodeIssue.HIGH, CodeLine)
        End If

    End Sub

    Private Sub CheckIsHttps(CodeLine As String, FileName As String)
        ' Determine whether or not the code connects to external URLs
        ' Check for any any unsafe usage if necessary
        '============================================================

        '== Check for secure HTTP usage ==
        If CodeLine.Contains("URLConnection") And CodeLine.Contains("HTTP:") Then
            frmMain.ListCodeIssue("URL request sent over HTTP:", "The URL used in the HTTP request appears to be unencrypted. Check the code manually to ensure that sensitive data is not being submitted.", FileName, CodeIssue.STANDARD, CodeLine)
        ElseIf (CodeLine.Contains("URLConnection(") Or CodeLine.Contains("URLConnection (")) And (Not CodeLine.Contains("""")) Then
            frmMain.ListCodeIssue("URL Request Gets Path from Variable", "The URL used in the HTTP request appears to be loaded from a variable. Check the code manually to ensure that malicious URLs cannot be submitted by an attacker.", FileName, CodeIssue.STANDARD, CodeLine)
        End If

    End Sub

    Private Sub CheckClone(CodeLine As String, FileName As String)
        ' Determine whether or not the code implements cloning
        ' Check for any any unsafe usage if necessary
        '=====================================================

        '== Check for safe or unsafe implementation of cloning ==
        If Regex.IsMatch(CodeLine, "\bpublic\b\s+\w+\s+\bclone\b\s*\(") Then
            ctCodeTracker.ImplementsClone = True
        End If
        If ctCodeTracker.ImplementsClone = True And CodeLine.Contains("throw new java.lang.CloneNotSupportedException") Then
            ctCodeTracker.ImplementsClone = False
        End If

    End Sub

    Private Sub CheckSerialize(CodeLine As String, FileName As String)
        ' Determine whether or not the code implements serialization
        ' Check for any any unsafe usage if necessary
        '===========================================================

        '== Check for safe or unsafe implementation of serialization/deserialization ==
        If CodeLine.Contains(" writeObject") Then ctCodeTracker.IsSerialize = True
        If CodeLine.Contains(" readObject") Then ctCodeTracker.IsDeserialize = True

        If ctCodeTracker.IsSerialize = True And ctCodeTracker.TrackBraces(CodeLine, ctCodeTracker.SerializeBraces) And CodeLine.Contains("throw new java.io.IOException") Then
            ctCodeTracker.IsSerialize = False
        End If
        If ctCodeTracker.IsDeserialize = True And ctCodeTracker.TrackBraces(CodeLine, ctCodeTracker.DeserializeBraces) And CodeLine.Contains("throw new java.io.IOException") Then
            ctCodeTracker.IsDeserialize = False
        End If

    End Sub

    Private Sub CheckModifiers(CodeLine As String, FileName As String)
        ' Identify any public variables in classes
        '=========================================
        Dim strVarName As String = ""


        '== Check for public variables and non-final classes (finalize check is optional) ==
        If CodeLine.Contains("public ") And CodeLine.Contains(";") And Not (CodeLine.Contains("{") Or CodeLine.Contains("abstract ") Or CodeLine.Contains("class ") Or CodeLine.Contains("static ")) Then

            strVarName = GetVarName(CodeLine)
            If Regex.IsMatch(strVarName, "^[a-zA-Z0-9_]*$") Then
                frmMain.ListCodeIssue("Class Contains Public Variable: " & strVarName, "The class variable may be accessed and modified by other classes without the use of getter/setter methods. It is considered unsafe to have public fields or methods in a class unless required as any method, field, or class that is not private is a potential avenue of attack. It is safer to provide accessor methods to variables in order to limit their accessibility.", FileName, CodeIssue.STANDARD, CodeLine)
            End If

            '== Store public variable name for any thread safety checks if this is a servlet ==
            If ctCodeTracker.IsServlet Then
                If Not ctCodeTracker.GlobalVars.ContainsKey(strVarName) Then ctCodeTracker.GlobalVars.Add(strVarName, ctCodeTracker.ServletName)
            End If

        ElseIf asAppSettings.IsFinalizeCheck And (CodeLine.Contains("public ") And CodeLine.Contains("class ")) And Not CodeLine.Contains("final ") Then
            frmMain.ListCodeIssue("Public Class Not Declared as Final", "The class is not declared as final as per OWASP recommendations. It is considered best practice to make classes final where possible and practical (i.e. It has no classes which inherit from it). Non-Final classes can allow an attacker to extend a class in a malicious manner. Manually inspect the code to determine whether or not it is practical to make this class final.", FileName, CodeIssue.POSSIBLY_SAFE, CodeLine)
        End If

    End Sub

    Private Sub CheckInnerClasses(CodeLine As String, FileName As String)
        ' Identify any inner classes within classes
        '==========================================

        '== Check for entry into class ==
        If Not ctCodeTracker.IsInsideClass And Regex.IsMatch(CodeLine, "\bpublic\b\s*\bclass\b") Then
            If CodeLine.Contains("{") Then
                ctCodeTracker.IsInsideClass = ctCodeTracker.TrackBraces(CodeLine, ctCodeTracker.ClassBraces)
            Else
                ctCodeTracker.IsInsideClass = True
            End If
        ElseIf ctCodeTracker.IsInsideClass Then
            If CodeLine.Contains("private ") And CodeLine.Contains("class ") Then
                frmMain.ListCodeIssue("Class Contains Inner Class", "When translated into bytecode, any inner classes are rebuilt within the JVM as external classes within the same package. As a result, any class in the package can access these inner classes. The enclosing class's private fields become protected fields, accessible by the now external 'inner class'.", FileName, CodeIssue.STANDARD, CodeLine)
            End If
            ctCodeTracker.IsInsideClass = ctCodeTracker.TrackBraces(CodeLine, ctCodeTracker.ClassBraces)
        End If

    End Sub

    Private Sub CheckThreadIssues(CodeLine As String, FileName As String)
        ' Identify potential for race conditions and deadlocking
        '=======================================================
        Dim blnIsRace As Boolean = False
        Dim strSyncObject As String = ""



        '== Identify object locked for use in synchronized block ==
        If ctCodeTracker.IsSynchronized = False And Regex.IsMatch(CodeLine, "\bsynchronized\b\s*\(\s*\w+\s*\)") Then
            strSyncObject = GetSyncObject(CodeLine)
            ctCodeTracker.LockedObject = strSyncObject
            ctCodeTracker.SyncIndex += 1
        End If



        '== Identify entry into a synchronized block ==
        '== The synchronized may be followed by method type and name for a synchronized method, or by braces for a synchronized block ==
        If ctCodeTracker.IsSynchronized = False And Regex.IsMatch(CodeLine, "\bsynchronized\b\s*\S*\s*\S*\s*\(") Then
            If CodeLine.Contains("{") Then
                ctCodeTracker.IsSynchronized = ctCodeTracker.TrackBraces(CodeLine, ctCodeTracker.SyncBraces)
            Else
                ctCodeTracker.IsSynchronized = True
            End If

        ElseIf ctCodeTracker.IsSynchronized = False And ctCodeTracker.IsServlet = True Then

            '== Check for any unsafe modifications to instance variables == 
            If ctCodeTracker.GlobalVars.Count > 0 Then

                For Each itmItem In ctCodeTracker.GlobalVars
                    If CodeLine.Contains(itmItem.Key) Then
                        frmMain.ListCodeIssue("Possible Race Condition", "A HttpServlet instance variable is being used/modified without a synchronize block: " & itmItem.Key & vbNewLine & "Check if any code which calls this code is thread-safe.", FileName, CodeIssue.MEDIUM)
                        Exit For
                    End If
                Next
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

    Private Sub IdentifyServlets(CodeLine As String)
        ' Identify any instantiation of Servlet Classes and store the object names for thread safety checks
        '==================================================================================================
        Dim strVarName As String = ""


        If (CodeLine.Contains("public ") Or CodeLine.Contains("private ") Or CodeLine.Contains("protected ")) And CodeLine.Contains(";") And Not CodeLine.Contains("{") And Not CodeLine.Contains("abstract ") Then
            For Each strName In ctCodeTracker.ServletNames
                If CodeLine.Contains(strName) Then
                    strVarName = GetVarName(CodeLine)
                    If Not ctCodeTracker.ServletInstances.ContainsKey(strVarName) Then ctCodeTracker.ServletInstances.Add(strVarName, strName)
                    Exit For
                End If
            Next
        End If

    End Sub

    Private Sub IdentifyGetAndSet(CodeLine As String)
        ' Identify any getter and setter methods within Servlet Classes and store the object names for thread safety checks
        '==================================================================================================================
        Dim strMethodName As String = ""
        Dim arrFragments As String()


        '== Do we have a susceptible method? ==
        If Regex.IsMatch(CodeLine, "\s*\bpublic\b\s+\S*\s+(g|s)et\S+\s*\(") Then

            '== Extract method name ==
            arrFragments = CodeLine.Split("(")
            strMethodName = arrFragments.First
            strMethodName = GetLastItem(strMethodName)

            If Not ctCodeTracker.GetSetMethods.ContainsKey(strMethodName) Then ctCodeTracker.GetSetMethods.Add(strMethodName, ctCodeTracker.ServletName)

        End If

    End Sub

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
                    frmMain.ListCodeIssue("Possible Race Condition", "A HttpServlet instance variable is being used/modified without a synchronize block.", FileName, CodeIssue.HIGH)
                    blnRetVal = True
                End If
            End If
        End If

        Return blnRetVal

    End Function

    Private Sub CheckUnsafeTempFiles(CodeLine As String, FileName As String)
        ' Identify any creation of temp files with static names
        '======================================================

        If Regex.IsMatch(CodeLine, "\bnew\b\s+File\s*\(\s*\""*\S*(temp|tmp)\S*\""\s*\)") Then
            frmMain.ListCodeIssue("Unsafe Temporary File Allocation", "The application appears to create a temporary file with a static, hard-coded name. This causes security issues in the form of a classic race condition (an attacker creates a file with the same name between the application's creation and attempted usage) or a symbolic linbk attack where an attacker creates a symbolic link at the temporary file location.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

    End Sub

    Private Function GetSyncObject(CodeLine As String) As String
        ' Extract the name of a synchronized object from a line of code
        '==============================================================
        Dim strSyncObject As String = ""
        Dim strFragments As String()


        strFragments = Regex.Split(CodeLine, "\bsynchronized\b\s*\(")
        strSyncObject = GetFirstItem(strFragments.Last, ")")
        If strSyncObject <> "" Then ctCodeTracker.LockedObject = strSyncObject

        Return strSyncObject

    End Function

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
                frmMain.ListCodeIssue("Synchronized Code - Possible Performance Impact", "There are " & ctCodeTracker.SyncLineCount & " lines of code in the synchronized block. Manually check the code to ensure any shared resources are not being locked unnecessarily.", FileName, intSeverity)
            End If

            ctCodeTracker.SyncLineCount = 0

        ElseIf ctCodeTracker.LockedObject <> "" And Regex.IsMatch(CodeLine, "\bsynchronized\b\s*\(\s*\w+\s*\)") Then
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

    Public Sub AddNewSyncBlock(OuterObject As String, InnerObject As String)
        ' Initialise a new syncblock container to hold details of locked items
        '=====================================================================
        Dim sbSyncBlock As New SyncBlock

        sbSyncBlock.BlockIndex = ctCodeTracker.SyncIndex
        sbSyncBlock.OuterObject = OuterObject
        sbSyncBlock.InnerObjects.Add(InnerObject)

        ctCodeTracker.SyncBlockObjects.Add(sbSyncBlock)

    End Sub

    Public Sub CheckDeadlock(OuterObject As String, InnerObject As String, FileName As String)
        ' Check whether the locked object combination has a reverse block where the inner item and outer item swap places
        '================================================================================================================

        For Each itmItem In ctCodeTracker.SyncBlockObjects
            If itmItem.OuterObject = InnerObject And itmItem.InnerObjects.Contains(OuterObject) Then
                frmMain.ListCodeIssue("Synchronized Code May Result in DeadLock", "The objects " & OuterObject & " and " & InnerObject & " lock each other in such a way that they may become deadlocked.", FileName, CodeIssue.MEDIUM)
                Exit For
            End If
        Next

    End Sub

    Private Sub CheckPrivileged(CodeLine As String, FileName As String)
        ' Check for unsafe use of privileged blocks
        '==========================================
        Dim intSeverity As Integer = 0


        '== The IsInsideClass variable tracks whether we are inside a public class and can be re-used here ==
        If ctCodeTracker.IsInsideClass = True Then

            '== Check for public method ==
            If ctCodeTracker.IsInsideMethod = False And Regex.IsMatch(CodeLine, "\bpublic\b\s+\w+\s+\w+\s*\w*\s*\(") Then

                If CodeLine.Contains("{") Then
                    ctCodeTracker.IsInsideMethod = ctCodeTracker.TrackBraces(CodeLine, ctCodeTracker.MethodBraces)
                Else
                    ctCodeTracker.IsInsideMethod = True
                End If

            ElseIf ctCodeTracker.IsInsideMethod = True And Regex.IsMatch(CodeLine, "\bAccessController\b\.\bdoPrivileged\b") Then

                If CodeLine.Contains("{") Then
                    ctCodeTracker.IsPrivileged = ctCodeTracker.TrackBraces(CodeLine, ctCodeTracker.PrivBraces)
                Else
                    ctCodeTracker.IsPrivileged = True
                End If
                frmMain.ListCodeIssue("Use of AccessController.doPrivileged() in Public Method of Public Class", "The code will execute with system privileges and should be manually checked with great care to ensure no vulnerabilities are present.", FileName, CodeIssue.MEDIUM, CodeLine)

            ElseIf ctCodeTracker.IsPrivileged = False And Regex.IsMatch(CodeLine, "\bAccessController\b\.\bdoPrivileged\b") Then

                If CodeLine.Contains("{") Then
                    ctCodeTracker.IsPrivileged = ctCodeTracker.TrackBraces(CodeLine, ctCodeTracker.PrivBraces)
                Else
                    ctCodeTracker.IsPrivileged = True
                End If

            ElseIf ctCodeTracker.IsPrivileged = True Then

                '== Track the amount of code that is inside the lock - resources may be locked unnecessarily ==
                If (CodeLine.Trim <> "{" And CodeLine.Trim <> "}") Then ctCodeTracker.PrivLineCount += 1
                ctCodeTracker.IsPrivileged = ctCodeTracker.TrackBraces(CodeLine, ctCodeTracker.PrivBraces)

                '== If we've exited then give notice of excessively large privileged blocks ==
                If ctCodeTracker.IsInsideMethod = True And ctCodeTracker.IsPrivileged = False Then

                    If ctCodeTracker.PrivLineCount > 20 Then
                        intSeverity = CodeIssue.MEDIUM
                    ElseIf ctCodeTracker.PrivLineCount > 15 Then
                        intSeverity = CodeIssue.STANDARD
                    ElseIf ctCodeTracker.PrivLineCount > 10 Then
                        intSeverity = CodeIssue.LOW
                    End If

                    If ctCodeTracker.PrivLineCount > 10 Then
                        frmMain.ListCodeIssue("Privileged Code - Possible Risks", "There are " & ctCodeTracker.PrivLineCount & " lines of code in the privileged block. Manually check the code to ensure no unnecessary code is included.", FileName, intSeverity)
                    End If
                    ctCodeTracker.PrivLineCount = 0
                ElseIf ctCodeTracker.IsPrivileged = True Then
                    '== Check for use of user-controlled variables within privileged code ==
                    For Each strVar In ctCodeTracker.GetVariables
                        If Not (strVar.contains("(") Or strVar.contains(")") Or strVar.contains("[") Or strVar.contains("]") Or strVar.contains(" ") Or strVar.contains("+") Or strVar.contains("*")) Then
                            If Regex.IsMatch(CodeLine, "\b" & strVar & "\b") Then
                                frmMain.ListCodeIssue("Use of User-Controlled Variable Within Privileged Code", "The code will execute with system privileges and the usage of the variable should be manually checked with great care.", FileName, CodeIssue.HIGH, CodeLine)
                                Exit For
                            End If
                        End If
                    Next
                End If
            End If

        End If

    End Sub

    Private Sub CheckRequestDispatcher(CodeLine As String, FileName As String)
        ' Check for unsafe use of RequestDispatcher
        '==========================================

        If Regex.IsMatch(CodeLine, "\.\bgetRequestDispatcher\b\s*\(") Then
            '== Check for use of user-controlled variable within privileged code ==
            For Each strVar In ctCodeTracker.GetVariables
                If Not (strVar.contains("(") Or strVar.contains(")") Or strVar.contains("[") Or strVar.contains("]") Or strVar.contains(" ") Or strVar.contains("+") Or strVar.contains("*")) Then
                    If Regex.IsMatch(CodeLine, "\bgetRequestDispatcher\b\s*\(\s*\S*\s*\S*\s*\b" & strVar & "\b") Then
                        frmMain.ListCodeIssue("Use of RequestDispatcher in Combination with User-Controlled Variable", "The code appears to use a user-controlled variable in a RequestDispatcher method which can allow horizontal directory traversal, allowing an attacker to download system files.", FileName, CodeIssue.HIGH, CodeLine)
                        Exit For
                    End If
                End If
            Next
        End If

    End Sub

    Private Sub CheckXXE(CodeLine As String, FileName As String)
        ' Check for potential XXE vulnerabilities in XML parsing code
        '===========================================================

        ' Use a regular expression to check for import of JAXB
        If Not ctCodeTracker.HasXXEEnabled Then
            If Regex.IsMatch(CodeLine, "import\s+javax\.xml\.bind\.JAXB\s*;") Then
                ctCodeTracker.HasXXEEnabled = True
                ctCodeTracker.VulnerableLines.Add(CodeLine) ' Record the vulnerable line
                frmMain.ListCodeIssue("Potential XXE Vulnerability",
                                   "Detected use of JAXB, which may lead to XXE.",
                                   FileName)
            End If
        End If

        ' If JAXB has been detected, check for other factors
        If ctCodeTracker.HasXXEEnabled Then
            ' Check for insecure XML processing features
            If Regex.IsMatch(CodeLine, "\(\s*(XMLConstants\.FEATURE_SECURE_PROCESSING|XMLInputFactory\.SUPPORT_DTD)\s*\,\s*false\s*\)") Then
                ctCodeTracker.VulnerableLines.Add(CodeLine) ' Record the vulnerable line
                frmMain.ListCodeIssue("Insecure XML Processing",
                                   "XML processing features are set to false, which may lead to XXE.",
                                   FileName)
            End If

            ' Check for use of other XML parsers
            If Regex.IsMatch(CodeLine, "\b(DocumentBuilderFactory|SAXParserFactory|DOM4J|XMLInputFactory|XMLReader|parseXml)\b") Then
                ctCodeTracker.VulnerableLines.Add(CodeLine) ' Record the vulnerable line
                frmMain.ListCodeIssue("Use of XML Parser",
                                   "Detected use of an XML parser that may be vulnerable to XXE.",
                                   FileName)
            End If
        End If

        ' Check for external entity declarations in XML strings
        If InStr(1, CodeLine, "<!doctype", vbTextCompare) > 0 OrElse
       InStr(1, CodeLine, "<!ENTITY", vbTextCompare) > 0 Then
            ctCodeTracker.VulnerableLines.Add(CodeLine) ' Record the vulnerable line
            frmMain.ListCodeIssue("Possible XXE Payload",
                               "XML contains doctype or entity declarations, which may lead to XXE attacks.",
                               FileName)
        End If

        ' Check for the use of external entity resolution settings
        If InStr(1, CodeLine, "setProperty", vbTextCompare) > 0 AndAlso
       (InStr(1, CodeLine, "javax.xml.XMLConstants.ACCESS_EXTERNAL_DTD", vbTextCompare) > 0 OrElse
        InStr(1, CodeLine, "javax.xml.XMLConstants.ACCESS_EXTERNAL_SCHEMA", vbTextCompare) > 0) Then

            If Not (InStr(1, CodeLine, "ACCESS_EXTERNAL_DTD", vbTextCompare) > 0 AndAlso
                InStr(1, CodeLine, "ACCESS_EXTERNAL_SCHEMA", vbTextCompare) > 0) Then
                ctCodeTracker.VulnerableLines.Add(CodeLine) ' Record the vulnerable line
                frmMain.ListCodeIssue("Improper External Entity Access Configuration",
                                   "XML parser configuration does not restrict external DTD/schema access.",
                                   FileName)
            End If
        End If
    End Sub

    Private Sub CheckOverflow(CodeLine As String, FileName As String)
        ' Identify occurences of primitive types and warn for any potential overflows
        '============================================================================

        '== Identify any primitives and add to dictionary ==
        If Regex.IsMatch(CodeLine, "\b(short|int|long)\b\s+\w+\s*(\=|\;)") Then
            ctCodeTracker.HasPrimitives = True
            ctCodeTracker.AddInteger(CodeLine)
        End If

        '== Warn of any mathematical operations on integers and possible overflows ==
        If ctCodeTracker.HasPrimitives = True And (CodeLine.Contains("+") Or CodeLine.Contains("-") Or CodeLine.Contains("*")) Then
            For Each itmIntItem In ctCodeTracker.GetIntegers
                If Not (itmIntItem.Key.Contains("(") Or itmIntItem.Key.Contains(")") Or itmIntItem.Key.Contains("[") Or itmIntItem.Key.Contains("]") Or itmIntItem.Key.Contains(" ") Or itmIntItem.Key.Contains("+") Or itmIntItem.Key.Contains("*")) Then
                    If Regex.IsMatch(CodeLine, "\b" & itmIntItem.Key & "\b") Then
                        For Each itmVarItem In ctCodeTracker.GetVariables
                            frmMain.ListCodeIssue("Operation on Primitive Data Type", "The code appears to be carrying out a mathematical operation involving a primitive data type and a user-supplied variable. This may result in an overflow and unexpected behaviour. Check the code manually to determine the risk.", FileName, CodeIssue.HIGH, CodeLine)
                            Exit Sub
                        Next
                        frmMain.ListCodeIssue("Operation on Primitive Data Type", "The code appears to be carrying out a mathematical operation on a primitive data type. In some circumstances this can result in an overflow and unexpected behaviour. Check the code manually to determine the risk.", FileName, CodeIssue.LOW, CodeLine)
                        Exit Sub
                    End If
                End If
            Next
        End If

    End Sub

    Private Sub CheckResourceRelease(CodeLine As String, FileName As String)
        ' Check that try ... catch blocks are being used to release resources and avoid DoS
        '==================================================================================

        '== Record any instances of filestreams being created ==
        If ctCodeTracker.IsFileOpen = False And Regex.IsMatch(CodeLine, "\bnew\b\s+\bFileOutputStream\b\s*\(") Then
            ctCodeTracker.IsFileOpen = True
            ctCodeTracker.HasResourceRelease = False
            ctCodeTracker.FileOpenLine = rtResultsTracker.LineCount
        End If


        '== Check for safe release of resources in all cases ==
        If ctCodeTracker.IsFileOpen = True And Regex.IsMatch(CodeLine, "\btry\b") Then
            ctCodeTracker.HasTry = True
        ElseIf ctCodeTracker.IsFileOpen = True And Regex.IsMatch(CodeLine, "\bfinally\b") Then
            ctCodeTracker.IsFileOpen = False
            If Regex.IsMatch(CodeLine, "\.\bclose\b\s*\(") Then
                ctCodeTracker.HasResourceRelease = True
            End If
        End If

    End Sub

    Private Sub CheckAndroidStaticCrypto(CodeLine As String, FileName As String)
        ' Determine whether static crypto is being used for Android apps
        '===============================================================

        '== Check for use of static string in crypto command ==
        If Regex.IsMatch(CodeLine, "CryptoAPI\.(encrypt|decrypt)\s*\(\""\w+\""\s*\,") Then
            frmMain.ListCodeIssue("Static Crypto Keys in Use", "The application appears to be using static crypto keys. The absence of secure key storage may allow unauthorised decryption of data.", FileName, CodeIssue.HIGH, CodeLine)
        End If

    End Sub

    Private Sub CheckAndroidIntent(CodeLine As String, FileName As String)
        ' Determine whether implicit intents are being used for Android apps
        '===================================================================
        Dim strFragments As String()
        Dim strIntent As String = ""


        '== Check for creation of blank intent ==
        If ctCodeTracker.HasIntent = False And Regex.IsMatch(CodeLine, "\bIntent\b\s+\w+\s*\=\s*new\s+Intent\s*\(\s*\)") Then

            ' Sey boolean to show that an intent exists
            ctCodeTracker.HasIntent = True

            ' Store the name of the intent
            strFragments = Regex.Split(CodeLine, "\=\s*new\s+Intent\s*\(\s*\)")
            strIntent = GetLastItem(strFragments.First())
            If strIntent <> "" And Not ctCodeTracker.AndroidIntents.Contains(strIntent) Then ctCodeTracker.AndroidIntents.Add(strIntent)

        ElseIf ctCodeTracker.HasIntent = True And Regex.IsMatch(CodeLine, "\.setClass\(") Then

            ' Remove any explicit intents from the dictionary
            strFragments = Regex.Split(CodeLine, "\.setClass\(")

            If strFragments.Count > 1 Then
                strIntent = GetFirstItem(strFragments.ElementAt(1), ")")

                If strIntent <> "" And ctCodeTracker.AndroidIntents.Contains(strIntent) Then ctCodeTracker.AndroidIntents.Remove(strIntent)
                If ctCodeTracker.AndroidIntents.Count = 0 Then ctCodeTracker.HasIntent = False
            End If

        ElseIf ctCodeTracker.HasIntent = True And Regex.IsMatch(CodeLine, "\bstartActivity\b\s*\(") Then

            ' Remove any explicit intents from the dictionary
            strFragments = Regex.Split(CodeLine, "\bstartActivity\b\s*\(")

            If strFragments.Count > 1 Then
                strIntent = GetFirstItem(strFragments.ElementAt(1), ")")
                If strIntent <> "" And ctCodeTracker.AndroidIntents.Contains(strIntent) Then
                    ctCodeTracker.AndroidIntents.Remove(strIntent)
                    If ctCodeTracker.AndroidIntents.Count = 0 Then ctCodeTracker.HasIntent = False
                    frmMain.ListCodeIssue("Implicit Intents in Use", "The application appears to be using implicit intents which could be intercepted by rogue applications. Intent name: " & strIntent, FileName, CodeIssue.MEDIUM, CodeLine)
                End If
            End If
        End If

    End Sub

    Private Sub CheckInsecureDeserialization(CodeLine As String, FileName As String)
        ' Check for insecure deserialization vulnerabilities
        '==================================================
        ' Define patterns for deserialization methods and APIs
        Dim deserializationPatterns As New List(Of String) From {
        "\.readObject\(",
        "\.readUnshared\(",
        "New XMLDecoder\(",
        "New XStream\("
    }
        Dim customDeserializationPatterns As New List(Of String) From {
        "Private Sub readObject\(",
        "Private Sub readObjectNoData\(",
        "Function readResolve\(",
        "Sub readExternal\("
    }
        Dim gadgetPatterns As New List(Of String) From {
        "CommonsCollections",
        "BeanShell1",
        "Groovy1",
        "Spring1"
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
        If customDeserializationPatterns.Any(Function(p) System.Text.RegularExpressions.Regex.IsMatch(CodeLine, p)) Then
            frmMain.ListCodeIssue("Custom Deserialization Implementation",
                           "Detected custom deserialization methods. Ensure input validation and type checking.",
                           FileName,
                           CodeIssue.MEDIUM)
        End If

        ' Check for use of XMLDecoder (potential RCE risk)
        If System.Text.RegularExpressions.Regex.IsMatch(CodeLine, "New XMLDecoder\(") Then
            frmMain.ListCodeIssue("Use of XMLDecoder",
                           "XMLDecoder may lead to remote code execution if data is user-controlled.",
                           FileName,
                           CodeIssue.HIGH)
        End If

        ' Check for use of XStream with fromXML (version <= 1.46 may be vulnerable)
        If CodeLine.Contains("XStream") And CodeLine.Contains(".fromXML(") Then
            frmMain.ListCodeIssue("Use of XStream",
                           "XStream (version <= 1.46) has vulnerabilities related to deserialization. Ensure to check the version and validate input data.",
                           FileName,
                           CodeIssue.MEDIUM)
        End If

        ' Check for gadget chains in ysoserial
        If gadgetPatterns.Any(Function(p) CodeLine.Contains(p)) Then
            frmMain.ListCodeIssue("Potential Gadget Chain",
                           "Detected potential gadget chain from ysoserial. Consider thoroughly validating function call chains.",
                           FileName,
                           CodeIssue.MEDIUM)
        End If

        ' Update input validation status
        If CodeLine.Contains("instanceof") Or
       CodeLine.Contains("getClass().getName()") Or
       CodeLine.Contains("validateObject(") Or
       CodeLine.Contains("ObjectInputValidation") Then
            ctCodeTracker.HasInputValidation = True
        End If
    End Sub



    '======================================================================================
    '== EXTENDED RULESET                                                                 ==
    '== Additional checks appended without altering any pre-existing logic.              ==
    '======================================================================================

    Private Function IsUserInputJava(CodeLine As String) As Boolean
        ' Return True where the line appears to reference a tainted (user-controlled) source
        '==================================================================================

        If Regex.IsMatch(CodeLine, "\b(getParameter|getParameterValues|getParameterMap|getHeader|getHeaders|getCookies|getQueryString|getInputStream|getReader|getPathInfo|getRequestURI|getRequestURL|getRemoteUser|getPart|getParts)\s*\(") Then Return True
        If Regex.IsMatch(CodeLine, "@(RequestParam|PathVariable|RequestBody|RequestHeader|CookieValue|ModelAttribute|MatrixVariable|QueryParam|FormParam|HeaderParam|PathParam)\b") Then Return True
        If Regex.IsMatch(CodeLine, "\b(System\s*\.\s*getenv|System\s*\.\s*getProperty|Scanner\s*\(\s*System\s*\.\s*in|BufferedReader)\b") Then Return True
        If Regex.IsMatch(CodeLine, "\b(getIntent\s*\(\s*\)|getStringExtra|getExtras|getQueryParameter|getData\s*\(\s*\))\b") Then Return True
        If Regex.IsMatch(CodeLine, "\bargs\s*\[") Then Return True

        Return False

    End Function

    Private Sub CheckJavaWeakCrypto(CodeLine As String, FileName As String)
        ' Identify broken cryptographic primitives, modes and key material
        '=================================================================
        Dim mchMatch As Match
        Dim intKeySize As Integer = 0


        '== Broken hash algorithms ==
        If Regex.IsMatch(CodeLine, "MessageDigest\s*\.\s*getInstance\s*\(\s*""\s*(MD2|MD4|MD5|SHA-?1)\s*""") Or _
           Regex.IsMatch(CodeLine, "\b(DigestUtils\s*\.\s*(md5|md5Hex|sha1|sha1Hex)|Hashing\s*\.\s*(md5|sha1))\s*\(") Or _
           Regex.IsMatch(CodeLine, "Mac\s*\.\s*getInstance\s*\(\s*""\s*Hmac(MD5|SHA1)\s*""") Then
            frmMain.ListCodeIssue("Use of Broken or Deprecated Hashing Algorithm", "The code selects MD2, MD4, MD5 or SHA-1. Practical collision attacks exist against all of these, so they cannot be relied upon for signatures, integrity verification or password storage. Move to SHA-256 or better; for passwords use Argon2id, bcrypt or PBKDF2-HMAC-SHA256 with a high iteration count.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

        '== Broken ciphers and unsafe modes ==
        If Regex.IsMatch(CodeLine, "Cipher\s*\.\s*getInstance\s*\(\s*""\s*(DES|DESede|TripleDES|RC2|RC4|ARCFOUR|Blowfish)\b") Then
            frmMain.ListCodeIssue("Use of Broken or Deprecated Symmetric Cipher", "DES, Triple-DES, RC2, RC4 and Blowfish are all unsuitable for new work: DES has a 56-bit key, RC4 has statistical biases that leak plaintext, and the 64-bit block sizes of DESede and Blowfish expose them to Sweet32 birthday attacks. Use AES-256-GCM.", FileName, CodeIssue.HIGH, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "Cipher\s*\.\s*getInstance\s*\(\s*""[^""]*ECB") Then
            frmMain.ListCodeIssue("Use of ECB Cipher Mode", "ECB encrypts each block independently, so identical plaintext blocks yield identical ciphertext blocks. Structure of the plaintext leaks directly and blocks can be reordered or spliced by an attacker. Use AES/GCM/NoPadding.", FileName, CodeIssue.HIGH, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "Cipher\s*\.\s*getInstance\s*\(\s*""\s*(AES|DES|DESede|Blowfish)\s*""\s*\)") Then
            frmMain.ListCodeIssue("Cipher Transformation Without Explicit Mode", "Requesting a bare algorithm name causes the JCE to fall back to the provider default, which for SunJCE is ECB. Always specify the mode and padding explicitly, for example AES/GCM/NoPadding.", FileName, CodeIssue.HIGH, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "Cipher\s*\.\s*getInstance\s*\(\s*""[^""]*(CBC|ECB)/PKCS5Padding") And Not CodeLine.Contains("GCM") Then
            frmMain.ListCodeIssue("Unauthenticated Encryption Mode", "CBC with PKCS#5 padding provides confidentiality but no integrity. Where the application returns distinguishable errors for padding failures this permits padding-oracle decryption and, in some designs, forgery. Use an AEAD mode such as GCM, or apply Encrypt-then-MAC with a separate key.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\bNullCipher\b") Then
            frmMain.ListCodeIssue("Use of NullCipher", "NullCipher performs no encryption whatsoever and returns the plaintext unchanged.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If

        '== Hard-coded keys, IVs and salts ==
        If Regex.IsMatch(CodeLine, "new\s+(SecretKeySpec|IvParameterSpec|PBEKeySpec|GCMParameterSpec)\s*\(") And Regex.IsMatch(CodeLine, "(""[^""]{4,}""\s*\.\s*getBytes|new\s+byte\s*\[\s*\]\s*\{)") Then
            frmMain.ListCodeIssue("Hard-Coded Cryptographic Key, IV or Salt", "Key or IV material is derived from a literal embedded in the class file. String constants survive compilation intact and are recovered instantly with javap or any decompiler, so the encryption offers no protection against an attacker holding the ciphertext and the application. Keys must come from a keystore, KMS or HSM, and IVs must be random per message.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If

        '== Weak key sizes ==
        mchMatch = Regex.Match(CodeLine, "\b(KeyPairGenerator|KeyGenerator)\b[^;]*\.\s*init(ialize)?\s*\(\s*(\d+)")
        If mchMatch.Success Then
            If Integer.TryParse(mchMatch.Groups(3).Value, intKeySize) Then
                If (intKeySize > 0 And intKeySize < 2048 And intKeySize > 512) Or intKeySize = 512 Or intKeySize = 1024 Then
                    frmMain.ListCodeIssue("Potentially Insufficient Key Length", "A key of " & intKeySize.ToString() & " bits is generated. For RSA/DSA/DH this is below the 2048-bit minimum required by current guidance; for symmetric keys anything below 128 bits is inadequate. Confirm the algorithm and raise the key size accordingly.", FileName, CodeIssue.MEDIUM, CodeLine)
                End If
            End If
        End If

        '== Predictable randomness for security-relevant values ==
        If Regex.IsMatch(CodeLine, "\bnew\s+java\.util\.Random\s*\(|\bnew\s+Random\s*\(|\bMath\s*\.\s*random\s*\(") And _
           Regex.IsMatch(CodeLine, "(?i)\b\w*(token|session|nonce|salt|key|password|otp|secret|csrf|uuid|reset)\w*\b") Then
            frmMain.ListCodeIssue("Predictable Random Value Used For Security Purpose", "java.util.Random is a linear congruential generator seeded from the system clock. Observing a small number of outputs allows the internal state - and therefore all past and future outputs - to be recovered. Use java.security.SecureRandom for tokens, salts, nonces and identifiers.", FileName, CodeIssue.HIGH, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "SecureRandom\s*\(\s*""[^""]+""\s*\.\s*getBytes|\bsetSeed\s*\(\s*(\d+|""[^""]*""|System\s*\.\s*currentTimeMillis)") Then
            frmMain.ListCodeIssue("SecureRandom Seeded With Predictable Value", "Seeding SecureRandom with a constant or with the current time destroys its unpredictability and makes all generated values reproducible by an attacker. Allow SecureRandom to self-seed from the operating system entropy source.", FileName, CodeIssue.HIGH, CodeLine)
        End If

    End Sub

    Private Sub CheckJavaTrustManager(CodeLine As String, FileName As String)
        ' Identify disabled TLS certificate and hostname verification
        '============================================================

        If Regex.IsMatch(CodeLine, "\b(ALLOW_ALL_HOSTNAME_VERIFIER|AllowAllHostnameVerifier|NoopHostnameVerifier|SSLSocketFactory\s*\.\s*ALLOW_ALL)\b") Then
            frmMain.ListCodeIssue("Hostname Verification Disabled", "The connection accepts a certificate regardless of the hostname it was issued for. Any valid certificate from any public CA - including one an attacker legitimately owns - will then be accepted for this host, defeating TLS authentication.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\bverify\s*\(\s*String\s+\w+\s*,\s*SSLSession\s+\w+\s*\)") Or Regex.IsMatch(CodeLine, "setHostnameVerifier\s*\(") Then
            frmMain.ListCodeIssue("Custom Hostname Verifier Installed", "A custom HostnameVerifier is supplied. Manually confirm that it actually compares the requested host against the certificate CN/SAN; an implementation which simply returns true accepts any certificate.", FileName, CodeIssue.HIGH, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\b(X509TrustManager|TrustManager\s*\[\s*\]|checkServerTrusted|checkClientTrusted|TrustAllCerts|TrustSelfSignedStrategy|TrustAllStrategy)\b") Then
            frmMain.ListCodeIssue("Custom Or Permissive TrustManager", "A custom TrustManager is defined. Where checkServerTrusted has an empty body, or getAcceptedIssuers returns null, every certificate is trusted and the connection provides no protection against active interception. This is the single most common TLS defect in Java and Android code.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "SSLContext\s*\.\s*getInstance\s*\(\s*""\s*(SSL|SSLv2|SSLv3|TLSv1|TLSv1\.1)\s*""") Then
            frmMain.ListCodeIssue("Obsolete TLS/SSL Protocol Version", "SSLv2, SSLv3, TLS 1.0 and TLS 1.1 are deprecated by RFC 8996 and vulnerable to POODLE and BEAST. Request TLSv1.2 or TLSv1.3.", FileName, CodeIssue.HIGH, CodeLine)
        End If

        '== Android specific ==
        If asAppSettings.IsAndroid = True Then
            If Regex.IsMatch(CodeLine, "\bonReceivedSslError\b") Or Regex.IsMatch(CodeLine, "\bSslErrorHandler\b[^;]*\.\s*proceed\s*\(") Then
                frmMain.ListCodeIssue("WebView SSL Errors Ignored", "onReceivedSslError calls proceed(), instructing the WebView to load content despite a certificate failure. Any network attacker can then serve arbitrary content into the WebView, which frequently has JavaScript bridges into native code.", FileName, CodeIssue.CRITICAL, CodeLine)
            End If
            If Regex.IsMatch(CodeLine, "usesCleartextTraffic\s*=\s*""true""") Or Regex.IsMatch(CodeLine, "cleartextTrafficPermitted\s*=\s*""true""") Then
                frmMain.ListCodeIssue("Cleartext Network Traffic Permitted", "The application manifest or network security configuration allows plain HTTP. Traffic is then readable and modifiable by anyone on the network path.", FileName, CodeIssue.HIGH, CodeLine)
            End If
        End If

    End Sub

    Private Sub CheckJavaPathTraversal(CodeLine As String, FileName As String)
        ' Identify filesystem operations driven by user-controlled data
        '==============================================================

        If Regex.IsMatch(CodeLine, "\bnew\s+(File|FileInputStream|FileOutputStream|FileReader|FileWriter|RandomAccessFile)\s*\(") Or _
           Regex.IsMatch(CodeLine, "\b(Paths\s*\.\s*get|Files\s*\.\s*(newInputStream|newOutputStream|readAllBytes|readAllLines|write|delete|copy|move))\s*\(") Then
            If IsUserInputJava(CodeLine) Then
                frmMain.ListCodeIssue("Potential Path Traversal", "A filesystem path is constructed from request data. Sequences such as '../' or an absolute path in the input allow an attacker to read, overwrite or delete files outside the intended directory - typically configuration files, key material or application code. Canonicalise with getCanonicalPath() and verify the result is still under the intended base directory, or map the input to a fixed set of identifiers.", FileName, CodeIssue.HIGH, CodeLine)
            End If
        End If

        '== Zip Slip ==
        If Regex.IsMatch(CodeLine, "\b(ZipEntry|TarArchiveEntry|ZipArchiveEntry)\b[^;]*\.\s*getName\s*\(") Or _
           (Regex.IsMatch(CodeLine, "\bgetNextEntry\s*\(") And Regex.IsMatch(CodeLine, "\bnew\s+File\s*\(")) Then
            frmMain.ListCodeIssue("Potential Zip Slip During Archive Extraction", "An archive entry name is used to build an output path. Entry names are attacker-controlled and may contain '../' sequences, allowing files to be written outside the extraction directory - overwriting web-accessible scripts, cron files or libraries and frequently achieving code execution. Resolve the destination and verify it starts with the canonical extraction root before writing.", FileName, CodeIssue.HIGH, CodeLine)
        End If

    End Sub

    Private Sub CheckJavaSSRF(CodeLine As String, FileName As String)
        ' Identify outbound requests whose destination is user-controlled
        '================================================================

        If Regex.IsMatch(CodeLine, "\bnew\s+(URL|URI|HttpGet|HttpPost|Request\.Builder)\s*\(") Or _
           Regex.IsMatch(CodeLine, "\b(RestTemplate|WebClient|HttpClient|OkHttpClient|URLConnection|HttpURLConnection|IOUtils\s*\.\s*toString)\b") Then
            If IsUserInputJava(CodeLine) Then
                frmMain.ListCodeIssue("Potential Server-Side Request Forgery (SSRF)", "The target of an outbound request appears to derive from user input. This allows an attacker to reach services bound to loopback or private ranges, to query cloud instance metadata endpoints for credentials, and to use the server as a proxy for port scanning. Validate against a host allow-list after DNS resolution, reject private and link-local addresses, and disable redirect following.", FileName, CodeIssue.HIGH, CodeLine)
            End If
        End If

    End Sub

    Private Sub CheckJavaExpressionInjection(CodeLine As String, FileName As String)
        ' Identify expression language, template and script injection sinks
        '==================================================================

        If Regex.IsMatch(CodeLine, "\b(SpelExpressionParser|ExpressionParser|parseExpression|StandardEvaluationContext)\b") Then
            frmMain.ListCodeIssue("Potential Spring Expression Language (SpEL) Injection", "A SpEL expression is parsed at runtime. SpEL permits arbitrary method invocation, including T(java.lang.Runtime).getRuntime().exec(), so an attacker-controlled expression yields remote code execution. Use SimpleEvaluationContext rather than StandardEvaluationContext and never build the expression from request data.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\b(Ognl\s*\.\s*(getValue|parseExpression)|MVEL\s*\.\s*(eval|executeExpression)|ELProcessor|ExpressionFactory\s*\.\s*createValueExpression)\b") Then
            frmMain.ListCodeIssue("Potential OGNL/MVEL/EL Injection", "An expression language interpreter evaluates a runtime string. These interpreters expose the full Java object graph and have historically produced critical remote code execution issues (for example the Struts 2 OGNL series). Remove the dynamic evaluation or restrict it to a sandboxed member access policy.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\b(ScriptEngineManager|ScriptEngine\s*\.\s*eval|GroovyShell|GroovyClassLoader|Binding\s*\(\s*\)|JexlEngine)\b") Then
            frmMain.ListCodeIssue("Runtime Script Evaluation", "A scripting engine (Nashorn, Groovy, JEXL) evaluates code at runtime. Where any portion of the script derives from user input this is a direct remote code execution primitive. Groovy in particular provides no sandbox by default.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\b(Velocity\s*\.\s*evaluate|freemarker\.template|new\s+Template\s*\(|TemplateEngine\s*\.\s*process|Pebble|Thymeleaf)\b") And IsUserInputJava(CodeLine) Then
            frmMain.ListCodeIssue("Potential Server-Side Template Injection", "A template is compiled from a string which appears to include user input. Velocity, FreeMarker and Thymeleaf all permit access to Java objects from within a template, converting template injection into code execution. Templates must be static resources; user data belongs in the model only.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If

    End Sub

    Private Sub CheckJavaJndiInjection(CodeLine As String, FileName As String)
        ' Identify JNDI lookups and logging patterns associated with Log4Shell
        '=====================================================================

        If Regex.IsMatch(CodeLine, "\b(InitialContext|InitialDirContext|Context\s*\.\s*lookup|\.lookup\s*\(|JndiTemplate|JndiObjectFactoryBean|RegistryConnector)\b") Then
            frmMain.ListCodeIssue("Potential JNDI Injection", "A JNDI lookup is performed. Where the name is influenced by user input an attacker supplies an ldap:// or rmi:// URI pointing at their own directory server, which returns a serialised or remote-classloading payload that the JVM instantiates - remote code execution. Restrict lookups to a fixed set of names and ensure com.sun.jndi.ldap.object.trustURLCodebase remains false.", FileName, CodeIssue.HIGH, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "\$\{jndi\s*:") Then
            frmMain.ListCodeIssue("JNDI Lookup Expression Present In Source", "A ${jndi:...} expression appears in the source or a resource file. This is the Log4Shell (CVE-2021-44228) exploitation syntax. Confirm whether this is a test artefact or a genuine lookup and verify the log4j-core version in use.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "log4j-core") And Regex.IsMatch(CodeLine, "\b(1\.\d|2\.([0-9]|1[0-6])(\.\d+)?)\b") Then
            frmMain.ListCodeIssue("Potentially Vulnerable log4j Version", "The dependency declaration references a log4j-core version at or below 2.16. Versions before 2.17.1 are affected by one or more of CVE-2021-44228, CVE-2021-45046 and CVE-2021-45105; log4j 1.x is end-of-life and carries its own JMSAppender deserialisation issue. Confirm the effective resolved version.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If

    End Sub

    Private Sub CheckJavaLdapXPath(CodeLine As String, FileName As String)
        ' Identify LDAP and XPath queries built through concatenation
        '============================================================

        If Regex.IsMatch(CodeLine, "\.\s*search\s*\(") And (CodeLine.Contains("+") Or Regex.IsMatch(CodeLine, "String\s*\.\s*format|concat\s*\(")) Then
            frmMain.ListCodeIssue("Potential LDAP Injection", "An LDAP search filter appears to be assembled by concatenation. Metacharacters such as '*', '(', ')' and '\' let an attacker rewrite the filter to authenticate without a password or to enumerate every entry in the directory. Escape input per RFC 4515 or bind the filter arguments using the Object[] overload of DirContext.search.", FileName, CodeIssue.HIGH, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "\bXPath\w*\b[^;]*\.\s*(compile|evaluate|selectNodes|selectSingleNode)\s*\(") And (CodeLine.Contains("+") Or CodeLine.Contains("concat")) Then
            frmMain.ListCodeIssue("Potential XPath Injection", "An XPath expression is built by concatenation. Injected quotes and boolean operators allow authentication bypass and disclosure of the whole XML document. Use XPathVariableResolver to bind values rather than embedding them in the expression.", FileName, CodeIssue.HIGH, CodeLine)
        End If

    End Sub

    Private Sub CheckSpringSecurityConfig(CodeLine As String, FileName As String)
        ' Identify weakened Spring Security and framework configuration
        '==============================================================

        If Regex.IsMatch(CodeLine, "\bcsrf\s*\(\s*\)\s*\.\s*disable\s*\(|csrf\s*\(\s*(AbstractHttpConfigurer\s*::\s*disable|\w+\s*->\s*\w+\s*\.\s*disable)") Then
            frmMain.ListCodeIssue("CSRF Protection Disabled", "Spring Security's CSRF filter has been switched off. Where the application authenticates using cookies this allows any site to trigger state-changing requests with the victim's session. Disabling CSRF is only defensible for a stateless API that authenticates solely via a bearer token which is never sent automatically by the browser.", FileName, CodeIssue.HIGH, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "\banyRequest\s*\(\s*\)\s*\.\s*(permitAll|anonymous)\s*\(") Then
            frmMain.ListCodeIssue("All Requests Permitted Without Authentication", "The security configuration allows every request without authentication. Confirm that authorisation is genuinely enforced elsewhere, for example by method-level annotations.", FileName, CodeIssue.HIGH, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "@CrossOrigin\s*\(\s*(origins\s*=\s*)?""\s*\*|setAllowedOrigins\s*\([^\)]*""\s*\*|addAllowedOrigin\s*\(\s*""\s*\*") Then
            frmMain.ListCodeIssue("Overly Permissive CORS Configuration", "Any origin may read responses from this endpoint. Where combined with setAllowCredentials(true) this permits authenticated cross-origin reads from arbitrary sites, which is a full account compromise primitive.", FileName, CodeIssue.HIGH, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "\b(NoOpPasswordEncoder|withDefaultPasswordEncoder|StandardPasswordEncoder|MessageDigestPasswordEncoder)\b") Then
            frmMain.ListCodeIssue("Insecure Password Encoder", "NoOpPasswordEncoder stores passwords in cleartext; StandardPasswordEncoder and MessageDigestPasswordEncoder use a fast digest that is unsuitable for password storage and are deprecated. Use BCryptPasswordEncoder or Argon2PasswordEncoder via DelegatingPasswordEncoder.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "\b(headers\s*\(\s*\)\s*\.\s*(frameOptions|disable)|frameOptions\s*\(\s*\)\s*\.\s*disable)\b") Then
            frmMain.ListCodeIssue("Security Response Headers Disabled", "Framing protection or the default security header set has been disabled, exposing users to clickjacking and removing MIME-sniffing and referrer protections.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "\b(actuator|management\.endpoints\.web\.exposure\.include)\b") And Regex.IsMatch(CodeLine, "(\*|env|heapdump|threaddump|jolokia|shutdown)") Then
            frmMain.ListCodeIssue("Spring Actuator Endpoints Broadly Exposed", "Management endpoints are exposed. /env and /configprops disclose configuration including credentials, /heapdump yields a full memory image containing session tokens, and /jolokia has repeatedly been used to reach remote code execution. Expose only /health and require authentication.", FileName, CodeIssue.HIGH, CodeLine)
        End If

    End Sub

    Private Sub CheckJavaJwt(CodeLine As String, FileName As String)
        ' Identify weak JSON Web Token handling
        '======================================

        If Regex.IsMatch(CodeLine, "\.\s*(parseClaimsJwt|parsePlaintextJwt)\s*\(") Then
            frmMain.ListCodeIssue("Unsigned JWT Accepted", "parseClaimsJwt parses an unsigned token. Every claim it returns - including identity and roles - is supplied by the client with no cryptographic verification. Use parseClaimsJws with a configured signing key.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\bAlgorithm\s*\.\s*none\s*\(|""\s*alg\s*""\s*:\s*""\s*none") Then
            frmMain.ListCodeIssue("JWT 'none' Algorithm In Use", "The 'none' algorithm disables signature verification entirely, allowing any client to mint a token with arbitrary claims.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\b(setSigningKey|Algorithm\s*\.\s*HMAC\d+)\s*\(\s*""[^""]{1,}""") Then
            frmMain.ListCodeIssue("Hard-Coded JWT Signing Secret", "The HMAC secret used to sign tokens is a literal in source. Recovery of the secret allows an attacker to forge tokens for any user. Store it in a secrets manager and ensure it carries at least 256 bits of entropy - short secrets are also recoverable by offline brute force against a captured token.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\b(requireExpiration|setAllowedClockSkewSeconds)\s*\(\s*\d{4,}") Then
            frmMain.ListCodeIssue("Excessive JWT Clock Skew Tolerance", "A very large clock skew allowance effectively extends token lifetime well beyond the stated expiry, increasing the window in which a stolen token remains usable.", FileName, CodeIssue.LOW, CodeLine)
        End If

    End Sub

    Private Sub CheckJavaDeserializationExtended(CodeLine As String, FileName As String)
        ' Additional deserialization surfaces beyond the existing check
        '==============================================================

        If Regex.IsMatch(CodeLine, "\bnew\s+XStream\s*\(") Then
            frmMain.ListCodeIssue("XStream Deserialization", "XStream reconstructs arbitrary types named in the XML document. Unless an explicit allow-list is configured via addPermission/allowTypes this is a remote code execution sink with a long history of bypasses. Configure XStream.setupDefaultSecurity and an explicit type allow-list.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\b(enableDefaultTyping|activateDefaultTyping|JSON\s*\.\s*parseObject\s*\([^\)]*Feature\.SupportAutoType|@JsonTypeInfo\s*\(\s*use\s*=\s*Id\.CLASS)\b") Then
            frmMain.ListCodeIssue("Polymorphic Type Handling Enabled In JSON Parser", "Jackson default typing (or Fastjson AutoType) instantiates the class named inside the JSON document. Numerous gadget chains exist in common libraries that turn this into remote code execution. Disable default typing, or restrict it with a strict PolymorphicTypeValidator.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\bnew\s+Yaml\s*\(\s*\)|Yaml\s*\.\s*load\s*\(") Then
            frmMain.ListCodeIssue("Unsafe YAML Deserialization", "SnakeYAML's default constructor permits arbitrary type instantiation through the !!javaObject tag, which is a known code execution sink. Use new Yaml(new SafeConstructor()) or Yaml.loadAs with an explicit type.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\bBeanUtils\s*\.\s*populate|\bBeanUtilsBean\b|\bWrapDynaBean\b") Then
            frmMain.ListCodeIssue("Potential Mass Assignment Via BeanUtils", "BeanUtils.populate sets bean properties from a request map. Where the bean exposes a 'class' getter this reaches the classloader (the Struts/Spring 'class.module.classLoader' issue) and permits remote code execution; more generally it permits over-posting of privileged fields.", FileName, CodeIssue.HIGH, CodeLine)
        End If

    End Sub

    Private Sub CheckJavaHardcodedSecrets(CodeLine As String, FileName As String)
        ' Identify credentials and API keys embedded in source or resources
        '==================================================================

        If Regex.IsMatch(CodeLine, "AKIA[0-9A-Z]{16}") Then
            frmMain.ListCodeIssue("Hard-Coded AWS Access Key", "A string matching the AWS access key ID format is present. Revoke it and move to an instance role or a secrets manager.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "(gh[pousr]_[A-Za-z0-9]{36}|xox[baprs]-[A-Za-z0-9\-]{10,}|sk_live_[0-9a-zA-Z]{24,}|AIza[0-9A-Za-z\-_]{35})") Then
            frmMain.ListCodeIssue("Hard-Coded Third-Party API Token", "A GitHub, Slack, Stripe or Google API token appears to be embedded in source or resources.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "-----BEGIN\s+(RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE KEY") Then
            frmMain.ListCodeIssue("Private Key Embedded In Source", "A PEM-encoded private key is stored in the repository. The associated identity must be treated as compromised.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "(?i)\b(String|char\s*\[\s*\]|final)\b[^=]*\b\w*(password|passwd|pwd|secret|apikey|api_key|token|privatekey|clientsecret|keystorepass)\w*\s*=\s*""[^""]{3,}""") Then
            frmMain.ListCodeIssue("Hard-Coded Secret Assigned To Variable", "A field whose name indicates a credential is initialised with a literal. String constants are stored in the class constant pool and are recovered directly from the compiled artefact.", FileName, CodeIssue.HIGH, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "jdbc:[a-z]+://[^""]*(password|pwd)=") Then
            frmMain.ListCodeIssue("Database Password In JDBC URL", "A JDBC connection string contains an inline password. Connection strings are frequently written to logs and stack traces.", FileName, CodeIssue.HIGH, CodeLine)
        End If

    End Sub

    Private Sub CheckJavaLogging(CodeLine As String, FileName As String)
        ' Identify sensitive data and unsanitised input written to logs
        '==============================================================

        If Regex.IsMatch(CodeLine, "\b(log|logger|LOG|LOGGER|System\s*\.\s*(out|err))\b[^;]*\.\s*(debug|info|warn|error|trace|print|println)\s*\(") Then
            If Regex.IsMatch(CodeLine, "(?i)\b\w*(password|passwd|pwd|secret|token|apikey|api_key|creditcard|ssn|cvv|authorization|sessionid|cookie)\w*\b") Then
                frmMain.ListCodeIssue("Sensitive Data Written To Log", "A credential, token or other sensitive value appears to be written to the application log. Logs are typically retained longer than the data, replicated to aggregation platforms and readable by a far wider audience than the production database.", FileName, CodeIssue.HIGH, CodeLine)
            ElseIf IsUserInputJava(CodeLine) Then
                frmMain.ListCodeIssue("Unsanitised User Input Written To Log", "Request data is written to the log without neutralising carriage return and line feed characters. An attacker can therefore forge additional log entries, obscuring their activity or misleading incident responders. Where logs are rendered in a web console this also becomes stored cross-site scripting.", FileName, CodeIssue.MEDIUM, CodeLine)
            End If
        End If

    End Sub

    Private Sub CheckAndroidComponentSecurity(CodeLine As String, FileName As String)
        ' Android-specific component, storage and WebView issues
        '=======================================================

        If asAppSettings.IsAndroid = False Then Exit Sub

        '== WebView configuration ==
        If Regex.IsMatch(CodeLine, "\baddJavascriptInterface\s*\(") Then
            frmMain.ListCodeIssue("WebView JavaScript Bridge Exposed", "addJavascriptInterface exposes a Java object to any page loaded in the WebView. On API levels below 17 this permits reflection to Runtime.exec from JavaScript; on later levels only @JavascriptInterface methods are reachable, but any such method still becomes an entry point for hostile content loaded over a compromised connection.", FileName, CodeIssue.HIGH, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\b(setAllowFileAccessFromFileURLs|setAllowUniversalAccessFromFileURLs|setAllowFileAccess|setAllowContentAccess)\s*\(\s*true\s*\)") Then
            frmMain.ListCodeIssue("WebView Local File Access Enabled", "The WebView is permitted to read local files or to grant file:// pages universal origin access. A single cross-site scripting flaw, or any redirect to a file:// URL, then allows exfiltration of the application's private data directory.", FileName, CodeIssue.HIGH, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "setJavaScriptEnabled\s*\(\s*true\s*\)") Then
            frmMain.ListCodeIssue("JavaScript Enabled In WebView", "JavaScript execution is enabled. Confirm that only trusted, integrity-protected content is ever loaded and that a WebViewClient restricts navigation to an allow-list of hosts.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

        '== Insecure local storage ==
        If Regex.IsMatch(CodeLine, "\bMODE_WORLD_(READABLE|WRITEABLE|WRITABLE)\b") Then
            frmMain.ListCodeIssue("World-Accessible File Mode", "The file or preference store is created with world-readable or world-writable permissions, exposing it to every other application on the device. These modes have been deprecated and throw SecurityException from API 24 onwards.", FileName, CodeIssue.HIGH, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\b(getExternalStorageDirectory|getExternalFilesDir|getExternalCacheDir|Environment\s*\.\s*DIRECTORY_)\b") Then
            frmMain.ListCodeIssue("Data Written To External Storage", "External storage is world-readable to any application holding READ_EXTERNAL_STORAGE and survives application uninstall. Sensitive material must be kept in internal storage, and encrypted where the device may be rooted.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\bgetSharedPreferences\s*\(") And Regex.IsMatch(CodeLine, "(?i)(password|token|secret|key|credential)") Then
            frmMain.ListCodeIssue("Credentials In SharedPreferences", "SharedPreferences are stored as plaintext XML in the application data directory, which is readable on a rooted or backed-up device. Use EncryptedSharedPreferences or the Android Keystore.", FileName, CodeIssue.HIGH, CodeLine)
        End If

        '== Exported components and backup ==
        If Regex.IsMatch(CodeLine, "android:exported\s*=\s*""true""") Then
            frmMain.ListCodeIssue("Exported Application Component", "The component is reachable by any other application on the device. Unless it is protected by a signature-level permission, confirm that it performs its own authorisation checks and validates all Intent extras.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "android:(allowBackup|debuggable)\s*=\s*""true""") Then
            frmMain.ListCodeIssue("Backup Or Debug Flag Enabled In Manifest", "allowBackup permits the full application data directory to be extracted over ADB without root; debuggable allows a debugger to attach to the production application and read process memory. Both must be false in release builds.", FileName, CodeIssue.HIGH, CodeLine)
        End If

        '== Broadcast and pending intents ==
        If Regex.IsMatch(CodeLine, "\bsendBroadcast\s*\(") And Not CodeLine.Contains("permission") Then
            frmMain.ListCodeIssue("Unprotected Broadcast Sent", "The broadcast is sent without a receiver permission, so any application registered for the action receives the Intent and its extras. Use LocalBroadcastManager or specify a signature-level permission.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\bPendingIntent\s*\.\s*get(Activity|Broadcast|Service)\s*\(") And Not Regex.IsMatch(CodeLine, "FLAG_IMMUTABLE") Then
            frmMain.ListCodeIssue("Mutable PendingIntent", "A PendingIntent is created without FLAG_IMMUTABLE. The receiving application can fill in the unpopulated fields and cause the Intent to be dispatched with this application's identity and permissions.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

    End Sub
End Module
