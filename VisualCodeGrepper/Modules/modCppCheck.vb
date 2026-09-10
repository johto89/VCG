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

Module modCppCheck

    ' Specific checks for C++ code
    '=============================

    Public Sub CheckCPPCode(CodeLine As String, FileName As String)
        ' Carry out any specific checks for the language in question
        '
        ' else-ifs have been avoided throughout due to C-programmers' tendency to efficiently   
        ' cram multiple functions into one line in one way or another.
        '====================================================================================

        TrackVarAssignments(CodeLine, FileName)     ' Check for matching new/delete, etc.
        TrackUserVarAssignments(CodeLine, FileName) ' Track any variables which are passed in on the command line, from files, etc.
        CheckBuffer(CodeLine, FileName)             ' Track buffer sizes and check for overflows
        CheckDestructorThrow(CodeLine, FileName)    ' Identify entry to class destructor, report any exception throw within destructor
        CheckRace(CodeLine, FileName)               ' Check for race conditions and TOCTOU vulns
        CheckPrintF(CodeLine, FileName)             ' Check for printf format string vulnerabilities
        CheckUnsafeTempFiles(CodeLine, FileName)    ' Check for static/obvious filenames for temp files
        CheckReallocFailure(CodeLine, FileName)     ' Check for 'free' on failure
        CheckUnsafeSafe(CodeLine, FileName)         ' Check unsafe use of return values from 'safe' functions
        CheckCmdInjection(CodeLine, FileName)       ' Check for potential command injection

        '== Extended ruleset ==
        CheckCppWeakCrypto(CodeLine, FileName)          ' Broken hashes/ciphers, disabled TLS verification, weak PRNG
        CheckCppFormatString(CodeLine, FileName)        ' Format string sinks, unbounded scanf, snprintf return misuse
        CheckCppIntegerIssues(CodeLine, FileName)       ' Allocation arithmetic, alloca, signed lengths, off-by-one
        CheckCppMemoryLifecycle(CodeLine, FileName)     ' Mismatched allocators, dangling pointers, stack address return
        CheckCppPrivilegeManagement(CodeLine, FileName) ' Privilege drop order, chroot, permissions, exec environment
        CheckCppPathHandling(CodeLine, FileName)        ' Path traversal, access() TOCTOU, unsafe temp file naming
        CheckCppHardcodedSecrets(CodeLine, FileName)    ' Credentials and private keys embedded in the binary
        CheckCppConcurrency(CodeLine, FileName)         ' Signal handler safety and non re-entrant library functions
        CheckCppErrorHandling(CodeLine, FileName)       ' Unchecked allocation and security-critical return values

        '== Beta functionality ==
        If asAppSettings.IncludeSigned Then
            CheckSigned(CodeLine, FileName)         ' Check for signed/unsigned integer comparisons
        End If

    End Sub

    Private Sub TrackVarAssignments(CodeLine As String, FileName As String)
        ' Keep record of malloc/new and track matching free and delete
        ' Mismatches and potential errors will be added to the CodeTracker dictionary
        '============================================================================

        '== Track 'malloc', 'new', etc. ==
        If (CodeLine.Contains("malloc ") Or CodeLine.Contains("malloc(")) Then
            ctCodeTracker.AddMalloc(CodeLine, FileName)

            '== Check for a 'fixed' malloc using numeric value instead of data type ==
            If Regex.IsMatch(CodeLine, "\b(malloc|xmalloc)\b\s*\(\s*\d+\s*\)") Then
                frmMain.ListCodeIssue("malloc( ) Using Fixed Value Instead of Variable Type Size", "The code uses a fixed value for malloc instead of the variable type size which is dependent on the platform (e.g. sizeof(int) instead of '4'). This can result in too much or too little memory being assigned with unpredicatble results such as performance impact, overflows or memory corruption.", FileName, CodeIssue.MEDIUM, CodeLine)
            End If
        End If

        If (CodeLine.Contains("new ") Or CodeLine.Contains("new(")) Then ctCodeTracker.AddNew(CodeLine, FileName)

        '== Check for matching 'free', 'delete', etc. ==
        If (CodeLine.Contains("free ") Or CodeLine.Contains("free(")) Then ctCodeTracker.AddFree(CodeLine, FileName)
        If (CodeLine.Contains("delete ") Or CodeLine.Contains("delete(")) Then ctCodeTracker.AddDelete(CodeLine, FileName)

    End Sub

    Private Sub TrackUserVarAssignments(CodeLine As String, FileName As String)
        ' Keep record of user-controlled variables
        '=========================================
        Dim arrFragments As String()
        Dim strLeft As String = ""


        '== Track assignments from argv, system variables, ini files or registry ==
        If (Regex.IsMatch(CodeLine, "\w+\s*\=\s*\bargv\b\s*\[")) Or (Regex.IsMatch(CodeLine, "\w+\s*\=\s*\b(getenv|GetPrivateProfileString|GetPrivateProfileInt)\b\s*\(")) Or (Regex.IsMatch(CodeLine, "\w+\s*\=\s*Registry\:\:\w+\-\>OpenSubKey")) Then
            ' Extract the variable name
            arrFragments = CodeLine.Split("=")
            strLeft = GetLastItem(arrFragments.First)
        End If

        '== Store any discovered variables
        If strLeft <> "" Then
            If Not ctCodeTracker.UserVariables.Contains(strLeft) Then
                ctCodeTracker.UserVariables.Add(strLeft)
            End If
        End If

    End Sub

    Private Sub CheckBuffer(CodeLine As String, FileName As String)
        ' Keep record of integer assignments and char arrays
        ' Add to the CodeTracker dictionary for checking
        '===================================================
        Dim arrFragments As String()
        Dim strLeft As String = ""


        '== Keep track of int/short/long variables and constants to help with detection of buffer overflows, etc. ==
        '== Check for assignment and check it's not an array ==
        If CodeLine.Contains("=") And Not (CodeLine.Contains("==") Or CodeLine.Contains("*") Or CodeLine.Contains("[")) And _
                                           (Regex.IsMatch(CodeLine, "\b(short|int|long|uint16|uint32|size_t|UINT|INT|LONG)\b")) Then
            ctCodeTracker.AddInteger(CodeLine)
        ElseIf Regex.IsMatch(CodeLine, "\s*\w+\s*\=") And Not CodeLine.Contains("==") Then
            arrFragments = CodeLine.Split("=")
            strLeft = GetLastItem(arrFragments.First)
            'For Each itmItem In ctCodeTracker.GetIntegers
            If ctCodeTracker.GetIntegers.ContainsKey(strLeft) Then
                ctCodeTracker.AddInteger(CodeLine)
                'Exit For
            End If
            'Next
        End If

        '== Track fixed buffers, char pointers, etc. to check for overflows (avoid recording any arrays of pointers) ==
        If Regex.IsMatch(CodeLine, "\b(char|TCHAR|BYTE)\b") And CodeLine.Contains("[") And CodeLine.Contains("]") Then ctCodeTracker.AddBuffer(CodeLine)
        If Regex.IsMatch(CodeLine, "\b(char|TCHAR|BYTE)\b") And CodeLine.Contains("*") Then ctCodeTracker.AddCharStar(CodeLine)

        '== Check strcpy for potential buffer overflows, using buffer list ==
        'If CodeLine.Contains("strcpy") Or CodeLine.Contains("strcat") Or CodeLine.Contains("strncpy") Or CodeLine.Contains("strncat") Or CodeLine.Contains("sprintf") Or CodeLine.Contains("memcpy") Or CodeLine.Contains("memmove") Then ctCodeTracker.CheckOverflow(CodeLine, FileName)
        If Regex.IsMatch(CodeLine, "\b(strcpy|strlcpy|strcat|strlcat|strncpy|strncat|sprintf|memcpy|memmove)\b") Then ctCodeTracker.CheckOverflow(CodeLine, FileName)

    End Sub

    Private Sub CheckSigned(CodeLine As String, FileName As String)
        ' Keep record of unsigned int assignments and add to CodeTracker dictionary
        ' Identify any signed/unsigned comparisons
        '==========================================================================

        '== Identify any unsigned integers ==
        If Regex.IsMatch(CodeLine, "\b(unsigned|UNSIGNED|size_t|uint16|uint32)\b") Then
            ctCodeTracker.AddUnsigned(CodeLine)
        End If

        '== Check for signed/unsigned integer comparisons ==
        If (CodeLine.Contains("==") Or CodeLine.Contains("!=") Or CodeLine.Contains("<") Or CodeLine.Contains(">")) _
            And Not (CodeLine.Contains("->") Or CodeLine.Contains(">>") Or CodeLine.Contains("<<") Or CodeLine.Contains("<>")) And Not Regex.IsMatch(CodeLine, "\<\s*\w+\s*\>") And Not Regex.IsMatch(CodeLine, "\<\s*\w+\s*\w+\s*\>") Then
            If ctCodeTracker.CheckSignedComp(CodeLine) Then frmMain.ListCodeIssue("Signed/Unsigned Comparison", "The code appears to compare a signed numeric value with an unsigned numeric value. This behaviour can return unexpected results as negative numbers will be forcibly cast to large positive numbers.", FileName, CodeIssue.HIGH, CodeLine)
        End If

    End Sub

    Private Sub CheckUnsafeSafe(CodeLine As String, FileName As String)
        ' Check for use of dubious return values from'safe' functions 
        '============================================================

        '== Identify any returned values being assigned to variables ==
        If Regex.IsMatch(CodeLine, "w+\s*\=\s*\b(snprintf|strlcpy|strlcat|strlprintf|std_strlcpy|std_strlcat|std_strlprintf)\b") Then
            frmMain.ListCodeIssue("Potential Misuse of Safe Function", "The code appears to assign the return value of a 'safe' function to a variable. This value represents the amount of bytes that the function attempted to write, not the amount actually written. Any use of this value for pointer arithmetic similar operations may result in memory corruption", FileName, CodeIssue.HIGH, CodeLine)
        End If

    End Sub

    Private Sub CheckDestructorThrow(CodeLine As String, FileName As String)
        ' Identify entry and exit points of destructor in CodeTracker
        ' Report any exception throw within destructor
        '============================================================
        Dim blnHasCheckedBraces As Boolean = False

        '== Check for entry to/exit from destructor ==
        If ctCodeTracker.IsDestructor = False And ((CodeLine.Contains("::~") Or CodeLine.Contains(":: ~") Or CodeLine.Contains(" ~")) And Not CodeLine.Contains(";")) Then
            ctCodeTracker.DestructorBraces = 0
            If CodeLine.Contains("{") Then
                ctCodeTracker.IsDestructor = ctCodeTracker.TrackBraces(CodeLine, ctCodeTracker.DestructorBraces)
                blnHasCheckedBraces = True
            Else
                ctCodeTracker.IsDestructor = True
            End If
        End If

        '== Check for any exceptions while in destructor ==
        If ctCodeTracker.IsDestructor = True Then
            If (CodeLine.Contains("throw") And ctCodeTracker.DestructorBraces > 0) Then
                frmMain.ListCodeIssue("Exception Throw in Destructor", "Throwing an exception causes an exit from the function and should not be carried out in a class destructor as it prevents memory from being safely deallocated. If the destructor is being called due to an exception thrown elsewhere in the application this will result in unexpected termination of the application with possible loss or corruption of data.", FileName)
            End If
            If Not blnHasCheckedBraces Then ctCodeTracker.IsDestructor = ctCodeTracker.TrackBraces(CodeLine, ctCodeTracker.DestructorBraces)
        End If

    End Sub

    Private Sub CheckRace(CodeLine As String, FileName As String)
        ' Check for potential TOCTOU/race conditions
        '===========================================

        Dim intSeverity As Integer = 0  ' For TOCTOU vulns, severity will be modified according to length of time between check and usage.


        '== Check for TOCTOU (Time Of Check, Time Of Use) vulnerabilities==
        If (Not ctCodeTracker.IsLstat) And (CodeLine.Contains(" lstat(") Or CodeLine.Contains(" lstat ") Or CodeLine.Contains(" stat(") Or CodeLine.Contains(" stat ")) And ((Not CodeLine.Contains("fopen")) And (Not CodeLine.Contains("opendir"))) Then
            ' Check has taken place - begin monitoring for use of the file/dir
            ctCodeTracker.IsLstat = True
        ElseIf ctCodeTracker.IsLstat Then
            ' Increase line count while monitoring
            ctCodeTracker.TocTouLineCount += 1
            If ctCodeTracker.TocTouLineCount < 2 And (CodeLine.Contains("fopen") Or CodeLine.Contains("opendir")) Then
                ' Usage takes place almost immediately so no problem
                ctCodeTracker.IsLstat = False
            ElseIf ctCodeTracker.TocTouLineCount > 1 And (CodeLine.Contains("fopen") Or CodeLine.Contains("opendir")) Then
                ' Usage takes place sometime later. Set severity accordingly and notify user
                ctCodeTracker.IsLstat = False
                If ctCodeTracker.TocTouLineCount > 5 Then intSeverity = 2
                frmMain.ListCodeIssue("Potential TOCTOU (Time Of Check, Time Of Use) Vulnerability", "The lstat() check occurs " & ctCodeTracker.TocTouLineCount & " lines before fopen() is called. The longer the time between the check and the fopen(), the greater the likelihood that the check will no longer be valid.", FileName)
            End If
        End If

    End Sub

    Private Sub CheckPrintF(CodeLine As String, FileName As String)
        ' Check for printf format string vulnerabilities 
        '===============================================

        If Regex.IsMatch(CodeLine, "\bprintf\b\s*\(\s*\w+\s*\)") And Not CodeLine.Contains(",") And Not CodeLine.Contains("""") Then
            frmMain.ListCodeIssue("Possible printf( ) Format String Vulnerability", "The call to printf appears to be printing a variable directly to standard output. Check whether this variable can be controlled or altered by the user to determine whether a format string vulnerability exists.", FileName, CodeIssue.HIGH, CodeLine)
        End If

    End Sub

    Private Sub CheckUnsafeTempFiles(CodeLine As String, FileName As String)
        ' Identify any creation of temp files with static names
        '======================================================

        If Regex.IsMatch(CodeLine, "\=\s*(_open|open|fopen|opendir)\s*\(\s*\""*\S*(temp|tmp)\S*\""\s*\,\s*\S*\s*\)") Then
            frmMain.ListCodeIssue("Unsafe Temporary File Allocation", "The application appears to create a temporary file with a static, hard-coded name. This causes security issues in the form of a classic race condition (an attacker creates a file with the same name between the application's creation and attempted usage) or a symbolic link attack where an attacker creates a symbolic link at the temporary file location.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

    End Sub

    Private Sub CheckReallocFailure(CodeLine As String, FileName As String)
        ' Identify any attempts to resize buffers that do not clear the buffer on failure
        '================================================================================
        Dim arrFragments As String()
        Dim strBuffer As String = ""
        Dim strDestination As String = ""


        '== Identify occurences of realloc ==
        If Regex.IsMatch(CodeLine, "\brealloc\b\s*\(") Then
            '== Extract variable names ==
            arrFragments = Regex.Split(CodeLine, "\=\s*\brealloc\b\s*\(")
            If arrFragments.Count < 2 Then Exit Sub

            '== Make sure we have the variable name and nothing else ==
            If arrFragments.First.Contains("(") Then
                strDestination = GetLastItem(arrFragments.First, "(")
                strDestination = GetLastItem(strDestination)
            Else
                strDestination = GetLastItem(arrFragments.First)
            End If

            If strDestination <> "" Then
                strBuffer = GetFirstItem(arrFragments(1), ",")
                If strDestination = strBuffer Then
                    frmMain.ListCodeIssue("Dangerous Use of realloc( )", "The source and destination buffers are the same. A failure to resize the buffer will set the pointer to NULL, possibly causing unpredicatable behaviour.", FileName, CodeIssue.MEDIUM, CodeLine)
                End If
                strDestination = strDestination.TrimStart("*").TrimStart()
                strBuffer = strBuffer.TrimStart("*").TrimStart()

                ctCodeTracker.DestinationBuffer = strDestination
                ctCodeTracker.SourceBuffer = strBuffer
            End If

        ElseIf ctCodeTracker.DestinationBuffer <> "" Then

            If Regex.IsMatch(ctCodeTracker.DestinationBuffer, "(\(|\)|\[|\])") Or Regex.IsMatch(ctCodeTracker.SourceBuffer, "(\(|\)|\[|\])") Then
                ctCodeTracker.DestinationBuffer = ""
                ctCodeTracker.SourceBuffer = ""
                Exit Sub
            End If
            If Regex.IsMatch(CodeLine, "\bfree\b\s*\(\s*(" & ctCodeTracker.DestinationBuffer & "|" & ctCodeTracker.SourceBuffer & ")") Then
                ctCodeTracker.DestinationBuffer = ""
                ctCodeTracker.SourceBuffer = ""
            ElseIf Regex.IsMatch(CodeLine, "(break|return|exit)") Then
                frmMain.ListCodeIssue("Potential Memory Leak", "On failure, the realloc function returns a NULL pointer but leaves memory allocated. The code should be modified to free the memory if NULL is returned.", FileName, CodeIssue.MEDIUM, CodeLine)
                ctCodeTracker.DestinationBuffer = ""
                ctCodeTracker.SourceBuffer = ""
            End If

        End If

    End Sub

    Private Sub CheckCmdInjection(CodeLine As String, FileName As String)
        ' Check for potential command injection
        '======================================
        Dim blnIsFound As Boolean = False


        '== Are commands being passed to system? ==
        If Regex.IsMatch(CodeLine, "\b(system|popen|execlp)\b\s*\(") Then

            '== Is a user-controlled variable present? ==
            For Each strVar In ctCodeTracker.UserVariables
                If CodeLine.Contains(strVar) Then
                    frmMain.ListCodeIssue("User Controlled Variable Used on System Command Line", "The application appears to allow the use of an unvalidated user-controlled variable [" + strVar + "] when executing a system command.", FileName, CodeIssue.HIGH, CodeLine)
                    blnIsFound = True
                    Exit For
                End If
            Next
            If blnIsFound = False And (Regex.IsMatch(CodeLine, "\b(system|popen|execlp)\b\s*\(\s*\bgetenv\b")) Then
                '== Is a system variable present? ==
                frmMain.ListCodeIssue("Application Variable Used on System Command Line", "The application appears to allow the use of an unvalidated system variable when executing a system command.", FileName, CodeIssue.HIGH, CodeLine)
            ElseIf blnIsFound = False And ((Not CodeLine.Contains("""")) Or (CodeLine.Contains("""") And CodeLine.Contains("+")) Or (Regex.IsMatch(CodeLine, "\b(system|popen|execlp)\b\s*\(\s*\b(strcat|strncat)\b"))) Then
                '== Is an unidentified variable present? ==
                frmMain.ListCodeIssue("Application Variable Used on System Command Line", "The application appears to allow the use of an unvalidated variable when executing a system command. Carry out a manual check to determine whether the variable is user-controlled.", FileName, CodeIssue.MEDIUM, CodeLine)
            End If
        End If

    End Sub


    '======================================================================================
    '== EXTENDED RULESET                                                                 ==
    '== Additional checks appended without altering any pre-existing logic.              ==
    '======================================================================================

    Private Function IsUserInputCpp(CodeLine As String) As Boolean
        ' Return True where the line appears to reference a tainted (user-controlled) source
        '==================================================================================

        If Regex.IsMatch(CodeLine, "\b(argv|getenv|scanf|fscanf|sscanf|gets|fgets|read|recv|recvfrom|fread|getline|GetEnvironmentVariable|ReadFile|GetPrivateProfileString)\b") Then Return True

        For Each strVar In ctCodeTracker.UserVariables
            If strVar <> "" AndAlso CodeLine.Contains(strVar) Then Return True
        Next

        Return False

    End Function

    Private Sub CheckCppWeakCrypto(CodeLine As String, FileName As String)
        ' Identify broken cryptographic primitives and weak TLS configuration
        '====================================================================

        '== Broken hash algorithms ==
        If Regex.IsMatch(CodeLine, "\b(MD2|MD4|MD5|SHA1|RIPEMD160)_(Init|Update|Final)\b") Or _
           Regex.IsMatch(CodeLine, "\bEVP_(md2|md4|md5|sha1|ripemd160)\s*\(") Or _
           Regex.IsMatch(CodeLine, "\bCryptCreateHash\s*\([^\)]*CALG_(MD2|MD4|MD5|SHA1)\b") Then
            frmMain.ListCodeIssue("Use of Broken Hashing Algorithm", "MD2, MD4, MD5 and SHA-1 are collision-vulnerable and unsuitable for signatures, integrity checks or password storage. Use SHA-256 or SHA-3 via the EVP interface.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

        '== Broken ciphers ==
        If Regex.IsMatch(CodeLine, "\bEVP_(des|des_ede3|rc2|rc4|bf|idea)_\w*\s*\(") Or _
           Regex.IsMatch(CodeLine, "\b(DES|RC2|RC4|Blowfish)_(set_key|ecb_encrypt|cbc_encrypt|encrypt)\b") Or _
           Regex.IsMatch(CodeLine, "CALG_(DES|3DES|RC2|RC4)\b") Then
            frmMain.ListCodeIssue("Use of Broken Symmetric Cipher", "DES, Triple-DES, RC2, RC4, Blowfish and IDEA are all obsolete. DES is brute-forceable, RC4 leaks plaintext through keystream biases, and the 64-bit block ciphers are subject to Sweet32. Use AES-256-GCM.", FileName, CodeIssue.HIGH, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\bEVP_\w+_ecb\s*\(") Then
            frmMain.ListCodeIssue("Use of ECB Cipher Mode", "ECB encrypts each block independently so plaintext structure is preserved in the ciphertext and blocks can be reordered by an attacker. Use GCM.", FileName, CodeIssue.HIGH, CodeLine)
        End If

        '== TLS verification and protocol selection ==
        If Regex.IsMatch(CodeLine, "SSL_VERIFY_NONE") Or Regex.IsMatch(CodeLine, "SSL_CTX_set_verify\s*\([^,]+,\s*SSL_VERIFY_NONE") Then
            frmMain.ListCodeIssue("TLS Peer Verification Disabled", "SSL_VERIFY_NONE instructs OpenSSL to complete the handshake regardless of certificate validity, so the connection provides no authentication and no protection against active interception. Use SSL_VERIFY_PEER and verify the hostname explicitly with X509_check_host - OpenSSL does not check the hostname for you.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\b(SSLv2|SSLv3|TLSv1|TLSv1_1)_(client_|server_)?method\s*\(") Then
            frmMain.ListCodeIssue("Obsolete TLS/SSL Protocol Version Selected", "SSLv2, SSLv3, TLS 1.0 and TLS 1.1 are deprecated by RFC 8996 and vulnerable to downgrade, POODLE and BEAST attacks. Use TLS_method() with a minimum version of TLS 1.2.", FileName, CodeIssue.HIGH, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "curl_easy_setopt\s*\([^,]+,\s*CURLOPT_SSL_VERIFY(PEER|HOST)\s*,\s*0") Then
            frmMain.ListCodeIssue("cURL TLS Verification Disabled", "Certificate or hostname verification is switched off, reducing TLS to unauthenticated encryption.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If

        '== Weak randomness ==
        If Regex.IsMatch(CodeLine, "\b(rand|random|srand|srandom|drand48|lrand48)\s*\(") Then
            frmMain.ListCodeIssue("Use of Non-Cryptographic Random Number Generator", "rand() and its relatives are deterministic pseudo-random generators with small internal state. Where the output is used for keys, tokens, nonces, salts or address-space randomisation the value is predictable. Use a CSPRNG - getrandom(), /dev/urandom, RAND_bytes() or BCryptGenRandom().", FileName, CodeIssue.MEDIUM, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\bsrand\s*\(\s*(time\s*\(|0|1|\d+)\s*") Then
            frmMain.ListCodeIssue("Predictable PRNG Seed", "Seeding with the current time or a constant makes the entire output sequence reproducible by anyone who can estimate the seed to within a few seconds.", FileName, CodeIssue.HIGH, CodeLine)
        End If

        '== Secret material left in memory ==
        If Regex.IsMatch(CodeLine, "\bmemset\s*\(") And Regex.IsMatch(CodeLine, "(?i)\b\w*(key|password|passwd|secret|token|cred)\w*\b") Then
            frmMain.ListCodeIssue("Secret Cleared With memset()", "A compiler is permitted to remove a memset() whose result is never read - the dead-store elimination problem - leaving the secret resident in memory where it may reach a core dump, swap file or hibernation image. Use memset_s(), explicit_bzero(), SecureZeroMemory() or OPENSSL_cleanse().", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

    End Sub

    Private Sub CheckCppFormatString(CodeLine As String, FileName As String)
        ' Extend format string detection beyond the existing printf check
        '================================================================

        '== Any formatted output function taking a bare variable as the format argument ==
        If Regex.IsMatch(CodeLine, "\b(fprintf|sprintf|snprintf|vsprintf|vsnprintf|vprintf|vfprintf|syslog|wprintf|swprintf|asprintf|err|warn)\s*\(") Then
            If Regex.IsMatch(CodeLine, "\b(fprintf|syslog)\s*\(\s*\w+\s*,\s*\w+\s*\)") Or _
               Regex.IsMatch(CodeLine, "\b(sprintf|vsprintf)\s*\(\s*\w+\s*,\s*\w+\s*\)") Then
                If Not CodeLine.Contains("""") Then
                    frmMain.ListCodeIssue("Potential Format String Vulnerability", "A variable is passed where a format string is expected. If an attacker controls that variable, '%x' sequences read the stack and '%n' writes an attacker-chosen value to an attacker-chosen address, which is a reliable path to code execution. Always pass a literal format string and supply the variable as an argument.", FileName, CodeIssue.HIGH, CodeLine)
                End If
            End If
        End If

        '== Unbounded scanf conversions ==
        If Regex.IsMatch(CodeLine, "\b(scanf|fscanf|sscanf)\s*\([^\)]*%s") And Not Regex.IsMatch(CodeLine, "%\d+s") Then
            frmMain.ListCodeIssue("Unbounded %s Conversion In scanf()", "A %s conversion without a field width copies input until whitespace is encountered, overflowing the destination buffer exactly as gets() would. Specify a maximum field width one byte shorter than the destination.", FileName, CodeIssue.HIGH, CodeLine)
        End If

        '== snprintf return value misuse ==
        If Regex.IsMatch(CodeLine, "\w+\s*\+?=\s*\bsnprintf\s*\(") Then
            frmMain.ListCodeIssue("snprintf() Return Value Used As A Length", "snprintf returns the number of bytes that would have been written, not the number actually written. Using the return value to advance a cursor causes the pointer to move beyond the end of the buffer when truncation occurs, producing an out-of-bounds write on the next operation.", FileName, CodeIssue.HIGH, CodeLine)
        End If

    End Sub

    Private Sub CheckCppIntegerIssues(CodeLine As String, FileName As String)
        ' Identify integer overflow and truncation feeding allocation or copy operations
        '==============================================================================

        '== Arithmetic inside an allocation size argument ==
        If Regex.IsMatch(CodeLine, "\b(malloc|calloc|realloc|alloca|new)\b[^;]*[\+\*][^;]*\)") And Not Regex.IsMatch(CodeLine, "sizeof\s*\(\s*\w+\s*\)\s*\)") Then
            frmMain.ListCodeIssue("Arithmetic In Allocation Size", "The allocation size is computed with addition or multiplication. Where either operand is attacker-influenced the computation can wrap, producing a small allocation that is subsequently written as though it were large - a classic heap overflow. Check for overflow before allocating, or use calloc(), which performs the multiplication check itself.", FileName, CodeIssue.HIGH, CodeLine)
        End If

        '== alloca with a non-constant size ==
        If Regex.IsMatch(CodeLine, "\balloca\s*\(") And Not Regex.IsMatch(CodeLine, "\balloca\s*\(\s*\d+\s*\)") Then
            frmMain.ListCodeIssue("Variable-Sized Stack Allocation", "alloca() with an attacker-influenced size moves the stack pointer by an arbitrary amount, allowing the stack guard page to be skipped entirely (stack clash). A subsequent write then lands in an unrelated mapping. Use a fixed-size buffer or heap allocation.", FileName, CodeIssue.HIGH, CodeLine)
        End If

        '== Signed length variables passed to memory functions ==
        If Regex.IsMatch(CodeLine, "\b(memcpy|memmove|memset|strncpy|strncat|read|recv|write)\s*\(") And Regex.IsMatch(CodeLine, "\b(int|short|long|char)\s+\w+\s*[,\)]") Then
            frmMain.ListCodeIssue("Signed Length Parameter In A Memory Operation", "A signed value used as a length is converted to size_t at the call. A negative length therefore becomes an extremely large positive value, and the copy runs far past the end of the buffer. Use size_t throughout and validate the length against the destination size before copying.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

        '== strlen based allocation without room for the terminator ==
        If Regex.IsMatch(CodeLine, "\b(malloc|alloca)\s*\(\s*strlen\s*\([^\)]*\)\s*\)") Then
            frmMain.ListCodeIssue("Allocation Omits Space For The NUL Terminator", "malloc(strlen(s)) allocates one byte too few for a copy of the string. The subsequent strcpy writes the terminating NUL one byte past the end of the allocation - an off-by-one heap overflow which is exploitable on many allocators.", FileName, CodeIssue.HIGH, CodeLine)
        End If

    End Sub

    Private Sub CheckCppMemoryLifecycle(CodeLine As String, FileName As String)
        ' Identify use-after-free, double free and mismatched allocation patterns
        '=======================================================================
        Dim strFreed As String = ""
        Dim arrFragments As String()


        '== Mismatched array delete ==
        If Regex.IsMatch(CodeLine, "\bdelete\s+\w+\s*;") And Regex.IsMatch(CodeLine, "new\s+\w+\s*\[") Then
            frmMain.ListCodeIssue("Mismatched new[] And delete", "Memory allocated with new[] must be released with delete[]. Using scalar delete invokes only the first destructor and passes an incorrect pointer to the deallocator, which is undefined behaviour and typically corrupts the heap.", FileName, CodeIssue.HIGH, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\bfree\s*\(") And Regex.IsMatch(CodeLine, "\bnew\b") Then
            frmMain.ListCodeIssue("Mismatched Allocator And Deallocator", "Memory obtained from new must be released with delete, and memory from malloc with free. Mixing the two corrupts allocator metadata.", FileName, CodeIssue.HIGH, CodeLine)
        End If

        '== Pointer not nulled after release ==
        If Regex.IsMatch(CodeLine, "\b(free|delete)\s*(\(|\s)\s*\*?\s*(\w+)") Then
            arrFragments = Regex.Split(CodeLine, "\b(free|delete)\s*(\(|\s)")
            If arrFragments.Count > 2 Then
                strFreed = GetFirstItem(arrFragments.Last, ")").Trim().TrimStart("*").TrimStart("&")
                strFreed = GetFirstItem(strFreed, ";").Trim()
                If Regex.IsMatch(strFreed, "^[A-Za-z_]\w*$") And Not Regex.IsMatch(CodeLine, strFreed & "\s*=\s*(NULL|nullptr|0)") Then
                    frmMain.ListCodeIssue("Pointer Not Cleared After Release", "The pointer is not set to NULL after the memory is released. A later dereference is then a use-after-free and a second release is a double free; both are routinely exploited to gain control of allocator metadata and, from there, of execution flow.", FileName, CodeIssue.MEDIUM, CodeLine)
                End If
            End If
        End If

        '== Return of a pointer to stack memory ==
        If Regex.IsMatch(CodeLine, "\breturn\s+&\s*\w+\s*;") Then
            frmMain.ListCodeIssue("Address Of A Local Variable Returned", "The address of an automatic variable is returned to the caller. The stack frame is destroyed on return, so any dereference reads or writes memory that has been reused by subsequent calls.", FileName, CodeIssue.HIGH, CodeLine)
        End If

        '== Use of std::auto_ptr and other removed constructs ==
        If Regex.IsMatch(CodeLine, "\bauto_ptr\b") Then
            frmMain.ListCodeIssue("Use of std::auto_ptr", "auto_ptr transfers ownership on copy, which produces silent null dereferences when the object is passed by value or stored in a container. It was deprecated in C++11 and removed in C++17. Use unique_ptr.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

    End Sub

    Private Sub CheckCppPrivilegeManagement(CodeLine As String, FileName As String)
        ' Identify unsafe privilege dropping and filesystem permission handling
        '=====================================================================

        If Regex.IsMatch(CodeLine, "\bsetuid\s*\(") And Not Regex.IsMatch(CodeLine, "\bsetgid\s*\(") Then
            frmMain.ListCodeIssue("setuid() Without setgid()", "Privilege must be dropped in the correct order: supplementary groups first with setgroups(), then setgid(), then setuid(). Calling setuid() first permanently discards the ability to change group, leaving the process with the original group privileges. Also check the return value - setuid can fail under RLIMIT_NPROC.", FileName, CodeIssue.HIGH, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\b(seteuid|setegid|setreuid|setregid)\s*\(") Then
            frmMain.ListCodeIssue("Temporary Privilege Change", "seteuid/setreuid drop privilege only temporarily; the saved set-user-ID retains the original value and can be restored by the process or by injected code. Where privilege is not required again, drop it permanently with setresuid().", FileName, CodeIssue.MEDIUM, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\bchroot\s*\(") And Not Regex.IsMatch(CodeLine, "\bchdir\s*\(\s*""\s*/\s*""") Then
            frmMain.ListCodeIssue("chroot() Without A Following chdir()", "If the working directory remains outside the new root, relative paths escape the jail immediately. Call chdir to the new root directly after chroot, and note that chroot alone is not a security boundary for a process which retains root privilege.", FileName, CodeIssue.HIGH, CodeLine)
        End If

        '== World-writable file and permissive umask ==
        If Regex.IsMatch(CodeLine, "\b(open|creat|mkdir|chmod|fchmod)\s*\([^\)]*0?7[0-7][0-7]\b") Or Regex.IsMatch(CodeLine, "\b(chmod|fchmod)\s*\([^\)]*(S_IWOTH|S_IRWXO)") Then
            frmMain.ListCodeIssue("Overly Permissive File Permissions", "The file or directory is created world-writable or world-readable. Any local user can then modify configuration, replace executables or read sensitive content. Grant the minimum required mode and rely on umask for defence in depth.", FileName, CodeIssue.HIGH, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "\bumask\s*\(\s*0+\s*\)") Then
            frmMain.ListCodeIssue("umask Set To Zero", "A zero umask causes every subsequently created file to take the mode requested by the caller with no masking, frequently resulting in world-writable files.", FileName, CodeIssue.HIGH, CodeLine)
        End If

        '== Environment inherited by child processes ==
        If Regex.IsMatch(CodeLine, "\b(execl|execlp|execv|execvp|execle)\s*\(") And Not Regex.IsMatch(CodeLine, "\b(execle|execve)\b") Then
            frmMain.ListCodeIssue("Child Process Inherits The Environment", "execlp and execvp resolve the program name using PATH and pass the inherited environment to the child. In a setuid or privileged context an attacker who controls PATH, LD_PRELOAD or IFS can substitute their own binary or library. Use execve with an absolute path and a sanitised environment.", FileName, CodeIssue.HIGH, CodeLine)
        End If

    End Sub

    Private Sub CheckCppPathHandling(CodeLine As String, FileName As String)
        ' Identify path traversal and unsafe link handling
        '=================================================

        If Regex.IsMatch(CodeLine, "\b(fopen|open|opendir|unlink|remove|rename|chmod|chown|stat|access)\s*\(") And IsUserInputCpp(CodeLine) Then
            frmMain.ListCodeIssue("Potential Path Traversal", "A filesystem path appears to be derived from user input or the environment. Traversal sequences allow access to arbitrary files with the privileges of the process. Canonicalise with realpath() and confirm the result remains within the intended directory before use.", FileName, CodeIssue.HIGH, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "\baccess\s*\(") Then
            frmMain.ListCodeIssue("Use of access() For An Authorisation Decision", "access() tests the real user ID rather than the effective one and leaves a window between the check and the subsequent open() in which the path can be replaced by a symbolic link. In a setuid program this is the canonical TOCTOU pattern. Open the file first and then examine the descriptor with fstat().", FileName, CodeIssue.HIGH, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "\b(readlink|symlink|link)\s*\(") Then
            frmMain.ListCodeIssue("Symbolic Link Operation", "Confirm that the result is length-checked and NUL-terminated - readlink() does not terminate the buffer - and that link creation cannot be redirected by an attacker who controls the containing directory. Use the *at() family with O_NOFOLLOW where possible.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "\b(tmpnam|tempnam|mktemp)\s*\(") Then
            frmMain.ListCodeIssue("Insecure Temporary Filename Generation", "tmpnam, tempnam and mktemp return a name without creating the file, leaving a window in which an attacker can create a symbolic link at that path. Use mkstemp() or mkdtemp(), which create the file atomically with restrictive permissions.", FileName, CodeIssue.HIGH, CodeLine)
        End If

    End Sub

    Private Sub CheckCppHardcodedSecrets(CodeLine As String, FileName As String)
        ' Identify credentials embedded in source
        '========================================

        If Regex.IsMatch(CodeLine, "-----BEGIN\s+(RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE KEY") Then
            frmMain.ListCodeIssue("Private Key Embedded In Source", "A PEM-encoded private key is compiled into the binary and is recoverable with a hex editor. The associated identity must be treated as compromised.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "(?i)\b(char|const\s+char|std::string|wchar_t|TCHAR)\b[^=]*\b\w*(password|passwd|pwd|secret|apikey|api_key|token|privkey)\w*\s*(\[\s*\d*\s*\])?\s*=\s*""[^""]{3,}""") Then
            frmMain.ListCodeIssue("Hard-Coded Credential", "A string literal assigned to a credential-named variable is stored in the binary's read-only data section and is extracted in seconds with the 'strings' utility. Obfuscation does not help; the value must be supplied at runtime from a protected store.", FileName, CodeIssue.HIGH, CodeLine)
        End If
        If Regex.IsMatch(CodeLine, "AKIA[0-9A-Z]{16}") Then
            frmMain.ListCodeIssue("Hard-Coded AWS Access Key", "A string matching the AWS access key ID format is embedded in source.", FileName, CodeIssue.CRITICAL, CodeLine)
        End If

    End Sub

    Private Sub CheckCppConcurrency(CodeLine As String, FileName As String)
        ' Identify signal handling and thread-safety defects
        '===================================================

        If Regex.IsMatch(CodeLine, "\bsignal\s*\(") Then
            frmMain.ListCodeIssue("Use of signal() Rather Than sigaction()", "signal() has implementation-defined semantics for handler reinstatement and interrupted system calls. More importantly, only async-signal-safe functions may be called from a handler: invoking malloc, free, printf or syslog from a handler creates a re-entrancy window that has repeatedly produced exploitable double-free conditions. Use sigaction() and confine the handler to setting a volatile sig_atomic_t flag.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "\b(strtok|asctime|ctime|gmtime|localtime|getpwnam|getpwuid|getgrnam|gethostbyname|gethostbyaddr|readdir|rand|crypt|inet_ntoa|tmpnam)\s*\(") And Not Regex.IsMatch(CodeLine, "_r\s*\(") Then
            frmMain.ListCodeIssue("Use of a Non Re-Entrant Library Function", "This function returns a pointer to a static internal buffer, so concurrent calls from multiple threads or from a signal handler corrupt each other's results. Use the _r variant.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

        If Regex.IsMatch(CodeLine, "\b(system|popen)\s*\(") And Regex.IsMatch(CodeLine, "\b(pthread_create|fork)\b") Then
            frmMain.ListCodeIssue("Process Creation In A Threaded Context", "Calling fork() from a multi-threaded process duplicates only the calling thread but preserves the state of every mutex, so a lock held by another thread at the moment of the fork is never released in the child. Only async-signal-safe functions may be called between fork and exec.", FileName, CodeIssue.MEDIUM, CodeLine)
        End If

    End Sub

    Private Sub CheckCppErrorHandling(CodeLine As String, FileName As String)
        ' Identify unchecked return values on security-relevant calls
        '============================================================

        '== Allocation results used without a check ==
        If Regex.IsMatch(CodeLine, "\b(malloc|calloc|realloc|strdup)\s*\(") And Regex.IsMatch(CodeLine, "^\s*\w+\s*(\*\s*)?\w+\s*=") And Not Regex.IsMatch(CodeLine, "(if|assert|\?)") Then
            frmMain.ListCodeIssue("Allocation Result Not Checked", "The return value of the allocator is not tested against NULL on this line. Under memory pressure - which an attacker may be able to induce - the subsequent dereference is a NULL pointer write. Test every allocation before use.", FileName, CodeIssue.LOW, CodeLine)
        End If

        '== Privilege and crypto calls whose failure is silently ignored ==
        If Regex.IsMatch(CodeLine, "^\s*\b(setuid|setgid|seteuid|setegid|setgroups|chroot|chdir|RAND_bytes|EVP_\w+|SSL_\w+)\s*\(") And Not CodeLine.Contains("=") And Not CodeLine.Contains("if") Then
            frmMain.ListCodeIssue("Return Value Of A Security-Critical Call Ignored", "The result of this call is discarded. If a privilege drop, directory change or cryptographic operation fails and the failure is not detected, execution continues in a state the developer believed impossible - typically with full privilege retained or with uninitialised key material in use.", FileName, CodeIssue.HIGH, CodeLine)
        End If

    End Sub
End Module
