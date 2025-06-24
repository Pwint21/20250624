Imports System.Data.SqlClient
Imports System.Text.RegularExpressions
Imports System.Web.Security
Imports System.IO
Imports System.Security.Cryptography
Imports System.Text
Imports System
Imports System.Web
Imports System.Data
Imports System.Security
Imports System.Collections.Generic
Imports System.Linq
Imports System.Net

Public Class SecurityHelper
    ' Security configuration constants
    Private Shared ReadOnly BLOCKED_USER_AGENTS As String() = {
        "sqlmap", "nikto", "nmap", "masscan", "zap", "burp", "acunetix", 
        "nessus", "openvas", "w3af", "skipfish", "wpscan", "dirb", "gobuster"
    }
    
    Private Shared ReadOnly SUSPICIOUS_PATTERNS As String() = {
        "union.*select", "insert.*into", "update.*set", "delete.*from",
        "drop.*table", "create.*table", "alter.*table", "exec.*xp_",
        "sp_oacreate", "sp_oamethod", "openrowset", "opendatasource",
        "xp_cmdshell", "bulk.*insert", "truncate.*table", "<script",
        "javascript:", "vbscript:", "onload=", "onerror=", "eval\(",
        "expression\(", "document\.", "window\.", "alert\(", "confirm\(",
        "../", "..\\", "%2e%2e", "%252e%252e", "etc/passwd", "boot.ini"
    }

    ' Initialize security settings
    Public Shared Sub InitializeSecuritySettings()
        Try
            ' Set machine key for encryption if not already set
            If HttpContext.Current.Cache("SecurityInitialized") Is Nothing Then
                HttpContext.Current.Cache.Insert("SecurityInitialized", True, Nothing, DateTime.Now.AddHours(24), TimeSpan.Zero)
                LogSecurityEvent("SECURITY_INITIALIZED", "Security settings initialized")
            End If
        Catch ex As Exception
            LogSecurityEvent("SECURITY_INIT_ERROR", ex.Message)
        End Try
    End Sub

    ' Get client IP address (handles proxies and load balancers)
    Public Shared Function GetClientIPAddress(request As HttpRequest) As String
        Try
            Dim ipAddress As String = String.Empty
            
            ' Check for IP from shared internet
            If Not String.IsNullOrEmpty(request.ServerVariables("HTTP_CLIENT_IP")) Then
                ipAddress = request.ServerVariables("HTTP_CLIENT_IP")
            ElseIf Not String.IsNullOrEmpty(request.ServerVariables("HTTP_X_FORWARDED_FOR")) Then
                ' Check for IP passed from proxy
                ipAddress = request.ServerVariables("HTTP_X_FORWARDED_FOR").Split(","c)(0).Trim()
            ElseIf Not String.IsNullOrEmpty(request.ServerVariables("HTTP_X_FORWARDED")) Then
                ipAddress = request.ServerVariables("HTTP_X_FORWARDED")
            ElseIf Not String.IsNullOrEmpty(request.ServerVariables("HTTP_FORWARDED_FOR")) Then
                ipAddress = request.ServerVariables("HTTP_FORWARDED_FOR")
            ElseIf Not String.IsNullOrEmpty(request.ServerVariables("HTTP_FORWARDED")) Then
                ipAddress = request.ServerVariables("HTTP_FORWARDED")
            Else
                ipAddress = request.ServerVariables("REMOTE_ADDR")
            End If
            
            ' Validate IP address format
            Dim ip As IPAddress
            If IPAddress.TryParse(ipAddress, ip) Then
                Return ipAddress
            Else
                Return request.UserHostAddress
            End If
            
        Catch ex As Exception
            LogSecurityEvent("IP_ADDRESS_ERROR", ex.Message)
            Return request.UserHostAddress
        End Try
    End Function

    ' Check if request is suspicious
    Public Shared Function IsSuspiciousRequest(request As HttpRequest) As Boolean
        Try
            ' Check User-Agent
            Dim userAgent As String = If(request.UserAgent, String.Empty).ToLower()
            For Each blockedAgent As String In BLOCKED_USER_AGENTS
                If userAgent.Contains(blockedAgent) Then
                    Return True
                End If
            Next
            
            ' Check URL for suspicious patterns
            Dim url As String = request.Url.ToString().ToLower()
            For Each pattern As String In SUSPICIOUS_PATTERNS
                If Regex.IsMatch(url, pattern, RegexOptions.IgnoreCase) Then
                    Return True
                End If
            Next
            
            ' Check query string
            If Not String.IsNullOrEmpty(request.QueryString.ToString()) Then
                Dim queryString As String = request.QueryString.ToString().ToLower()
                For Each pattern As String In SUSPICIOUS_PATTERNS
                    If Regex.IsMatch(queryString, pattern, RegexOptions.IgnoreCase) Then
                        Return True
                    End If
                Next
            End If
            
            ' Check form data
            If request.Form IsNot Nothing Then
                For Each key As String In request.Form.AllKeys
                    If key IsNot Nothing Then
                        Dim value As String = If(request.Form(key), String.Empty).ToLower()
                        For Each pattern As String In SUSPICIOUS_PATTERNS
                            If Regex.IsMatch(value, pattern, RegexOptions.IgnoreCase) Then
                                Return True
                            End If
                        Next
                    End If
                Next
            End If
            
            ' Check headers for suspicious content
            For Each headerName As String In request.Headers.AllKeys
                If headerName IsNot Nothing Then
                    Dim headerValue As String = If(request.Headers(headerName), String.Empty).ToLower()
                    If ContainsDangerousPatterns(headerValue) Then
                        Return True
                    End If
                End If
            Next
            
            Return False
            
        Catch ex As Exception
            LogSecurityEvent("SUSPICIOUS_REQUEST_CHECK_ERROR", ex.Message)
            Return False
        End Try
    End Function

    ' Enhanced rate limiting with sliding window
    Public Shared Function IsRateLimited(identifier As String, maxRequests As Integer, timeWindowMinutes As Integer) As Boolean
        Try
            Dim cacheKey As String = $"RateLimit_{identifier}"
            Dim requestTimes As List(Of DateTime) = TryCast(HttpContext.Current.Cache(cacheKey), List(Of DateTime))
            
            If requestTimes Is Nothing Then
                requestTimes = New List(Of DateTime)()
            End If
            
            ' Remove old requests outside the time window
            Dim cutoffTime As DateTime = DateTime.Now.AddMinutes(-timeWindowMinutes)
            requestTimes.RemoveAll(Function(time) time < cutoffTime)
            
            ' Check if limit exceeded
            If requestTimes.Count >= maxRequests Then
                Return True
            End If
            
            ' Add current request
            requestTimes.Add(DateTime.Now)
            
            ' Update cache
            HttpContext.Current.Cache.Insert(cacheKey, requestTimes, Nothing, 
                DateTime.Now.AddMinutes(timeWindowMinutes), TimeSpan.Zero)
            
            Return False
            
        Catch ex As Exception
            LogSecurityEvent("RATE_LIMIT_ERROR", ex.Message)
            Return False
        End Try
    End Function

    ' Validate and sanitize file upload
    Public Shared Function ValidateFileUpload(fileUpload As HttpPostedFile, allowedExtensions As String(), maxSizeBytes As Long) As Boolean
        Try
            If fileUpload Is Nothing OrElse fileUpload.ContentLength = 0 Then
                Return False
            End If
            
            ' Check file size
            If fileUpload.ContentLength > maxSizeBytes Then
                LogSecurityEvent("FILE_SIZE_EXCEEDED", $"Size: {fileUpload.ContentLength}, Max: {maxSizeBytes}")
                Return False
            End If
            
            ' Check file extension
            Dim extension As String = Path.GetExtension(fileUpload.FileName).ToLower()
            If Not allowedExtensions.Contains(extension) Then
                LogSecurityEvent("INVALID_FILE_EXTENSION", $"Extension: {extension}")
                Return False
            End If
            
            ' Check MIME type
            Dim allowedMimeTypes As String() = {
                "image/jpeg", "image/png", "image/gif", "image/bmp",
                "application/pdf", "text/plain", "application/msword",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            }
            
            If Not allowedMimeTypes.Contains(fileUpload.ContentType.ToLower()) Then
                LogSecurityEvent("INVALID_MIME_TYPE", $"MIME: {fileUpload.ContentType}")
                Return False
            End If
            
            ' Check for malicious content in filename
            If ContainsDangerousPatterns(fileUpload.FileName) Then
                LogSecurityEvent("MALICIOUS_FILENAME", $"Filename: {fileUpload.FileName}")
                Return False
            End If
            
            Return True
            
        Catch ex As Exception
            LogSecurityEvent("FILE_VALIDATION_ERROR", ex.Message)
            Return False
        End Try
    End Function

    ' Generate secure random password
    Public Shared Function GenerateSecurePassword(length As Integer) As String
        Try
            Const chars As String = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*"
            Using rng As New RNGCryptoServiceProvider()
                Dim bytes(length - 1) As Byte
                rng.GetBytes(bytes)
                
                Dim result As New StringBuilder(length)
                For Each b As Byte In bytes
                    result.Append(chars(b Mod chars.Length))
                Next
                
                Return result.ToString()
            End Using
        Catch ex As Exception
            LogSecurityEvent("PASSWORD_GENERATION_ERROR", ex.Message)
            Return String.Empty
        End Try
    End Function

    ' Validate password strength
    Public Shared Function ValidatePasswordStrength(password As String) As Boolean
        Try
            If String.IsNullOrEmpty(password) OrElse password.Length < 8 Then
                Return False
            End If
            
            ' Check for at least one uppercase letter
            If Not Regex.IsMatch(password, "[A-Z]") Then
                Return False
            End If
            
            ' Check for at least one lowercase letter
            If Not Regex.IsMatch(password, "[a-z]") Then
                Return False
            End If
            
            ' Check for at least one digit
            If Not Regex.IsMatch(password, "[0-9]") Then
                Return False
            End If
            
            ' Check for at least one special character
            If Not Regex.IsMatch(password, "[!@#$%^&*()_+\-=\[\]{};':""\\|,.<>\/?]") Then
                Return False
            End If
            
            Return True
            
        Catch ex As Exception
            LogSecurityEvent("PASSWORD_VALIDATION_ERROR", ex.Message)
            Return False
        End Try
    End Function

    ' Encrypt sensitive data
    Public Shared Function EncryptData(plainText As String, key As String) As String
        Try
            If String.IsNullOrEmpty(plainText) Then
                Return String.Empty
            End If
            
            Using aes As Aes = Aes.Create()
                aes.Key = Encoding.UTF8.GetBytes(key.PadRight(32).Substring(0, 32))
                aes.IV = New Byte(15) {} ' Zero IV for simplicity, use random IV in production
                
                Using encryptor As ICryptoTransform = aes.CreateEncryptor(aes.Key, aes.IV)
                    Using msEncrypt As New MemoryStream()
                        Using csEncrypt As New CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write)
                            Using swEncrypt As New StreamWriter(csEncrypt)
                                swEncrypt.Write(plainText)
                            End Using
                        End Using
                        Return Convert.ToBase64String(msEncrypt.ToArray())
                    End Using
                End Using
            End Using
            
        Catch ex As Exception
            LogSecurityEvent("ENCRYPTION_ERROR", ex.Message)
            Return String.Empty
        End Try
    End Function

    ' Decrypt sensitive data
    Public Shared Function DecryptData(cipherText As String, key As String) As String
        Try
            If String.IsNullOrEmpty(cipherText) Then
                Return String.Empty
            End If
            
            Dim cipherBytes As Byte() = Convert.FromBase64String(cipherText)
            
            Using aes As Aes = Aes.Create()
                aes.Key = Encoding.UTF8.GetBytes(key.PadRight(32).Substring(0, 32))
                aes.IV = New Byte(15) {} ' Zero IV for simplicity, use random IV in production
                
                Using decryptor As ICryptoTransform = aes.CreateDecryptor(aes.Key, aes.IV)
                    Using msDecrypt As New MemoryStream(cipherBytes)
                        Using csDecrypt As New CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read)
                            Using srDecrypt As New StreamReader(csDecrypt)
                                Return srDecrypt.ReadToEnd()
                            End Using
                        End Using
                    End Using
                End Using
            End Using
            
        Catch ex As Exception
            LogSecurityEvent("DECRYPTION_ERROR", ex.Message)
            Return String.Empty
        End Try
    End Function

    ' Validate users list format
    Public Shared Function ValidateUsersList(usersList As String) As Boolean
        Try
            If String.IsNullOrEmpty(usersList) Then
                Return False
            End If

            ' Remove quotes and validate format
            usersList = usersList.Replace("'", "").Replace(" ", "")

            If Not Regex.IsMatch(usersList, "^[0-9,]+$") Then
                Return False
            End If

            ' Validate each user ID
            Dim users As String() = usersList.Split(","c)
            For Each user As String In users
                If Not String.IsNullOrEmpty(user) Then
                    Dim userId As Integer
                    If Not Integer.TryParse(user, userId) OrElse userId <= 0 Then
                        Return False
                    End If
                End If
            Next

            Return True
        Catch ex As Exception
            LogSecurityEvent("USERS_LIST_VALIDATION_ERROR", ex.Message)
            Return False
        End Try
    End Function
    ' Execute secure query
    Public Shared Function ExecuteSecureQuery(query As String, parameters As Dictionary(Of String, Object)) As DataTable
        Try
            Return DatabaseHelper.ExecuteQuery(query, parameters)
        Catch ex As Exception
            LogSecurityEvent("SECURE_QUERY_ERROR", ex.Message)
            Throw New SecurityException("Database operation failed")
        End Try
    End Function
    ' Execute secure non-query
    Public Shared Function ExecuteSecureNonQuery(query As String, parameters As Dictionary(Of String, Object)) As Integer
        Try
            Return DatabaseHelper.ExecuteNonQuery(query, parameters)
        Catch ex As Exception
            LogSecurityEvent("SECURE_NONQUERY_ERROR", ex.Message)
            Throw New SecurityException("Database operation failed")
        End Try
    End Function
    Public Shared Function CheckRateLimit(key As String, maxAttempts As Integer, timeWindow As TimeSpan) As Boolean
        Try
            Dim cacheKey As String = "RateLimit_" & key
            Dim attempts As Integer = 0

            If HttpContext.Current.Cache(cacheKey) IsNot Nothing Then
                attempts = CInt(HttpContext.Current.Cache(cacheKey))
            End If

            If attempts >= maxAttempts Then
                Return False
            End If

            attempts += 1
            HttpContext.Current.Cache.Insert(cacheKey, attempts, Nothing, DateTime.Now.Add(timeWindow), TimeSpan.Zero)

            Return True
        Catch ex As Exception
            LogSecurityEvent("RATE_LIMIT_ERROR", ex.Message)
            Return True ' Allow on error to prevent blocking legitimate users
        End Try
    End Function
    ' Sanitize log messages to prevent log injection
    Public Shared Function SanitizeLogMessage(message As String) As String
        If String.IsNullOrEmpty(message) Then
            Return String.Empty
        End If

        ' Remove or replace dangerous characters
        Dim sanitized As String = message.Replace(vbCrLf, " ").Replace(vbCr, " ").Replace(vbLf, " ")
        sanitized = Regex.Replace(sanitized, "[\x00-\x1F\x7F]", " ") ' Remove control characters

        ' Limit length
        If sanitized.Length > 500 Then
            sanitized = sanitized.Substring(0, 500) & "..."
        End If

        Return sanitized
    End Function
    Public Shared Function IsValidUserId(userId As String) As Boolean
        If String.IsNullOrEmpty(userId) Then
            Return False
        End If

        Dim userIdInt As Integer
        Return Integer.TryParse(userId, userIdInt) AndAlso userIdInt > 0
    End Function

    ' Validate plate number format (alphanumeric only)
    Public Shared Function IsValidPlateNumber(plateNumber As String) As Boolean
        If String.IsNullOrEmpty(plateNumber) OrElse plateNumber.Length > 20 Then
            Return False
        End If

        ' Allow alphanumeric characters and hyphens
        Return Regex.IsMatch(plateNumber, "^[a-zA-Z0-9\-]+$")
    End Function

    ' Validate email format
    Public Shared Function IsValidEmail(email As String) As Boolean
        If String.IsNullOrEmpty(email) Then
            Return False
        End If

        Try
            Dim addr As New System.Net.Mail.MailAddress(email)
            Return addr.Address = email AndAlso email.Length <= 254
        Catch
            Return False
        End Try
    End Function

    ' Validate date format
    Public Shared Function IsValidDate(dateString As String, ByRef parsedDate As DateTime) As Boolean
        If String.IsNullOrEmpty(dateString) Then
            parsedDate = DateTime.MinValue
            Return False
        End If

        Return DateTime.TryParse(dateString, parsedDate) AndAlso
               parsedDate >= New DateTime(1900, 1, 1) AndAlso
               parsedDate <= New DateTime(2100, 12, 31)
    End Function

    ' Sanitize string input for database
    Public Shared Function SanitizeString(input As String, maxLength As Integer) As String
        If String.IsNullOrEmpty(input) Then
            Return String.Empty
        End If

        ' Remove potentially dangerous characters
        Dim sanitized As String = input.Replace("'", "''").Replace("<", "<").Replace(">", ">")

        ' Truncate to max length
        If sanitized.Length > maxLength Then
            sanitized = sanitized.Substring(0, maxLength)
        End If

        Return sanitized
    End Function

    ' Generate secure session token
    Public Shared Function GenerateSecureToken() As String
        Using rng As New RNGCryptoServiceProvider()
            Dim tokenBytes(31) As Byte
            rng.GetBytes(tokenBytes)
            Return Convert.ToBase64String(tokenBytes)
        End Using
    End Function
    ' SECURITY FIX: Password hashing
    Public Shared Function HashPassword(password As String) As String
        Using sha256 As SHA256 = SHA256.Create()
            Dim hashedBytes As Byte() = sha256.ComputeHash(Encoding.UTF8.GetBytes(password))
            Return BitConverter.ToString(hashedBytes).Replace("-", "").ToLower()
        End Using
    End Function

    ' Validate role
    Public Shared Function IsValidRole(role As String) As Boolean
        Dim validRoles As String() = {"User", "SuperUser", "Operator", "Admin"}
        Dim r As String
        For Each r In validRoles
            If r = role Then Return True
        Next
        Return False
    End Function

    ' Check if user has permission for operation
    Public Shared Function HasPermission(userRole As String, requiredRole As String) As Boolean
        Dim roleHierarchy As New Dictionary(Of String, Integer) From {
            {"User", 1},
            {"Operator", 2},
            {"SuperUser", 3},
            {"Admin", 4}
        }

        If Not roleHierarchy.ContainsKey(userRole) OrElse Not roleHierarchy.ContainsKey(requiredRole) Then
            Return False
        End If

        Return roleHierarchy(userRole) >= roleHierarchy(requiredRole)
    End Function

    ' Validate numeric input
    Public Shared Function IsValidNumeric(input As String, ByRef numericValue As Integer) As Boolean
        Return Integer.TryParse(input, numericValue) AndAlso numericValue >= 0
    End Function

    ' Encode output for safe HTML display
    Public Shared Function SafeHtmlEncode(input As String) As String
        If String.IsNullOrEmpty(input) Then
            Return String.Empty
        End If

        Return HttpUtility.HtmlEncode(input)
    End Function

    ' Encode output for safe JavaScript
    Public Shared Function SafeJavaScriptEncode(input As String) As String
        If String.IsNullOrEmpty(input) Then
            Return String.Empty
        End If

        Return HttpUtility.JavaScriptStringEncode(input)
    End Function

    ' Validate file extension
    Public Shared Function IsValidFileExtension(fileName As String, allowedExtensions As String()) As Boolean
        If String.IsNullOrEmpty(fileName) Then
            Return False
        End If
        Dim ext As String
        Dim extension As String = System.IO.Path.GetExtension(fileName).ToLower()
        For Each ext In allowedExtensions
            If ext.ToLower() = extension Then
                Return True
            End If
        Next
        Return False
    End Function


    ' SECURITY FIX: User session validation
    Public Shared Function ValidateUserSession(request As HttpRequest, session As HttpSessionState) As Boolean
        Try
            If request.Cookies("userinfo") Is Nothing Then
                Return False
            End If

            Dim userid As String = request.Cookies("userinfo")("userid")
            Dim role As String = request.Cookies("userinfo")("role")

            ' Validate userid is numeric
            Dim userIdInt As Integer
            If Not Integer.TryParse(userid, userIdInt) OrElse userIdInt <= 0 Then
                Return False
            End If

            ' Validate role is in allowed list
            If Not ValidateUserRole(role) Then
                Return False
            End If

            Return True
        Catch
            Return False
        End Try
    End Function

    ' SECURITY FIX: Input validation methods
    ' SECURITY FIX: Input validation methods
    Public Shared Function ValidateInput(input As String, pattern As String) As Boolean
        If String.IsNullOrEmpty(input) Then
            Return False
        End If

        If Not String.IsNullOrEmpty(pattern) Then
            Dim regex As New Regex(pattern)
            If Not regex.IsMatch(input) Then
                Return False
            End If
        End If

        Return True
    End Function
    ' SQL injection prevention
    Public Shared Function SanitizeForSql(input As String) As String
        If String.IsNullOrEmpty(input) Then
            Return String.Empty
        End If

        ' Remove dangerous characters
        input = input.Replace("'", "''")
        input = input.Replace(";", "")
        input = input.Replace("--", "")
        input = input.Replace("/*", "")
        input = input.Replace("*/", "")
        input = input.Replace("xp_", "")
        input = input.Replace("sp_", "")

        Return input
    End Function

    ' SECURITY FIX: SQL parameter helper
    Public Shared Function CreateSqlParameter(parameterName As String, value As Object, sqlDbType As SqlDbType) As SqlParameter
        Dim parameter As New SqlParameter(parameterName, sqlDbType)
        parameter.Value = If(value, DBNull.Value)
        Return parameter
    End Function

    ' SECURITY FIX: HTML encoding helper
    Public Shared Function HtmlEncode(input As String) As String
        If String.IsNullOrEmpty(input) Then
            Return String.Empty
        End If
        Return HttpUtility.HtmlEncode(input)
    End Function

    ' SECURITY FIX: User ID validation and retrieval
    Public Shared Function ValidateAndGetUserId(request As HttpRequest) As String
        Dim userid As String = request.Cookies("userinfo")("userid")
        If ValidateUserId(userid) Then
            Return userid
        End If
        Throw New SecurityException("Invalid user ID")
    End Function

    Public Shared Function ValidateUserId(userId As String) As Boolean
        Dim userIdInt As Integer
        Return Integer.TryParse(userId, userIdInt) AndAlso userIdInt > 0
    End Function

    ' SECURITY FIX: Role validation and retrieval
    Public Shared Function ValidateAndGetUserRole(request As HttpRequest) As String
        Dim role As String = request.Cookies("userinfo")("role")
        If ValidateUserRole(role) Then
            Return role
        End If
        Throw New SecurityException("Invalid user role")
    End Function

    Public Shared Function ValidateUserRole(role As String) As Boolean
        Dim allowedRoles As String() = {"Admin", "SuperUser", "Operator", "User"}

        For Each allowedRole As String In allowedRoles
            If String.Equals(allowedRole, role, StringComparison.OrdinalIgnoreCase) Then
                Return True
            End If
        Next

        Return False
    End Function

    ' SECURITY FIX: Users list validation and retrieval
    Public Shared Function ValidateAndGetUsersList(request As HttpRequest) As String
        Dim userslist As String = request.Cookies("userinfo")("userslist")
        If IsValidUsersList(userslist) Then
            Return userslist
        End If
        Return String.Empty ' Return empty string instead of throwing exception for optional field
    End Function

    Public Shared Function IsValidUsersList(usersList As String) As Boolean
        If String.IsNullOrEmpty(usersList) Then
            Return False
        End If

        ' Check if all values are numeric
        Dim users As String() = usersList.Split(","c)
        For Each user As String In users
            Dim userId As Integer
            If Not Integer.TryParse(user.Trim(), userId) OrElse userId <= 0 Then
                Return False
            End If
        Next
        Return True
    End Function

    ' SECURITY FIX: Date validation
    Public Shared Function ValidateDate(dateString As String) As Boolean
        Dim dateValue As DateTime
        Return DateTime.TryParse(dateString, dateValue)
    End Function

    ' SECURITY FIX: Plate number validation
    Public Shared Function ValidatePlateNumber(plateNumber As String) As Boolean
        If String.IsNullOrEmpty(plateNumber) Then
            Return False
        End If

        ' Allow alphanumeric characters and common plate number formats
        Dim pattern As String = "^[A-Za-z0-9\-\s]{1,15}$"
        Dim regex As New Regex(pattern)
        Return regex.IsMatch(plateNumber)
    End Function

    ' SECURITY FIX: Coordinate validation
    Public Shared Function ValidateCoordinate(latitude As String, longitude As String) As Boolean
        Dim lat, lon As Double

        If Not Double.TryParse(latitude, lat) OrElse Not Double.TryParse(longitude, lon) Then
            Return False
        End If

        ' Validate coordinate ranges
        If lat < -90 OrElse lat > 90 Then
            Return False
        End If

        If lon < -180 OrElse lon > 180 Then
            Return False
        End If

        Return True
    End Function

    ' SECURITY FIX: Dangerous pattern detection
    Public Shared Function ContainsDangerousPatterns(input As String) As Boolean
        If String.IsNullOrEmpty(input) Then
            Return False
        End If

        Dim dangerousPatterns() As String = {
            "<script", "</script>", "javascript:", "vbscript:", "onload=", "onerror=",
            "eval\(", "expression\(", "url\(", "import\(", "document\.", "window\.",
            "alert\(", "confirm\(", "prompt\(", "setTimeout\(", "setInterval\(",
            "union.*select", "insert.*into", "update.*set", "delete.*from",
            "drop.*table", "create.*table", "alter.*table", "exec.*xp_",
            "sp_oacreate", "sp_oamethod", "openrowset", "opendatasource",
            "xp_cmdshell", "bulk.*insert", "truncate.*table", "--", "/*", "*/"
        }

        Dim inputLower As String = input.ToLower()
        For Each pattern As String In dangerousPatterns
            If Regex.IsMatch(inputLower, pattern, RegexOptions.IgnoreCase) Then
                Return True
            End If
        Next

        Return False
    End Function

    ' SECURITY FIX: Error logging
    Public Shared Sub LogError(message As String, ex As Exception, server As HttpServerUtility)
        Try
            Dim logPath As String = server.MapPath("~/Logs/ErrorLog.txt")
            Dim logEntry As String = $"{DateTime.Now:yyyy/MM/dd HH:mm:ss.fff} - {message}: {ex.Message}{Environment.NewLine}"

            ' Ensure logs directory exists
            Dim logDir As String = Path.GetDirectoryName(logPath)
            If Not Directory.Exists(logDir) Then
                Directory.CreateDirectory(logDir)
            End If

            File.AppendAllText(logPath, logEntry)
        Catch
            ' Fail silently if logging fails
        End Try
    End Sub

    ' SECURITY FIX: Security event logging
    Public Shared Sub LogSecurityEvent(message As String, Optional message_Id As String = "")
        Try
            Dim logPath As String = HttpContext.Current.Server.MapPath("~/Logs/SecurityLog.txt")
            Dim logEntry As String = $"{DateTime.Now:yyyy/MM/dd HH:mm:ss.fff} - SECURITY: {message} - IP: {HttpContext.Current.Request.UserHostAddress}{Environment.NewLine}"

            ' Ensure logs directory exists
            Dim logDir As String = Path.GetDirectoryName(logPath)
            If Not Directory.Exists(logDir) Then
                Directory.CreateDirectory(logDir)
            End If

            File.AppendAllText(logPath, logEntry)
        Catch
            ' Fail silently if logging fails
        End Try
    End Sub

    ' SECURITY FIX: Safe string truncation
    Public Shared Function SafeTruncate(input As String, maxLength As Integer) As String
        If String.IsNullOrEmpty(input) Then
            Return String.Empty
        End If

        If input.Length <= maxLength Then
            Return input
        End If

        Return input.Substring(0, maxLength)
    End Function

    ' SECURITY FIX: Numeric validation
    Public Shared Function ValidateNumeric(input As String, minValue As Double, maxValue As Double) As Boolean
        Dim numericValue As Double
        If Not Double.TryParse(input, numericValue) Then
            Return False
        End If

        Return numericValue >= minValue AndAlso numericValue <= maxValue
    End Function

    ' SECURITY FIX: CSRF token generation and validation
    Public Shared Function GenerateCSRFToken() As String
        Using rng As New RNGCryptoServiceProvider()
            Dim tokenBytes(31) As Byte
            rng.GetBytes(tokenBytes)
            Return Convert.ToBase64String(tokenBytes)
        End Using
    End Function

    ' Validate CSRF token
    Public Shared Function ValidateCSRFToken(submittedToken As String) As Boolean
        Try
            If String.IsNullOrEmpty(submittedToken) Then
                Return False
            End If

            Dim sessionToken As String = TryCast(HttpContext.Current.Session("CSRFToken"), String)
            If String.IsNullOrEmpty(sessionToken) Then
                Return False
            End If

            Return sessionToken.Equals(submittedToken, StringComparison.Ordinal)
        Catch ex As Exception
            LogSecurityEvent("CSRF_TOKEN_VALIDATION_ERROR", ex.Message)
            Return False
        End Try
    End Function

    ' SECURITY FIX: Rate limiting helpers
    Public Shared Function IsRateLimited(identifier As String, maxRequests As Integer, timeWindowMinutes As Integer) As Boolean
        Try
            Dim cacheKey As String = $"RateLimit_{identifier}"
            Dim requestCount As Integer = 0

            If HttpContext.Current.Cache(cacheKey) IsNot Nothing Then
                requestCount = CInt(HttpContext.Current.Cache(cacheKey))
            End If

            If requestCount = 0 Then
                HttpContext.Current.Cache.Insert(cacheKey, 1, Nothing, DateTime.Now.AddMinutes(timeWindowMinutes), TimeSpan.Zero)
                Return False
            Else
                requestCount += 1
                HttpContext.Current.Cache.Insert(cacheKey, requestCount, Nothing, DateTime.Now.AddMinutes(timeWindowMinutes), TimeSpan.Zero)
                Return requestCount > maxRequests
            End If
        Catch
            Return False
        End Try
    End Function

    ' SECURITY FIX: File path validation
    Public Shared Function ValidateFilePath(filePath As String) As Boolean
        If String.IsNullOrEmpty(filePath) Then
            Return False
        End If

        ' Check for directory traversal attempts
        If filePath.Contains("..") OrElse filePath.Contains("~") Then
            Return False
        End If

        ' Check for invalid characters
        Dim invalidChars() As Char = Path.GetInvalidPathChars()
        For Each invalidChar As Char In invalidChars
            If filePath.Contains(invalidChar) Then
                Return False
            End If
        Next

        Return True
    End Function

    ' SECURITY FIX: URL validation
    Public Shared Function ValidateURL(url As String) As Boolean
        If String.IsNullOrEmpty(url) Then
            Return False
        End If

        Try
            Dim uri As New Uri(url)
            Return uri.Scheme = "http" OrElse uri.Scheme = "https"
        Catch
            Return False
        End Try
    End Function

    ' SECURITY FIX: Create safe SQL command
    Public Shared Function CreateSafeCommand(query As String, connection As SqlConnection) As SqlCommand
        ' Validate query for dangerous patterns
        If ContainsDangerousPatterns(query) Then
            LogSecurityEvent("Potentially dangerous SQL query detected: " & query)
            Throw New SecurityException("Invalid SQL query")
        End If

        Return New SqlCommand(query, connection)
    End Function

    ' SECURITY FIX: Sanitize for HTML output
    Public Shared Function SanitizeForHtml(input As String) As String
        If String.IsNullOrEmpty(input) Then
            Return String.Empty
        End If

        Return HttpUtility.HtmlEncode(input)
    End Function

    ' SECURITY FIX: Sanitize for JavaScript output
    Public Shared Function SanitizeForJavaScript(input As String) As String
        If String.IsNullOrEmpty(input) Then
            Return String.Empty
        End If

        ' Escape special characters for JavaScript
        Return input.Replace("\", "\\") _
                   .Replace("'", "\'") _
                   .Replace("""", "\""") _
                   .Replace("<", "<") _
                   .Replace(">", ">")
    End Function
    ' SECURITY FIX: Session validation
    Public Shared Function ValidateSession() As Boolean
        Try
            If HttpContext.Current.Session Is Nothing Then
                Return False
            End If

            ' Check if user is authenticated
            If HttpContext.Current.Session("userid") Is Nothing Then
                Return False
            End If

            ' Check session timeout
            If HttpContext.Current.Session("logintime") IsNot Nothing Then
                Dim loginTime As DateTime = CDate(HttpContext.Current.Session("logintime"))
                If DateTime.Now.Subtract(loginTime).TotalMinutes > 30 Then ' 30 minute timeout
                    HttpContext.Current.Session.Clear()
                    Return False
                End If
            End If

            Return True
        Catch ex As Exception
            Return False
        End Try
    End Function
End Class