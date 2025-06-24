<%@ Application Language="VB" %>
<%@ Import Namespace="System.Data.SqlClient" %>
<%@ Import Namespace="System.Web.Http" %>
<%@ Import Namespace="System.Web.Routing" %>
<%@ Import Namespace="System.Web.Security" %>
<%@ Import Namespace="System.Security" %>

<script runat="server">

    Sub Application_BeginRequest(ByVal sender As Object, ByVal e As EventArgs)
        Try
            ' Security Headers
            Response.Headers.Add("X-Content-Type-Options", "nosniff")
            Response.Headers.Add("X-Frame-Options", "DENY")
            Response.Headers.Add("X-XSS-Protection", "1; mode=block")
            Response.Headers.Add("Referrer-Policy", "strict-origin-when-cross-origin")
            Response.Headers.Add("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'")
            
            ' Remove server information
            Response.Headers.Remove("Server")
            
            ' Rate limiting check
            Dim clientIP As String = SecurityHelper.GetClientIPAddress(Request)
            If SecurityHelper.IsRateLimited(clientIP, 100, 1) Then ' 100 requests per minute
                SecurityHelper.LogSecurityEvent("RATE_LIMIT_EXCEEDED", "IP: " & clientIP)
                Response.StatusCode = 429
                Response.StatusDescription = "Too Many Requests"
                Response.End()
                Return
            End If
            
            ' Block suspicious requests
            If SecurityHelper.IsSuspiciousRequest(Request) Then
                SecurityHelper.LogSecurityEvent("SUSPICIOUS_REQUEST_BLOCKED", "IP: " & clientIP & ", URL: " & Request.Url.ToString())
                Response.StatusCode = 403
                Response.StatusDescription = "Forbidden"
                Response.End()
                Return
            End If
            
            ' Validate request size
            If Request.ContentLength > 10485760 Then ' 10MB limit
                SecurityHelper.LogSecurityEvent("REQUEST_SIZE_EXCEEDED", "Size: " & Request.ContentLength.ToString())
                Response.StatusCode = 413
                Response.StatusDescription = "Request Entity Too Large"
                Response.End()
                Return
            End If
            
        Catch ex As Exception
            SecurityHelper.LogSecurityEvent("APPLICATION_BEGIN_REQUEST_ERROR", ex.Message)
        End Try
    End Sub

    Sub Application_Start(ByVal sender As Object, ByVal e As EventArgs)
        Try
            ' Code that runs on application startup        
            RouteTable.Routes.MapHttpRoute(name:="DefaultApi",
                                           routeTemplate:="api/{controller}/{id}",
                                           defaults:=New With {
                                           Key .id = System.Web.Http.RouteParameter.[Optional]
                                           })
            
            ' Initialize security settings
            SecurityHelper.InitializeSecuritySettings()
            SecurityHelper.LogSecurityEvent("APPLICATION_STARTED", "Application initialized successfully")
            
        Catch ex As Exception
            SecurityHelper.LogSecurityEvent("APPLICATION_START_ERROR", ex.Message)
        End Try
    End Sub

    Sub Application_End(ByVal sender As Object, ByVal e As EventArgs)
        Try
            ' Code that runs on application shutdown
            SecurityHelper.LogSecurityEvent("APPLICATION_ENDED", "Application shutdown")
        Catch ex As Exception
            SecurityHelper.LogSecurityEvent("APPLICATION_END_ERROR", ex.Message)
        End Try
    End Sub

    Sub Application_Error(ByVal sender As Object, ByVal e As EventArgs)
        Try
            ' Code that runs when an unhandled error occurs
            Dim ex As Exception = Server.GetLastError()
            If ex IsNot Nothing Then
                ' Log the error securely without exposing sensitive information
                SecurityHelper.LogSecurityEvent("APPLICATION_ERROR", SecurityHelper.SanitizeLogMessage(ex.Message))
                
                ' Clear the error to prevent information disclosure
                Server.ClearError()
                
                ' Redirect to generic error page
                Response.Redirect("~/dashboard/Error.aspx", False)
            End If
        Catch logEx As Exception
            ' Fail silently if logging fails to prevent infinite loops
        End Try
    End Sub

    Sub Session_Start(ByVal sender As Object, ByVal e As EventArgs)
        Try
            ' Code that runs when a new session is started
            ' Generate and store CSRF token
            Session("CSRFToken") = SecurityHelper.GenerateCSRFToken()
            
            ' Set session timeout (30 minutes)
            Session.Timeout = 30
            
            ' Log session start
            SecurityHelper.LogSecurityEvent("SESSION_STARTED", "SessionID: " & Session.SessionID)
            
        Catch ex As Exception
            SecurityHelper.LogSecurityEvent("SESSION_START_ERROR", ex.Message)
        End Try
    End Sub

    Sub Session_End(ByVal sender As Object, ByVal e As EventArgs)
        Try
            ' Code that runs when a session ends
            ' Note: The Session_End event is raised only when the sessionstate mode
            ' is set to InProc in the Web.config file. If session mode is set to StateServer 
            ' or SQLServer, the event is not raised.
            
            ' Secure database operation with proper error handling
            If Session("userid") IsNot Nothing AndAlso Session("logintime") IsNot Nothing Then
                Dim userid As String = Session("userid").ToString()
                Dim logintime As String = Session("logintime").ToString()
                
                ' Validate inputs before database operation
                If SecurityHelper.IsValidUserId(userid) AndAlso SecurityHelper.IsValidDate(logintime, Nothing) Then
                    Using conn As New SqlConnection(System.Configuration.ConfigurationManager.AppSettings("sqlserverconnection"))
                        ' Use parameterized query to prevent SQL injection
                        Dim query As String = "UPDATE user_log SET status=0, logouttime=@logouttime WHERE userid=@userid AND logintime=@logintime"
                        Using cmd As New SqlCommand(query, conn)
                            cmd.Parameters.Add("@logouttime", SqlDbType.DateTime).Value = DateTime.Now
                            cmd.Parameters.Add("@userid", SqlDbType.Int).Value = Convert.ToInt32(userid)
                            cmd.Parameters.Add("@logintime", SqlDbType.DateTime).Value = Convert.ToDateTime(logintime)
                            
                            conn.Open()
                            cmd.ExecuteNonQuery()
                        End Using
                    End Using
                    
                    SecurityHelper.LogSecurityEvent("USER_LOGOUT", "UserID: " & userid)
                End If
            End If
            
        Catch ex As Exception
            ' Log error but don't expose sensitive information
            SecurityHelper.LogSecurityEvent("SESSION_END_ERROR", SecurityHelper.SanitizeLogMessage(ex.Message))
        End Try
    End Sub

</script>