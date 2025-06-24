<%@ Application Language="VB" %>
<%@ Import Namespace ="System.Data.SqlClient" %>
<%@ Import Namespace ="System.Web.Http" %>
<%@ Import Namespace ="System.Web.Routing" %>


<script runat="server">

    Sub Application_BeginRequest(ByVal sender As Object, ByVal e As EventArgs)
        'Response.Filter = New WhitespaceFilter(Response.Filter)
    End Sub

    Sub Application_Start(ByVal sender As Object, ByVal e As EventArgs)
        ' Code that runs on application startup        
        RouteTable.Routes.MapHttpRoute(name:="DefaultApi",
                                       routeTemplate:="api/{controller}/{id}",
                                       defaults:=New With {
                                       Key .id = System.Web.Http.RouteParameter.[Optional]
                                       })
    End Sub

    Sub Application_End(ByVal sender As Object, ByVal e As EventArgs)
        ' Code that runs on application shutdown        
    End Sub


    Sub Application_Error(ByVal sender As Object, ByVal e As EventArgs)
        ' Code that runs when an unhandled error occurs     
    End Sub
    Sub Session_Start(ByVal sender As Object, ByVal e As EventArgs)
        ' Code that runs when a new session is started     
    End Sub

    Sub Session_End(ByVal sender As Object, ByVal e As EventArgs)
        ' Code that runs when a session ends. 
        ' Note: The Session_End event is raised only when the sessionstate mode
        ' is set to InProc in the Web.config file. If session mode is set to StateServer 
        ' or SQLServer, the event is not raised.      
        Try
            Dim conn As New SqlConnection(System.Configuration.ConfigurationManager.AppSettings("sqlserverconnection"))
            Dim cmd As SqlCommand = New SqlCommand("update user_log set status=0,logouttime='" & Now.ToString("yyyy-MM-dd HH:mm:ss:fff") & "' where userid='" & Session("userid") & "' and logintime='" & Session("logintime") & "'", conn)
            conn.Open()
            cmd.ExecuteNonQuery()
            conn.Close()
        Catch ex As Exception

        End Try
    End Sub

</script>