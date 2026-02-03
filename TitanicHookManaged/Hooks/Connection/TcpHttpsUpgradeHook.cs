// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Oreeeee

using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Collections.Generic;
using System.Threading;
using TitanicHookManaged.Framework;
using TitanicHookManaged.Helpers;
using Harmony;

// ReSharper disable InconsistentNaming
namespace TitanicHookManaged.Hooks.Connection;

/// <summary>
/// Upgrades raw HTTP connections to HTTPS by intercepting Socket methods.
/// Redirects port 80 to 443 and wraps the socket with SSL.
/// </summary>
public class TcpHttpsUpgradeHook() : TitanicPatch(HookName)
{
    public const string HookName = "sh.Titanic.Hook.TcpHttpsUpgrade";

    public override void Patch()
    {
        // Socket.Connect sync overloads
        PatchSocketMethod("Connect", [typeof(EndPoint)],
            nameof(ConnectEndPointPrefix), nameof(ConnectPostfix));
        PatchSocketMethod("Connect", [typeof(IPAddress), typeof(int)],
            nameof(ConnectIpAddressPortPrefix), nameof(ConnectPostfix));
        PatchSocketMethod("Connect", [typeof(IPAddress[]), typeof(int)],
            nameof(ConnectIpAddressArrayPortPrefix), nameof(ConnectPostfix));
        PatchSocketMethod("Connect", [typeof(string), typeof(int)],
            nameof(ConnectHostPortPrefix), nameof(ConnectPostfix));
        
        // Socket.BeginConnect async overloads
        PatchSocketMethod("BeginConnect", [typeof(EndPoint), typeof(AsyncCallback), typeof(object)],
            nameof(BeginConnectEndPointPrefix));
        PatchSocketMethod("BeginConnect", [typeof(IPAddress), typeof(int), typeof(AsyncCallback), typeof(object)],
            nameof(BeginConnectIpAddressPortPrefix));
        PatchSocketMethod("BeginConnect", [typeof(IPAddress[]), typeof(int), typeof(AsyncCallback), typeof(object)],
            nameof(BeginConnectIpAddressArrayPortPrefix));
        PatchSocketMethod("BeginConnect", [typeof(string), typeof(int), typeof(AsyncCallback), typeof(object)],
            nameof(BeginConnectHostPortPrefix));
        
        // Socket.EndConnect - establish SSL after async connect completes
        PatchSocketMethod("EndConnect", [typeof(IAsyncResult)],
            postfixName: nameof(EndConnectPostfix));
        
        // Socket.Send sync overloads
        PatchSocketMethod("Send", [typeof(byte[]), typeof(int), typeof(int), typeof(SocketFlags)],
            nameof(SendPrefix));
        PatchSocketMethod("Send", [typeof(byte[]), typeof(SocketFlags)],
            nameof(SendBufferFlagsPrefix));
        PatchSocketMethod("Send", [typeof(byte[])],
            nameof(SendBufferPrefix));
        PatchSocketMethod("Send", [typeof(byte[]), typeof(int), typeof(int), typeof(SocketFlags), typeof(SocketError).MakeByRefType()],
            nameof(SendWithErrorPrefix));
        
        // Socket.BeginSend/EndSend async
        PatchSocketMethodByParamCount("BeginSend", 6, nameof(BeginSendPrefix));
        PatchSocketMethodByParamCount("EndSend", 1, nameof(EndSendPrefix));
        
        // Socket.Receive sync overloads
        PatchSocketMethod("Receive", [typeof(byte[]), typeof(int), typeof(int), typeof(SocketFlags)],
            nameof(ReceivePrefix));
        PatchSocketMethod("Receive", [typeof(byte[]), typeof(SocketFlags)],
            nameof(ReceiveBufferFlagsPrefix));
        PatchSocketMethod("Receive", [typeof(byte[])],
            nameof(ReceiveBufferPrefix));
        PatchSocketMethod("Receive", [typeof(byte[]), typeof(int), typeof(int), typeof(SocketFlags), typeof(SocketError).MakeByRefType()],
            nameof(ReceiveWithErrorPrefix));
        
        // Socket.BeginReceive/EndReceive async
        PatchSocketMethodByParamCount("BeginReceive", 6, nameof(BeginReceivePrefix));
        PatchSocketMethodByParamCount("EndReceive", 1, nameof(EndReceivePrefix));
        
        // Socket properties and state
        PatchSocketPropertyGetter("Available", nameof(AvailablePrefix));
        PatchSocketMethod("Poll", [typeof(int), typeof(SelectMode)], nameof(PollPrefix));
        PatchSocketMethod("Shutdown", [typeof(SocketShutdown)], nameof(ShutdownPrefix));
        PatchSocketMethod("Close", [], nameof(ClosePrefix));
    }
    
    #region Patching Helpers
    
    private void PatchSocketMethod(string methodName, Type[] paramTypes, string? prefixName = null, string? postfixName = null)
    {
        var method = typeof(Socket).GetMethod(methodName, BindingFlags.Instance | BindingFlags.Public, null, paramTypes, null);
        if (method == null)
        {
            Logging.HookError(HookName, $"Could not find Socket.{methodName}({string.Join(", ", paramTypes.Select(t => t.Name).ToArray())})");
            return;
        }
        
        var prefix = prefixName != null ? AccessTools.Method(typeof(TcpHttpsUpgradeHook), prefixName) : null;
        var postfix = postfixName != null ? AccessTools.Method(typeof(TcpHttpsUpgradeHook), postfixName) : null;
        
        try
        {
            Harmony.Patch(method,
                prefix != null ? new HarmonyMethod(prefix) : null,
                postfix != null ? new HarmonyMethod(postfix) : null);
        }
        catch (Exception ex)
        {
            Logging.HookError(HookName, $"Failed to patch Socket.{methodName}: {ex.Message}");
        }
    }
    
    private void PatchSocketMethodByParamCount(string methodName, int paramCount, string prefixName)
    {
        bool requiresByteArrayFirst = paramCount == 6;
        var method = typeof(Socket)
            .GetMethods(BindingFlags.Instance | BindingFlags.Public)
            .FirstOrDefault(m => m.Name == methodName &&
                                 m.GetParameters().Length == paramCount &&
                                 (!requiresByteArrayFirst || m.GetParameters()[0].ParameterType == typeof(byte[])));
        if (method == null)
        {
            Logging.HookError(HookName, $"Could not find Socket.{methodName}");
            return;
        }
        
        try
        {
            Harmony.Patch(method, new HarmonyMethod(AccessTools.Method(typeof(TcpHttpsUpgradeHook), prefixName)));
        }
        catch (Exception ex)
        {
            Logging.HookError(HookName, $"Failed to patch Socket.{methodName}: {ex.Message}");
        }
    }

    private void PatchSocketPropertyGetter(string propertyName, string prefixName)
    {
        var method = typeof(Socket)
            .GetProperty(propertyName, BindingFlags.Instance | BindingFlags.Public)?
            .GetGetMethod();
        if (method == null)
        {
            Logging.HookError(HookName, $"Could not find Socket.{propertyName} getter");
            return;
        }
        
        try
        {
            Harmony.Patch(method, new HarmonyMethod(AccessTools.Method(typeof(TcpHttpsUpgradeHook), prefixName)));
        }
        catch (Exception ex)
        {
            Logging.HookError(HookName, $"Failed to patch Socket.{propertyName}: {ex.Message}");
        }
    }
    
    #endregion

    #region Connect Hooks (Sync)

    private static void ConnectEndPointPrefix(Socket __instance, ref EndPoint __0)
    {
        if (__0 is not IPEndPoint endpoint || endpoint.Port != 80)
            return;
        
        Logging.HookTrigger(HookName);
        Logging.HookOutput(HookName, $"Upgrading {endpoint.Address}:80 -> :443");
        
        __0 = new IPEndPoint(endpoint.Address, 443);
        string hostname = DnsHostByNameHook.GetHostnameForIp(endpoint.Address.ToString()) ?? endpoint.Address.ToString();
        SslSocketState.AddPendingSocket(__instance, hostname);
    }

    private static void ConnectIpAddressPortPrefix(Socket __instance, IPAddress __0, ref int __1)
    {
        if (__1 != 80)
            return;
        
        Logging.HookTrigger(HookName);
        Logging.HookOutput(HookName, $"Upgrading {__0}:80 -> :443");
        
        __1 = 443;
        string hostname = DnsHostByNameHook.GetHostnameForIp(__0.ToString()) ?? __0.ToString();
        SslSocketState.AddPendingSocket(__instance, hostname);
    }

    private static void ConnectIpAddressArrayPortPrefix(Socket __instance, IPAddress[] __0, ref int __1)
    {
        if (__1 != 80 || __0.Length == 0)
            return;
        
        Logging.HookTrigger(HookName);
        Logging.HookOutput(HookName, $"Upgrading {__0[0]}:80 -> :443");
        
        __1 = 443;
        string hostname = DnsHostByNameHook.GetHostnameForIp(__0[0].ToString()) ?? __0[0].ToString();
        SslSocketState.AddPendingSocket(__instance, hostname);
    }

    private static void ConnectHostPortPrefix(Socket __instance, string __0, ref int __1)
    {
        if (__1 != 80)
            return;
        
        Logging.HookTrigger(HookName);
        Logging.HookOutput(HookName, $"Upgrading {__0}:80 -> :443");
        
        __1 = 443;
        SslSocketState.AddPendingSocket(__instance, __0);
    }

    private static void ConnectPostfix(Socket __instance) => EstablishSslAfterConnect(__instance, "Connect");

    #endregion

    #region BeginConnect Hooks (Async)

    private static void BeginConnectEndPointPrefix(Socket __instance, ref EndPoint __0)
    {
        if (__0 is not IPEndPoint endpoint || endpoint.Port != 80)
            return;
        
        Logging.HookTrigger(HookName);
        Logging.HookOutput(HookName, $"Upgrading {endpoint.Address}:80 -> :443");
        
        __0 = new IPEndPoint(endpoint.Address, 443);
        string hostname = DnsHostByNameHook.GetHostnameForIp(endpoint.Address.ToString()) ?? endpoint.Address.ToString();
        SslSocketState.AddPendingSocket(__instance, hostname);
    }

    private static void BeginConnectIpAddressPortPrefix(Socket __instance, IPAddress __0, ref int __1)
    {
        if (__1 != 80)
            return;
        
        Logging.HookTrigger(HookName);
        Logging.HookOutput(HookName, $"Upgrading {__0}:80 -> :443");
        
        __1 = 443;
        string hostname = DnsHostByNameHook.GetHostnameForIp(__0.ToString()) ?? __0.ToString();
        SslSocketState.AddPendingSocket(__instance, hostname);
    }

    private static void BeginConnectIpAddressArrayPortPrefix(Socket __instance, IPAddress[] __0, ref int __1)
    {
        if (__1 != 80 || __0.Length == 0)
            return;
        
        Logging.HookTrigger(HookName);
        Logging.HookOutput(HookName, $"Upgrading {__0[0]}:80 -> :443");
        
        __1 = 443;
        string hostname = DnsHostByNameHook.GetHostnameForIp(__0[0].ToString()) ?? __0[0].ToString();
        SslSocketState.AddPendingSocket(__instance, hostname);
    }

    private static void BeginConnectHostPortPrefix(Socket __instance, string __0, ref int __1)
    {
        if (__1 != 80)
            return;
        
        Logging.HookTrigger(HookName);
        Logging.HookOutput(HookName, $"Upgrading {__0}:80 -> :443");
        
        __1 = 443;
        SslSocketState.AddPendingSocket(__instance, __0);
    }

    private static void EndConnectPostfix(Socket __instance) => EstablishSslAfterConnect(__instance, "EndConnect");

    #endregion

    #region SSL Establishment
    
    private static void EstablishSslAfterConnect(Socket socket, string methodName)
    {
        string? hostname = SslSocketState.GetAndRemovePendingSocket(socket);
        if (hostname == null)
            return;
        
        if (!socket.Connected)
        {
            Logging.Warning($"[{HookName}] Socket not connected after {methodName}(), skipping SSL for {hostname}");
            return;
        }
        
        bool wasBlocking = socket.Blocking;
        try
        {
            if (!wasBlocking)
                socket.Blocking = true;
            
            if (SslHelper.TryEstablishSslConnection(socket, hostname, out SslStream? sslStream))
                SslSocketState.RegisterSslSocket(socket, sslStream!);
        }
        catch (Exception ex)
        {
            Logging.HookError(HookName, $"SSL connection failed ({methodName}): {ex.Message}");
        }
        finally
        {
            if (!wasBlocking)
                try { socket.Blocking = false; } catch { /* ignored */ }
        }
    }

    /// <summary>
    /// Attempts to establish SSL for a pending socket (e.g., when EndConnect wasn't called).
    /// Returns true if SSL was established or socket isn't ready yet (will retry later).
    /// </summary>
    internal static bool TryEstablishSslForPendingSocket(Socket socket)
    {
        if (SslSocketState.IsInsideSslOperation)
            return true;
        
        if (!socket.Connected)
            return true;
        
        string? hostname = SslSocketState.PeekPendingSocket(socket);
        if (string.IsNullOrEmpty(hostname))
            return true;
        
        bool wasBlocking = socket.Blocking;
        SslSocketState.EnterSslOperation();
        try
        {
            if (!wasBlocking)
                socket.Blocking = true;
            
            if (SslHelper.TryEstablishSslConnection(socket, hostname, out SslStream? sslStream))
            {
                SslSocketState.GetAndRemovePendingSocket(socket);
                SslSocketState.RegisterSslSocket(socket, sslStream!);
                return true;
            }
            
            SslSocketState.GetAndRemovePendingSocket(socket);
            return false;
        }
        catch (InvalidOperationException)
        {
            return true; // Socket not ready, will retry later
        }
        catch (Exception ex)
        {
            Logging.HookError(HookName, $"Late SSL setup failed: {ex.Message}");
            SslSocketState.GetAndRemovePendingSocket(socket);
            return false;
        }
        finally
        {
            SslSocketState.ExitSslOperation();
            if (!wasBlocking)
                try { socket.Blocking = false; } catch { /* ignored */ }
        }
    }

    #endregion

    #region Send Hooks

    private static bool SendPrefix(Socket __instance, byte[] __0, int __1, int __2, ref int __result)
    {
        if (!SslHelper.TrySslSend(__instance, __0, __1, __2, out int sent))
            return true;
        __result = sent;
        return false;
    }

    private static bool SendBufferFlagsPrefix(Socket __instance, byte[] __0, ref int __result)
    {
        if (!SslHelper.TrySslSend(__instance, __0, 0, __0.Length, out int sent))
            return true;
        __result = sent;
        return false;
    }

    private static bool SendBufferPrefix(Socket __instance, byte[] __0, ref int __result)
    {
        if (!SslHelper.TrySslSend(__instance, __0, 0, __0.Length, out int sent))
            return true;
        __result = sent;
        return false;
    }

    private static bool SendWithErrorPrefix(Socket __instance, byte[] __0, int __1, int __2, ref SocketError __4, ref int __result)
    {
        if (SslSocketState.IsInsideSslOperation || !SslSocketState.IsSslSocket(__instance))
            return true;
        
        if (!SslHelper.TrySslSend(__instance, __0, __1, __2, out int sent))
            return true;
        
        __result = sent;
        __4 = sent > 0 ? SocketError.Success : SocketError.SocketError;
        return false;
    }

    #endregion

    #region Receive Hooks

    private static bool ReceivePrefix(Socket __instance, byte[] __0, int __1, int __2, ref int __result)
    {
        if (!SslHelper.TrySslReceive(__instance, __0, __1, __2, out int received))
            return true;
        __result = received;
        return false;
    }

    private static bool ReceiveBufferFlagsPrefix(Socket __instance, byte[] __0, ref int __result)
    {
        if (!SslHelper.TrySslReceive(__instance, __0, 0, __0.Length, out int received))
            return true;
        __result = received;
        return false;
    }

    private static bool ReceiveBufferPrefix(Socket __instance, byte[] __0, ref int __result)
    {
        if (!SslHelper.TrySslReceive(__instance, __0, 0, __0.Length, out int received))
            return true;
        __result = received;
        return false;
    }

    private static bool ReceiveWithErrorPrefix(Socket __instance, byte[] __0, int __1, int __2, ref SocketError __4, ref int __result)
    {
        if (SslSocketState.IsInsideSslOperation || !SslSocketState.IsSslSocket(__instance))
            return true;
        
        if (!SslHelper.TrySslReceive(__instance, __0, __1, __2, out int received))
            return true;
        
        __result = received;
        __4 = received >= 0 ? SocketError.Success : SocketError.SocketError;
        return false;
    }

    #endregion

    #region BeginSend/EndSend Async Hooks

    private static bool BeginSendPrefix(Socket __instance, byte[] __0, int __1, int __2,
        SocketFlags __3, AsyncCallback __4, object __5, ref IAsyncResult __result)
    {
        if (SslSocketState.IsInsideSslOperation)
            return true;
        
        if (SslSocketState.HasPendingSocket(__instance) && !SslSocketState.IsSslSocket(__instance))
            TryEstablishSslForPendingSocket(__instance);
        
        var sslStream = SslSocketState.GetSslStream(__instance);
        if (sslStream == null)
            return true;
        
        if (!sslStream.CanWrite)
        {
            SslSocketState.RemoveSslSocket(__instance);
            __result = new CompletedAsyncResult(0, __5, new IOException("SSL stream closed"));
            __4?.Invoke(__result);
            return false;
        }
        
        var socketLock = SslSocketState.GetSocketLock(__instance);
        if (socketLock == null)
            return true;
        
        int bytesWritten = 0;
        Exception? error = null;
        
        try
        {
            lock (socketLock)
            {
                SslSocketState.EnterSslOperation();
                try
                {
                    sslStream.Write(__0, __1, __2);
                    sslStream.Flush();
                    bytesWritten = __2;
                }
                finally
                {
                    SslSocketState.ExitSslOperation();
                }
            }
        }
        catch (Exception ex)
        {
            error = ex;
            Logging.HookError(HookName, $"BeginSend SSL write failed: {ex.Message}");
            SslSocketState.RemoveSslSocket(__instance);
        }
        
        __result = new CompletedAsyncResult(bytesWritten, __5, error);
        __4?.Invoke(__result);
        return false;
    }

    private static bool EndSendPrefix(IAsyncResult __0, ref int __result)
    {
        if (__0 is not CompletedAsyncResult completed)
            return true;
        
        if (completed.Error != null)
            throw completed.Error;
        
        __result = completed.BytesTransferred;
        return false;
    }

    #endregion

    #region BeginReceive/EndReceive Async Hooks

    private static bool BeginReceivePrefix(Socket __instance, byte[] __0, int __1, int __2,
        SocketFlags __3, AsyncCallback __4, object __5, ref IAsyncResult __result)
    {
        if (SslSocketState.IsInsideSslOperation)
            return true;
        
        if (SslSocketState.HasPendingSocket(__instance) && !SslSocketState.IsSslSocket(__instance))
            TryEstablishSslForPendingSocket(__instance);
        
        var sslStream = SslSocketState.GetSslStream(__instance);
        if (sslStream == null)
            return true;
        
        if (!sslStream.CanRead)
        {
            SslSocketState.RemoveSslSocket(__instance);
            __result = new CompletedAsyncResult(0, __5, new IOException("SSL stream closed"));
            __4?.Invoke(__result);
            return false;
        }
        
        var socketLock = SslSocketState.GetSocketLock(__instance);
        if (socketLock == null)
            return true;
        
        int bytesRead = 0;
        Exception? error = null;
        
        try
        {
            lock (socketLock)
            {
                SslSocketState.EnterSslOperation();
                try
                {
                    bytesRead = sslStream.Read(__0, __1, __2);
                }
                finally
                {
                    SslSocketState.ExitSslOperation();
                }
            }
        }
        catch (IOException ioEx) when (ioEx.InnerException is SocketException { SocketErrorCode: SocketError.WouldBlock })
        {
            bytesRead = 0;
        }
        catch (Exception ex)
        {
            error = ex;
            Logging.HookError(HookName, $"BeginReceive SSL read failed: {ex.Message}");
            SslSocketState.RemoveSslSocket(__instance);
        }
        
        __result = new CompletedAsyncResult(bytesRead, __5, error);
        __4?.Invoke(__result);
        return false;
    }

    private static bool EndReceivePrefix(IAsyncResult __0, ref int __result)
    {
        if (__0 is not CompletedAsyncResult completed)
            return true;
        
        if (completed.Error != null)
            throw completed.Error;
        
        __result = completed.BytesTransferred;
        return false;
    }

    #endregion

    #region Socket Property/State Hooks

    private static bool AvailablePrefix(Socket __instance, ref int __result)
    {
        if (SslSocketState.IsInsideSslOperation || !SslSocketState.IsSslSocket(__instance))
            return true;
        
        SslSocketState.EnterSslOperation();
        try
        {
            __result = __instance.Available > 0 ? 1 : 0;
        }
        finally
        {
            SslSocketState.ExitSslOperation();
        }
        
        return false;
    }

    private static bool PollPrefix(Socket __instance, int __0, SelectMode __1, ref bool __result)
    {
        if (SslSocketState.IsInsideSslOperation || !SslSocketState.IsSslSocket(__instance))
            return true;
        
        if (__1 != SelectMode.SelectRead)
            return true;
        
        SslSocketState.EnterSslOperation();
        try
        {
            __result = __instance.Poll(__0, SelectMode.SelectRead);
        }
        finally
        {
            SslSocketState.ExitSslOperation();
        }
        
        return false;
    }

    private static bool ShutdownPrefix(Socket __instance)
    {
        // Block Shutdown for SSL sockets - it corrupts TLS state
        return SslSocketState.IsInsideSslOperation || !SslSocketState.IsSslSocket(__instance);
    }

    private static bool ClosePrefix(Socket __instance)
    {
        // Block Close for SSL sockets to allow pending reads
        return SslSocketState.IsInsideSslOperation || !SslSocketState.IsSslSocket(__instance);
    }

    #endregion
}

/// <summary>
/// SSL/TLS helper methods for HTTP -> HTTPS upgrade.
/// </summary>
internal static class SslHelper
{
    private const string HookName = TcpHttpsUpgradeHook.HookName;
    
    /// <summary>
    /// Certificate validation callback. Currently accepts all certificates.
    /// </summary>
    public static bool ValidateServerCertificate(
        object sender,
        X509Certificate? certificate,
        X509Chain? chain,
        SslPolicyErrors errors)
    {
        // TODO: Implement proper certificate validation
        return true;
    }
    
    /// <summary>
    /// Returns SSL protocols to try in order of preference.
    /// </summary>
    public static SslProtocols[] GetProtocolsToTry()
    {
        // Define protocols explicitly for .NET Framework compatibility
        const SslProtocols Tls12 = (SslProtocols)3072;
        const SslProtocols Tls11 = (SslProtocols)768;
        const SslProtocols Tls = SslProtocols.Tls;
        const SslProtocols Default = SslProtocols.Default;

        return
        [
            Tls12 | Tls11 | Tls,
            Tls12,
            Tls11,
            Tls,
            Default
        ];
    }
    
    /// <summary>
    /// Attempts to establish an SSL connection over the given socket.
    /// </summary>
    public static bool TryEstablishSslConnection(Socket socket, string hostname, out SslStream? sslStream)
    {
        NetworkStream? networkStream = null;
        Exception? lastException = null;
        sslStream = null;

        foreach (var protocol in GetProtocolsToTry())
        {
            try
            {
                networkStream?.Dispose();
                sslStream?.Dispose();
                
                networkStream = new NetworkStream(socket, ownsSocket: false);
                sslStream = new SslStream(networkStream, leaveInnerStreamOpen: true, ValidateServerCertificate);
                sslStream.AuthenticateAsClient(hostname, null, protocol, false);
                
                if (!sslStream.IsAuthenticated)
                    throw new InvalidOperationException("SSL stream not authenticated after handshake");
                
                Logging.HookOutput(HookName, $"SSL handshake OK: {hostname} ({protocol})");
                return true;
            }
            catch (Exception ex)
            {
                lastException = ex;
            }
        }
        
        Logging.Error($"SSL handshake failed: {lastException?.Message}");
        
        networkStream?.Dispose();
        sslStream?.Dispose();
        sslStream = null;
        return false;
    }
    
    /// <summary>
    /// Performs SSL send operation.
    /// </summary>
    public static bool TrySslSend(Socket socket, byte[] buffer, int offset, int count, out int bytesSent)
    {
        bytesSent = 0;
        
        if (SslSocketState.IsInsideSslOperation)
            return false;
        
        // Try to establish SSL if this socket has a pending upgrade
        if (SslSocketState.HasPendingSocket(socket) && !SslSocketState.IsSslSocket(socket))
            TcpHttpsUpgradeHook.TryEstablishSslForPendingSocket(socket);
        
        var sslStream = SslSocketState.GetSslStream(socket);
        if (sslStream == null)
            return false;
        
        if (!sslStream.CanWrite)
        {
            SslSocketState.RemoveSslSocket(socket);
            return true; // Handled, but with 0 bytes
        }
        
        var socketLock = SslSocketState.GetSocketLock(socket);
        if (socketLock == null)
            return false;
        
        try
        {
            lock (socketLock)
            {
                SslSocketState.EnterSslOperation();
                try
                {
                    sslStream.Write(buffer, offset, count);
                    sslStream.Flush();
                }
                finally
                {
                    SslSocketState.ExitSslOperation();
                }
            }
            bytesSent = count;
            return true;
        }
        catch (ObjectDisposedException)
        {
            SslSocketState.RemoveSslSocket(socket);
            return true;
        }
        catch (Exception ex)
        {
            Logging.HookError(HookName, $"SSL Send failed: {ex.Message}");
            return true;
        }
    }
    
    /// <summary>
    /// Performs SSL receive operation.
    /// </summary>
    public static bool TrySslReceive(Socket socket, byte[] buffer, int offset, int count, out int bytesReceived)
    {
        bytesReceived = 0;
        
        if (SslSocketState.IsInsideSslOperation)
            return false;
        
        // Try to establish SSL if this socket has a pending upgrade
        if (SslSocketState.HasPendingSocket(socket) && !SslSocketState.IsSslSocket(socket))
            TcpHttpsUpgradeHook.TryEstablishSslForPendingSocket(socket);
        
        var sslStream = SslSocketState.GetSslStream(socket);
        if (sslStream == null)
            return false;
        
        if (!sslStream.CanRead)
        {
            SslSocketState.RemoveSslSocket(socket);
            return true;
        }
        
        var socketLock = SslSocketState.GetSocketLock(socket);
        if (socketLock == null)
            return false;
        
        try
        {
            lock (socketLock)
            {
                // Check for data availability
                bool hasData;
                SslSocketState.EnterSslOperation();
                try
                {
                    hasData = socket.Available > 0;
                }
                finally
                {
                    SslSocketState.ExitSslOperation();
                }
                
                // Non-blocking mode with no data -> throw WouldBlock
                if (!socket.Blocking && !hasData)
                    throw new SocketException((int)SocketError.WouldBlock);
                
                // Force blocking mode for SSL read (TLS records may span packets)
                bool wasBlocking = socket.Blocking;
                SslSocketState.EnterSslOperation();
                try
                {
                    if (!wasBlocking)
                        socket.Blocking = true;
                    
                    bytesReceived = sslStream.Read(buffer, offset, count);
                }
                finally
                {
                    if (!wasBlocking)
                        socket.Blocking = false;
                    SslSocketState.ExitSslOperation();
                }
            }
            return true;
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.WouldBlock)
        {
            throw;
        }
        catch (IOException ex) when (ex.InnerException is SocketException { SocketErrorCode: SocketError.WouldBlock } sockEx)
        {
            throw sockEx;
        }
        catch (ObjectDisposedException)
        {
            SslSocketState.RemoveSslSocket(socket);
            return true;
        }
        catch (IOException ex)
        {
            Logging.Error($"SSL IO error: {ex.Message}");
            SslSocketState.RemoveSslSocket(socket);
            return true;
        }
        catch (Exception ex)
        {
            Logging.Error($"SSL Receive failed: {ex.Message}");
            return true;
        }
    }
}

/// <summary>
/// Tracks SSL socket state for HTTP -> HTTPS upgrade hooks.
/// </summary>
internal static class SslSocketState
{
    private static readonly Dictionary<Socket, string> _pendingSockets = new();
    private static readonly Dictionary<Socket, SslStream> _sslSockets = new();
    private static readonly Dictionary<Socket, object> _socketLocks = new();
    private static readonly object _lock = new();
    
    [System.ThreadStatic]
    private static bool _insideSslOperation;
    
    #region SSL Operation Guard
    
    /// <summary>
    /// Whether we're currently inside an SSL operation (prevents recursion).
    /// </summary>
    public static bool IsInsideSslOperation => _insideSslOperation;
    
    public static void EnterSslOperation() => _insideSslOperation = true;
    public static void ExitSslOperation() => _insideSslOperation = false;
    
    #endregion
    
    #region Pending Sockets (awaiting SSL handshake)
    
    public static void AddPendingSocket(Socket socket, string hostname)
    {
        lock (_lock)
            _pendingSockets[socket] = hostname;
    }
    
    public static bool HasPendingSocket(Socket socket)
    {
        lock (_lock)
            return _pendingSockets.ContainsKey(socket);
    }
    
    public static string? PeekPendingSocket(Socket socket)
    {
        lock (_lock)
            return _pendingSockets.TryGetValue(socket, out string? hostname) ? hostname : null;
    }
    
    public static string? GetAndRemovePendingSocket(Socket socket)
    {
        lock (_lock)
        {
            if (!_pendingSockets.TryGetValue(socket, out string? hostname))
                return null;
            
            _pendingSockets.Remove(socket);
            return hostname;
        }
    }
    
    #endregion
    
    #region SSL Sockets (handshake complete)
    
    public static void RegisterSslSocket(Socket socket, SslStream sslStream)
    {
        lock (_lock)
        {
            _sslSockets[socket] = sslStream;
            _socketLocks[socket] = new object();
        }
    }
    
    public static bool IsSslSocket(Socket socket)
    {
        lock (_lock)
            return _sslSockets.ContainsKey(socket);
    }
    
    public static SslStream? GetSslStream(Socket socket)
    {
        lock (_lock)
            return _sslSockets.TryGetValue(socket, out SslStream? stream) ? stream : null;
    }
    
    public static object? GetSocketLock(Socket socket)
    {
        lock (_lock)
            return _socketLocks.TryGetValue(socket, out object? lockObj) ? lockObj : null;
    }
    
    public static void RemoveSslSocket(Socket socket)
    {
        lock (_lock)
        {
            _sslSockets.Remove(socket);
            _socketLocks.Remove(socket);
        }
    }
    
    #endregion
}

/// <summary>
/// IAsyncResult implementation for completed async operations.
/// Allows returning synchronous SSL results through the async Socket API.
/// </summary>
internal class CompletedAsyncResult : IAsyncResult
{
    public int BytesTransferred { get; }
    public Exception? Error { get; }
    public object? AsyncState { get; }
    public WaitHandle AsyncWaitHandle { get; } = new ManualResetEvent(true);
    public bool CompletedSynchronously => true;
    public bool IsCompleted => true;
    
    public CompletedAsyncResult(int bytesTransferred, object? state, Exception? error = null)
    {
        BytesTransferred = bytesTransferred;
        AsyncState = state;
        Error = error;
    }
}
