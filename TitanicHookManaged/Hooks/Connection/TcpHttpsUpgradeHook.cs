// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Oreeeee

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using TitanicHookManaged.Framework;
using TitanicHookManaged.Helpers;
using Harmony;

// ReSharper disable InconsistentNaming
namespace TitanicHookManaged.Hooks.Connection;

/// <summary>
/// Upgrades raw HTTP connections to HTTPS, by intercepting Socket methods.
/// Redirects port 80 to 443 and wraps the socket with SSL.
/// </summary>
public class TcpHttpsUpgradeHook() : TitanicPatch(HookName)
{
    public const string HookName = "sh.Titanic.Hook.TcpHttpsUpgrade";

    public override void Patch()
    {
        // Socket.Connect(...) sync overloads
        PatchMethod("Connect", [typeof(EndPoint)],
            nameof(ConnectEndPointPrefix), nameof(ConnectPostfix));
        PatchMethod("Connect", [typeof(IPAddress), typeof(int)],
            nameof(ConnectIpAddressPortPrefix), nameof(ConnectPostfix));
        PatchMethod("Connect", [typeof(IPAddress[]), typeof(int)],
            nameof(ConnectIpAddressArrayPortPrefix), nameof(ConnectPostfix));
        PatchMethod("Connect", [typeof(string), typeof(int)],
            nameof(ConnectHostPortPrefix), nameof(ConnectPostfix));
        
        // Socket.BeginConnect(...) async overloads
        PatchMethod("BeginConnect", [typeof(EndPoint), typeof(AsyncCallback), typeof(object)],
            nameof(BeginConnectEndPointPrefix));
        PatchMethod("BeginConnect", [typeof(IPAddress), typeof(int), typeof(AsyncCallback), typeof(object)],
            nameof(BeginConnectIpAddressPortPrefix));
        PatchMethod("BeginConnect", [typeof(IPAddress[]), typeof(int), typeof(AsyncCallback), typeof(object)],
            nameof(BeginConnectIpAddressArrayPortPrefix));
        PatchMethod("BeginConnect", [typeof(string), typeof(int), typeof(AsyncCallback), typeof(object)],
            nameof(BeginConnectHostPortPrefix));
        
        // Socket.EndConnect -> this is where we establish SSL after async connect completes
        PatchMethod("EndConnect", [typeof(IAsyncResult)],
            null, nameof(EndConnectPostfix));
        
        // Socket.Send(...) sync overloads
        PatchMethod("Send", [typeof(byte[]), typeof(int), typeof(int), typeof(SocketFlags)],
            nameof(SendOverloadBufferOffsetSizeFlags));
        PatchMethod("Send", [typeof(byte[]), typeof(SocketFlags)],
            nameof(SendOverloadBufferFlags));
        PatchMethod("Send", [typeof(byte[])],
            nameof(SendOverloadBuffer));
        PatchMethod("Send", [typeof(byte[]), typeof(int), typeof(int), typeof(SocketFlags), typeof(SocketError).MakeByRefType()],
            nameof(SendOverloadBufferOffsetSizeFlagsOutError));
        
        // Socket.BeginSend/EndSend async
        PatchAsyncMethod("BeginSend", 6, nameof(BeginSendPrefix));
        PatchAsyncMethod("EndSend", 1, nameof(EndSendPrefix));
        
        // Socket.Receive(...) sync overloads
        PatchMethod("Receive", [typeof(byte[]), typeof(int), typeof(int), typeof(SocketFlags)],
            nameof(ReceiveOverloadBufferOffsetSizeFlags));
        PatchMethod("Receive", [typeof(byte[]), typeof(SocketFlags)],
            nameof(ReceiveOverloadBufferFlags));
        PatchMethod("Receive", [typeof(byte[])],
            nameof(ReceiveOverloadBuffer));
        PatchMethod("Receive", [typeof(byte[]), typeof(int), typeof(int), typeof(SocketFlags), typeof(SocketError).MakeByRefType()],
            nameof(ReceiveOverloadBufferOffsetSizeFlagsOutError));
        
        // Socket.BeginReceive/EndReceive async
        PatchAsyncMethod("BeginReceive", 6, nameof(BeginReceivePrefix));
        PatchAsyncMethod("EndReceive", 1, nameof(EndReceivePrefix));
        
        // Properties and state
        PatchPropertyGetter("Available", nameof(AvailablePrefix));
        PatchMethod("Poll", [typeof(int), typeof(SelectMode)],
            nameof(PollPrefix));
        PatchMethod("Shutdown", [typeof(SocketShutdown)],
            nameof(ShutdownPrefix));
        PatchMethod("Close", [],
            nameof(ClosePrefix));
    }
    
    private void PatchAsyncMethod(string methodName, int paramCount, string prefixName)
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

    private void PatchMethod(string methodName, Type[] paramTypes, string? prefixName, string? postfixName = null)
    {
        var method = typeof(Socket).GetMethod(methodName, BindingFlags.Instance | BindingFlags.Public, null, paramTypes, null);
        if (method == null)
        {
            string[] typeNames = paramTypes.Select(t => t.Name).ToArray();
            Logging.HookError(HookName, $"Could not find Socket.{methodName}({string.Join(", ", typeNames)})");
            return;
        }
        
        MethodInfo? prefix = prefixName != null ? AccessTools.Method(typeof(TcpHttpsUpgradeHook), prefixName) : null;
        MethodInfo? postfix = postfixName != null ? AccessTools.Method(typeof(TcpHttpsUpgradeHook), postfixName) : null;
        
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

    private void PatchPropertyGetter(string propertyName, string prefixName)
    {
        var method = typeof(Socket)
            .GetProperty(propertyName, BindingFlags.Instance | BindingFlags.Public)?
            .GetGetMethod();
        if (method == null)
        {
            Logging.HookError(HookName, $"Could not find Socket.{propertyName} getter");
            return;
        }
        
        var prefix = AccessTools.Method(typeof(TcpHttpsUpgradeHook), prefixName);
        
        try
        {
            Harmony.Patch(method, new HarmonyMethod(prefix));
        }
        catch (Exception ex)
        {
            Logging.HookError(HookName, $"Failed to patch Socket.{propertyName}: {ex.Message}");
        }
    }

    #region Socket.Connect Hooks

    /// <summary>Prefix for Socket.Connect(EndPoint)</summary>
    private static void ConnectEndPointPrefix(Socket __instance, ref EndPoint __0)
    {
        if (__0 is not IPEndPoint ipEndPoint || ipEndPoint.Port != 80)
            return;
        
        Logging.HookTrigger(HookName);
        Logging.HookOutput(HookName, $"Upgrading {ipEndPoint.Address}:80 -> :443");
        
        __0 = new IPEndPoint(ipEndPoint.Address, 443);
        
        string hostname = DnsHostByNameHook.GetHostnameForIp(ipEndPoint.Address.ToString()) 
                          ?? ipEndPoint.Address.ToString();
        
        SSLSocketState.AddPendingSocket(__instance, hostname);
    }

    /// <summary>Prefix for Socket.Connect(IPAddress, int)</summary>
    private static void ConnectIpAddressPortPrefix(Socket __instance, IPAddress __0, ref int __1)
    {
        if (__1 != 80)
            return;
        
        Logging.HookTrigger(HookName);
        Logging.HookOutput(HookName, $"Upgrading {__0}:80 -> :443");
        
        __1 = 443;
        
        string hostname = DnsHostByNameHook.GetHostnameForIp(__0.ToString()) 
                          ?? __0.ToString();
        
        SSLSocketState.AddPendingSocket(__instance, hostname);
    }

    /// <summary>Prefix for Socket.Connect(IPAddress[], int)</summary>
    private static void ConnectIpAddressArrayPortPrefix(Socket __instance, IPAddress[] __0, ref int __1)
    {
        if (__1 != 80 || __0.Length == 0)
            return;
        
        Logging.HookTrigger(HookName);
        Logging.HookOutput(HookName, $"Upgrading {__0[0]}:80 -> :443");
        
        __1 = 443;
        
        string hostname = DnsHostByNameHook.GetHostnameForIp(__0[0].ToString()) 
                          ?? __0[0].ToString();
        
        SSLSocketState.AddPendingSocket(__instance, hostname);
    }

    /// <summary>Prefix for Socket.Connect(string, int)</summary>
    private static void ConnectHostPortPrefix(Socket __instance, string __0, ref int __1)
    {
        if (__1 != 80)
            return;
        
        Logging.HookTrigger(HookName);
        Logging.HookOutput(HookName, $"Upgrading {__0}:80 -> :443");
        
        __1 = 443;
        
        SSLSocketState.AddPendingSocket(__instance, __0);
    }

    #endregion

    #region Socket.BeginConnect Hooks (Async)

    /// <summary>Prefix for Socket.BeginConnect(EndPoint, AsyncCallback, object)</summary>
    private static void BeginConnectEndPointPrefix(Socket __instance, ref EndPoint __0)
    {
        if (__0 is not IPEndPoint ipEndPoint || ipEndPoint.Port != 80)
            return;
        
        Logging.HookTrigger(HookName);
        Logging.HookOutput(HookName, $"Upgrading {ipEndPoint.Address}:80 -> :443");
        
        __0 = new IPEndPoint(ipEndPoint.Address, 443);
        
        string hostname = DnsHostByNameHook.GetHostnameForIp(ipEndPoint.Address.ToString()) 
                          ?? ipEndPoint.Address.ToString();
        
        SSLSocketState.AddPendingSocket(__instance, hostname);
    }

    /// <summary>Prefix for Socket.BeginConnect(IPAddress, int, AsyncCallback, object)</summary>
    private static void BeginConnectIpAddressPortPrefix(Socket __instance, IPAddress __0, ref int __1)
    {
        if (__1 != 80)
            return;
        
        Logging.HookTrigger(HookName);
        Logging.HookOutput(HookName, $"Upgrading {__0}:80 -> :443");
        
        __1 = 443;
        
        string hostname = DnsHostByNameHook.GetHostnameForIp(__0.ToString()) 
                          ?? __0.ToString();
        
        SSLSocketState.AddPendingSocket(__instance, hostname);
    }

    /// <summary>Prefix for Socket.BeginConnect(IPAddress[], int, AsyncCallback, object)</summary>
    private static void BeginConnectIpAddressArrayPortPrefix(Socket __instance, IPAddress[] __0, ref int __1)
    {
        if (__1 != 80 || __0.Length == 0)
            return;
        
        Logging.HookTrigger(HookName);
        Logging.HookOutput(HookName, $"Upgrading {__0[0]}:80 -> :443");
        
        __1 = 443;
        
        string hostname = DnsHostByNameHook.GetHostnameForIp(__0[0].ToString()) 
                          ?? __0[0].ToString();
        
        SSLSocketState.AddPendingSocket(__instance, hostname);
    }

    /// <summary>Prefix for Socket.BeginConnect(string, int, AsyncCallback, object)</summary>
    private static void BeginConnectHostPortPrefix(Socket __instance, string __0, ref int __1)
    {
        if (__1 != 80)
            return;
        
        Logging.HookTrigger(HookName);
        Logging.HookOutput(HookName, $"Upgrading {__0}:80 -> :443");
        
        __1 = 443;
        
        SSLSocketState.AddPendingSocket(__instance, __0);
    }

    /// <summary>Postfix for Socket.EndConnect(IAsyncResult) - establish SSL after async connect</summary>
    private static void EndConnectPostfix(Socket __instance) => EstablishSslAfterConnect(__instance, "EndConnect");

    #endregion

    #region Socket.Connect Postfix (Sync)

    private static void ConnectPostfix(Socket __instance) => EstablishSslAfterConnect(__instance, "Connect");
    
    private static void EstablishSslAfterConnect(Socket socket, string methodName)
    {
        string? hostname = SSLSocketState.GetAndRemovePendingSocket(socket);
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
            
            if (TryEstablishSslConnection(socket, hostname, out SslStream? sslStream))
            {
                SSLSocketState.RegisterSslSocket(socket, sslStream!);
            }
        }
        catch (Exception ex)
        {
            Logging.HookError(HookName, $"SSL connection failed ({methodName}): {ex.Message}");
        }
        finally
        {
            if (!wasBlocking)
            {
                try { socket.Blocking = false; } catch { }
            }
        }
    }

    private static bool TryEstablishSslConnection(Socket socket, string hostname, out SslStream? sslStream)
    {
        NetworkStream? networkStream = null;
        Exception? lastException = null;
        sslStream = null;

        var protocols = SSLHelper.GetProtocolsToTry();

        foreach (var protocol in protocols)
        {
            try
            {
                networkStream?.Dispose();
                sslStream?.Dispose();
                
                networkStream = new NetworkStream(socket, ownsSocket: false);
                sslStream = new SslStream(networkStream, leaveInnerStreamOpen: true, SSLHelper.ValidateServerCertificate);
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
    /// Attempts to establish SSL for a socket that was marked as pending (via BeginConnect)
    /// but never had SSL established (e.g., EndConnect was never called or didn't trigger our postfix).
    /// Returns true if SSL was established or if the socket isn't ready yet (will retry later).
    /// Returns false if SSL setup failed permanently.
    /// </summary>
    internal static bool TryEstablishSslForPendingSocket(Socket socket)
    {
        // Prevent recursion, ssl handshake will use socket operations internally
        if (SSLSocketState.IsInsideSslOperation)
            return true;
        
        // Don't attempt if socket reports not connected
        if (!socket.Connected)
            return true;
        
        // Peek at hostname without removing, we'll remove only on success
        string? hostname = SSLSocketState.PeekPendingSocket(socket);
        if (string.IsNullOrEmpty(hostname))
            return true;
        
        bool wasBlocking = socket.Blocking;
        
        SSLSocketState.EnterSslOperation();
        try
        {
            if (!wasBlocking)
                socket.Blocking = true;
            
            if (TryEstablishSslConnection(socket, hostname, out SslStream? sslStream))
            {
                // Success, now remove from pending and register
                SSLSocketState.GetAndRemovePendingSocket(socket);
                SSLSocketState.RegisterSslSocket(socket, sslStream!);
                return true;
            }
            else
            {
                // SSL handshake failed permanently, remove from pending
                SSLSocketState.GetAndRemovePendingSocket(socket);
                return false;
            }
        }
        catch (InvalidOperationException)
        {
            // Socket not ready yet, keep in pending, will retry on next Send/Receive
            return true;
        }
        catch (Exception ex)
        {
            // Remove from pending on other errors
            Logging.HookError(HookName, $"Late SSL setup failed: {ex.Message}");
            SSLSocketState.GetAndRemovePendingSocket(socket);
            return false;
        }
        finally
        {
            SSLSocketState.ExitSslOperation();
            if (!wasBlocking)
            {
                try { socket.Blocking = false; } catch { }
            }
        }
    }

    #endregion

    #region Socket.Send Hooks

    /// <summary>Prefix for Socket.Send(byte[], int, int, SocketFlags)</summary>
    private static bool SendOverloadBufferOffsetSizeFlags(Socket __instance, byte[] __0, int __1, int __2, ref int __result)
    {
        return SSLSendHelper.DoSend(__instance, __0, __1, __2, ref __result);
    }

    /// <summary>Prefix for Socket.Send(byte[], SocketFlags)</summary>
    private static bool SendOverloadBufferFlags(Socket __instance, byte[] __0, ref int __result)
    {
        return SSLSendHelper.DoSend(__instance, __0, 0, __0.Length, ref __result);
    }

    /// <summary>Prefix for Socket.Send(byte[])</summary>
    private static bool SendOverloadBuffer(Socket __instance, byte[] __0, ref int __result)
    {
        return SSLSendHelper.DoSend(__instance, __0, 0, __0.Length, ref __result);
    }

    /// <summary>Prefix for Socket.Send(byte[], int, int, SocketFlags, out SocketError)</summary>
    private static bool SendOverloadBufferOffsetSizeFlagsOutError(Socket __instance, byte[] __0, int __1, int __2, ref SocketError __4, ref int __result)
    {
        if (SSLSocketState.IsInsideSslOperation || !SSLSocketState.IsSslSocket(__instance))
            return true;
        
        bool handled = !SSLSendHelper.DoSend(__instance, __0, __1, __2, ref __result);
        if (handled)
        {
            __4 = __result > 0 ? SocketError.Success : SocketError.SocketError;
            return false;
        }
        return true;
    }

    #endregion

    #region Socket.Receive Hooks

    /// <summary>Prefix for Socket.Receive(byte[], int, int, SocketFlags)</summary>
    private static bool ReceiveOverloadBufferOffsetSizeFlags(Socket __instance, byte[] __0, int __1, int __2, ref int __result)
    {
        return SSLReceiveHelper.DoReceive(__instance, __0, __1, __2, ref __result);
    }

    /// <summary>Prefix for Socket.Receive(byte[], SocketFlags)</summary>
    private static bool ReceiveOverloadBufferFlags(Socket __instance, byte[] __0, ref int __result)
    {
        return SSLReceiveHelper.DoReceive(__instance, __0, 0, __0.Length, ref __result);
    }

    /// <summary>Prefix for Socket.Receive(byte[])</summary>
    private static bool ReceiveOverloadBuffer(Socket __instance, byte[] __0, ref int __result)
    {
        return SSLReceiveHelper.DoReceive(__instance, __0, 0, __0.Length, ref __result);
    }

    /// <summary>Prefix for Socket.Receive(byte[], int, int, SocketFlags, out SocketError)</summary>
    private static bool ReceiveOverloadBufferOffsetSizeFlagsOutError(Socket __instance, byte[] __0, int __1, int __2, ref SocketError __4, ref int __result)
    {
        if (SSLSocketState.IsInsideSslOperation || !SSLSocketState.IsSslSocket(__instance))
            return true;
        
        bool handled = !SSLReceiveHelper.DoReceive(__instance, __0, __1, __2, ref __result);
        if (handled)
        {
            __4 = __result >= 0 ? SocketError.Success : SocketError.SocketError;
            return false;
        }
        return true;
    }

    #endregion

    #region Socket.BeginSend/EndSend Async Hooks

    /// <summary>Prefix for Socket.BeginSend, performs synchronous SSL write and returns completed IAsyncResult</summary>
    private static bool BeginSendPrefix(Socket __instance, byte[] __0, int __1, int __2,
        SocketFlags __3, AsyncCallback __4, object __5, ref IAsyncResult __result)
    {
        if (SSLSocketState.IsInsideSslOperation)
            return true;
        
        // Try to establish SSL if this socket has a pending upgrade
        if (SSLSocketState.HasPendingSocket(__instance) && !SSLSocketState.IsSslSocket(__instance))
            TryEstablishSslForPendingSocket(__instance);
        
        var sslStream = SSLSocketState.GetSslStream(__instance);
        if (sslStream == null)
            return true;
        
        if (!sslStream.CanWrite)
        {
            SSLSocketState.RemoveSslSocket(__instance);
            __result = new CompletedAsyncResult(0, __5, new IOException("SSL stream closed"));
            __4?.Invoke(__result);
            return false;
        }
        
        object? socketLock = SSLSocketState.GetSocketLock(__instance);
        if (socketLock == null)
            return true;
        
        int bytesWritten = 0;
        Exception? error = null;
        
        try
        {
            lock (socketLock)
            {
                SSLSocketState.EnterSslOperation();
                try
                {
                    sslStream.Write(__0, __1, __2);
                    sslStream.Flush();
                    bytesWritten = __2;
                }
                finally
                {
                    SSLSocketState.ExitSslOperation();
                }
            }
        }
        catch (Exception ex)
        {
            error = ex;
            Logging.HookError(HookName, $"BeginSend SSL write failed: {ex.Message}");
            SSLSocketState.RemoveSslSocket(__instance);
        }
        
        __result = new CompletedAsyncResult(bytesWritten, __5, error);
        __4?.Invoke(__result);
        return false;
    }

    /// <summary>Prefix for Socket.EndSend, returns pre-computed result from CompletedAsyncResult</summary>
    private static bool EndSendPrefix(IAsyncResult __0, ref int __result)
    {
        if (__0 is CompletedAsyncResult completedResult)
        {
            if (completedResult.Error != null)
                throw completedResult.Error;
            __result = completedResult.BytesTransferred;
            return false;
        }
        return true;
    }

    #endregion

    #region Socket.BeginReceive/EndReceive Async Hooks

    /// <summary>Prefix for Socket.BeginReceive, performs synchronous SSL read and returns completed IAsyncResult</summary>
    private static bool BeginReceivePrefix(Socket __instance, byte[] __0, int __1, int __2,
        SocketFlags __3, AsyncCallback __4, object __5, ref IAsyncResult __result)
    {
        if (SSLSocketState.IsInsideSslOperation)
            return true;
        
        // Try to establish SSL if this socket has a pending upgrade
        if (SSLSocketState.HasPendingSocket(__instance) && !SSLSocketState.IsSslSocket(__instance))
            TryEstablishSslForPendingSocket(__instance);
        
        var sslStream = SSLSocketState.GetSslStream(__instance);
        if (sslStream == null)
            return true;
        
        if (!sslStream.CanRead)
        {
            SSLSocketState.RemoveSslSocket(__instance);
            __result = new CompletedAsyncResult(0, __5, new IOException("SSL stream closed"));
            __4?.Invoke(__result);
            return false;
        }
        
        object? socketLock = SSLSocketState.GetSocketLock(__instance);
        if (socketLock == null)
            return true;
        
        int bytesRead = 0;
        Exception? error = null;
        
        try
        {
            lock (socketLock)
            {
                SSLSocketState.EnterSslOperation();
                try
                {
                    bytesRead = sslStream.Read(__0, __1, __2);
                }
                finally
                {
                    SSLSocketState.ExitSslOperation();
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
            SSLSocketState.RemoveSslSocket(__instance);
        }
        
        __result = new CompletedAsyncResult(bytesRead, __5, error);
        __4?.Invoke(__result);
        return false;
    }

    /// <summary>Prefix for Socket.EndReceive, returns pre-computed result from CompletedAsyncResult</summary>
    private static bool EndReceivePrefix(IAsyncResult __0, ref int __result)
    {
        if (__0 is CompletedAsyncResult completedResult)
        {
            if (completedResult.Error != null)
                throw completedResult.Error;
            __result = completedResult.BytesTransferred;
            return false;
        }
        return true;
    }

    #endregion

    #region Socket Property/State Hooks

    private static bool AvailablePrefix(Socket __instance, ref int __result)
    {
        if (SSLSocketState.IsInsideSslOperation || !SSLSocketState.IsSslSocket(__instance))
            return true;
        
        SSLSocketState.EnterSslOperation();
        try
        {
            // Return 1 if encrypted data available, 0 otherwise
            __result = __instance.Available > 0 ? 1 : 0;
        }
        finally
        {
            SSLSocketState.ExitSslOperation();
        }
        
        return false;
    }

    private static bool PollPrefix(Socket __instance, int __0, SelectMode __1, ref bool __result)
    {
        if (SSLSocketState.IsInsideSslOperation || !SSLSocketState.IsSslSocket(__instance))
            return true;
        
        if (__1 != SelectMode.SelectRead)
            return true;
        
        SSLSocketState.EnterSslOperation();
        try
        {
            __result = __instance.Poll(__0, SelectMode.SelectRead);
        }
        finally
        {
            SSLSocketState.ExitSslOperation();
        }
        
        return false;
    }

    private static bool ShutdownPrefix(Socket __instance)
    {
        if (SSLSocketState.IsInsideSslOperation || !SSLSocketState.IsSslSocket(__instance))
            return true;
        
        // Block 'Shutdown' for SSL sockets, it corrupts the TLS state
        return false;
    }

    private static bool ClosePrefix(Socket __instance)
    {
        if (SSLSocketState.IsInsideSslOperation || !SSLSocketState.IsSslSocket(__instance))
            return true;
        
        // Block 'Close' for SSL sockets to allow pending reads
        return false;
    }

    #endregion
}

#region Helper Classes

/// <summary>
/// Shared SSL send implementation
/// </summary>
internal static class SSLSendHelper
{
    private const string HookName = "sh.Titanic.Hook.TcpHttpsUpgrade.Send";
    
    public static bool DoSend(Socket socket, byte[] buffer, int offset, int count, ref int result)
    {
        if (SSLSocketState.IsInsideSslOperation)
            return true;
        
        // Try to establish ssl if this socket has a pending upgrade
        if (SSLSocketState.HasPendingSocket(socket) && !SSLSocketState.IsSslSocket(socket))
            TcpHttpsUpgradeHook.TryEstablishSslForPendingSocket(socket);
        
        var sslStream = SSLSocketState.GetSslStream(socket);
        if (sslStream == null)
            return true;
        
        if (!sslStream.CanWrite)
        {
            SSLSocketState.RemoveSslSocket(socket);
            result = 0;
            return false;
        }
        
        var socketLock = SSLSocketState.GetSocketLock(socket);
        if (socketLock == null)
            return true;
        
        try
        {
            lock (socketLock)
            {
                SSLSocketState.EnterSslOperation();
                try
                {
                    sslStream.Write(buffer, offset, count);
                    sslStream.Flush();
                }
                finally
                {
                    SSLSocketState.ExitSslOperation();
                }
            }
            result = count;
            return false;
        }
        catch (ObjectDisposedException)
        {
            SSLSocketState.RemoveSslSocket(socket);
            result = 0;
            return false;
        }
        catch (Exception ex)
        {
            Logging.HookError(HookName, $"SSL Send failed: {ex.Message}");
            result = 0;
            return false;
        }
    }
}

/// <summary>
/// Shared SSL receive implementation
/// </summary>
internal static class SSLReceiveHelper
{
    private const string HookName = "sh.Titanic.Hook.TcpHttpsUpgrade.Receive";
    
    public static bool DoReceive(Socket socket, byte[] buffer, int offset, int count, ref int result)
    {
        if (SSLSocketState.IsInsideSslOperation)
            return true;
        
        // Try to establish SSL if this socket has a pending upgrade
        if (SSLSocketState.HasPendingSocket(socket) && !SSLSocketState.IsSslSocket(socket))
            TcpHttpsUpgradeHook.TryEstablishSslForPendingSocket(socket);
        
        var sslStream = SSLSocketState.GetSslStream(socket);
        if (sslStream == null)
            return true;
        
        if (!sslStream.CanRead)
        {
            SSLSocketState.RemoveSslSocket(socket);
            result = 0;
            return false;
        }
        
        var socketLock = SSLSocketState.GetSocketLock(socket);
        if (socketLock == null)
            return true;
        
        try
        {
            lock (socketLock)
            {
                // Check for data availability
                bool hasData;
                SSLSocketState.EnterSslOperation();
                try
                {
                    hasData = socket.Available > 0;
                }
                finally
                {
                    SSLSocketState.ExitSslOperation();
                }
                
                // Non-blocking mode with no data -> throw WouldBlock
                if (!socket.Blocking && !hasData)
                    throw new SocketException((int)SocketError.WouldBlock);
                
                // Force blocking mode for SSL read, TLS records may span packets
                bool wasBlocking = socket.Blocking;
                SSLSocketState.EnterSslOperation();
                try
                {
                    if (!wasBlocking)
                        socket.Blocking = true;
                    
                    result = sslStream.Read(buffer, offset, count);
                }
                finally
                {
                    if (!wasBlocking)
                        socket.Blocking = false;
                    SSLSocketState.ExitSslOperation();
                }
            }
            return false;
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.WouldBlock)
        {
            throw;
        }
        catch (IOException ioEx) when (ioEx.InnerException is SocketException { SocketErrorCode: SocketError.WouldBlock } sockEx)
        {
            throw sockEx;
        }
        catch (ObjectDisposedException)
        {
            SSLSocketState.RemoveSslSocket(socket);
            result = 0;
            return false;
        }
        catch (IOException ioEx)
        {
            Logging.HookError(HookName, $"SSL IO error: {ioEx.Message}");
            SSLSocketState.RemoveSslSocket(socket);
            result = 0;
            return false;
        }
        catch (Exception ex)
        {
            Logging.HookError(HookName, $"SSL Receive failed: {ex.Message}");
            result = 0;
            return false;
        }
    }
}

/// <summary>
/// SSL protocol helper
/// </summary>
internal static class SSLHelper
{
    public static bool ValidateServerCertificate(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors errors)
    {
        // TODO
        return true;
    }
    
    public static SslProtocols[] GetProtocolsToTry()
    {
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
}

/// <summary>
/// Tracks SSL socket state
/// </summary>
internal static class SSLSocketState
{
    private static readonly Dictionary<Socket, string> _pendingSockets = new();
    private static readonly Dictionary<Socket, SslStream> _sslSockets = new();
    private static readonly Dictionary<Socket, object> _socketLocks = new();
    
    [ThreadStatic]
    private static bool _insideSslOperation;
    
    public static bool IsInsideSslOperation => _insideSslOperation;
    
    public static void EnterSslOperation() => _insideSslOperation = true;
    public static void ExitSslOperation() => _insideSslOperation = false;
    
    public static void AddPendingSocket(Socket socket, string hostname)
    {
        lock (_pendingSockets)
        {
            _pendingSockets[socket] = hostname;
        }
    }
    
    public static bool HasPendingSocket(Socket socket)
    {
        lock (_pendingSockets)
        {
            return _pendingSockets.ContainsKey(socket);
        }
    }
    
    public static string? PeekPendingSocket(Socket socket)
    {
        lock (_pendingSockets)
        {
            return _pendingSockets.TryGetValue(socket, out string? hostname) ? hostname : null;
        }
    }
    
    public static string? GetAndRemovePendingSocket(Socket socket)
    {
        lock (_pendingSockets)
        {
            if (_pendingSockets.TryGetValue(socket, out string? hostname))
            {
                _pendingSockets.Remove(socket);
                return hostname;
            }
            return null;
        }
    }
    
    public static void RegisterSslSocket(Socket socket, SslStream sslStream)
    {
        lock (_sslSockets)
        {
            _sslSockets[socket] = sslStream;
            _socketLocks[socket] = new object();
        }
    }
    
    public static bool IsSslSocket(Socket socket)
    {
        lock (_sslSockets)
        {
            return _sslSockets.ContainsKey(socket);
        }
    }
    
    public static SslStream? GetSslStream(Socket socket)
    {
        lock (_sslSockets)
        {
            return _sslSockets.TryGetValue(socket, out SslStream? stream) ? stream : null;
        }
    }
    
    public static object? GetSocketLock(Socket socket)
    {
        lock (_sslSockets)
        {
            return _socketLocks.TryGetValue(socket, out object? lockObj) ? lockObj : null;
        }
    }
    
    public static void RemoveSslSocket(Socket socket)
    {
        lock (_sslSockets)
        {
            if (_sslSockets.ContainsKey(socket))
            {
                _sslSockets.Remove(socket);
                _socketLocks.Remove(socket);
            }
        }
    }
}

/// <summary>
/// IAsyncResult for completed async operations - allows us to return synchronous SSL results
/// through the async Socket API
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

#endregion
