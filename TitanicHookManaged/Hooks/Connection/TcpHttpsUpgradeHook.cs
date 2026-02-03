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
        // Socket.Connect(EndPoint)
        PatchMethod("Connect", [typeof(EndPoint)],
            nameof(ConnectPrefix), nameof(ConnectPostfix));
        
        // Socket.Send(...) overloads
        PatchMethod("Send", [typeof(byte[]), typeof(int), typeof(int), typeof(SocketFlags)],
            nameof(SendOverloadBufferOffsetSizeFlags));
        PatchMethod("Send", [typeof(byte[]), typeof(SocketFlags)],
            nameof(SendOverloadBufferFlags));
        PatchMethod("Send", [typeof(byte[])],
            nameof(SendOverloadBuffer));
        PatchMethod("Send", [typeof(byte[]), typeof(int), typeof(int), typeof(SocketFlags), typeof(SocketError).MakeByRefType()],
            nameof(SendOverloadBufferOffsetSizeFlagsOutError));
        
        // Socket.Receive(...) overloads
        PatchMethod("Receive", [typeof(byte[]), typeof(int), typeof(int), typeof(SocketFlags)],
            nameof(ReceiveOverloadBufferOffsetSizeFlags));
        PatchMethod("Receive", [typeof(byte[]), typeof(SocketFlags)],
            nameof(ReceiveOverloadBufferFlags));
        PatchMethod("Receive", [typeof(byte[])],
            nameof(ReceiveOverloadBuffer));
        PatchMethod("Receive", [typeof(byte[]), typeof(int), typeof(int), typeof(SocketFlags), typeof(SocketError).MakeByRefType()],
            nameof(ReceiveOverloadBufferOffsetSizeFlagsOutError));
        
        // Properties and state
        PatchPropertyGetter("Available", nameof(AvailablePrefix));
        PatchMethod("Poll", [typeof(int), typeof(SelectMode)],
            nameof(PollPrefix));
        PatchMethod("Shutdown", [typeof(SocketShutdown)],
            nameof(ShutdownPrefix));
        PatchMethod("Close", [],
            nameof(ClosePrefix));
    }

    private void PatchMethod(string methodName, Type[] paramTypes, string prefixName, string? postfixName = null)
    {
        var method = typeof(Socket).GetMethod(methodName, BindingFlags.Instance | BindingFlags.Public, null, paramTypes, null);
        if (method == null)
        {
            string[] typeNames = paramTypes.Select(t => t.Name).ToArray();
            Logging.HookError(HookName, $"Could not find Socket.{methodName}({string.Join(", ", typeNames)})");
            return;
        }
        
        MethodInfo prefix = AccessTools.Method(typeof(TcpHttpsUpgradeHook), prefixName);
        MethodInfo? postfix = postfixName != null ? AccessTools.Method(typeof(TcpHttpsUpgradeHook), postfixName) : null;
        
        try
        {
            Harmony.Patch(method,
                prefix != null ? new HarmonyMethod(prefix) : null,
                postfix != null ? new HarmonyMethod(postfix) : null);
            Logging.Info($"[{HookName}] Patched Socket.{methodName}");
        }
        catch (Exception ex)
        {
            Logging.HookError(HookName, $"Failed to patch Socket.{methodName}: {ex.Message}");
        }
    }

    private void PatchPropertyGetter(string propertyName, string prefixName)
    {
        var method = typeof(Socket).GetProperty(propertyName, BindingFlags.Instance | BindingFlags.Public)?.GetGetMethod();
        if (method == null)
        {
            Logging.HookError(HookName, $"Could not find Socket.{propertyName} getter");
            return;
        }
        
        var prefix = AccessTools.Method(typeof(TcpHttpsUpgradeHook), prefixName);
        
        try
        {
            Harmony.Patch(method, new HarmonyMethod(prefix));
            Logging.Info($"[{HookName}] Patched Socket.{propertyName}");
        }
        catch (Exception ex)
        {
            Logging.HookError(HookName, $"Failed to patch Socket.{propertyName}: {ex.Message}");
        }
    }

    #region Socket.Connect Hooks

    private static void ConnectPrefix(Socket __instance, ref EndPoint __0)
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

    private static void ConnectPostfix(Socket __instance)
    {
        string? hostname = SSLSocketState.GetAndRemovePendingSocket(__instance);
        if (hostname == null)
            return;
        
        // Verify socket is actually connected before attempting SSL
        if (!__instance.Connected)
        {
            Logging.Warning($"Socket not connected after Connect(), skipping SSL for {hostname}");
            return;
        }
        
        bool wasBlocking = __instance.Blocking;
        
        try
        {
            if (!wasBlocking)
                __instance.Blocking = true;
            
            if (TryEstablishSslConnection(__instance, hostname, out SslStream? sslStream))
            {
                SSLSocketState.RegisterSslSocket(__instance, sslStream!);
                return;
            }
        }
        catch (Exception ex)
        {
            Logging.HookError(HookName, $"SSL connection failed: {ex.Message}");
        }
        finally
        {
            // Restore original blocking mode
            if (!wasBlocking)
            {
                try { __instance.Blocking = false; } catch { }
            }
        }
    }

    private static bool TryEstablishSslConnection(Socket socket, string hostname, out SslStream? sslStream)
    {
        NetworkStream? networkStream = null;
        Exception? lastException = null;
        sslStream = null;

        foreach (var protocol in SSLHelper.GetProtocolsToTry())
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
        
        Logging.HookError(HookName, $"SSL handshake failed: {lastException?.Message}");
        
        networkStream?.Dispose();
        sslStream?.Dispose();
        sslStream = null;
        return false;
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
        
        SslStream? sslStream = SSLSocketState.GetSslStream(socket);
        if (sslStream == null)
            return true;
        
        if (!sslStream.CanWrite)
        {
            SSLSocketState.RemoveSslSocket(socket);
            result = 0;
            return false;
        }
        
        object? socketLock = SSLSocketState.GetSocketLock(socket);
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
        
        SslStream? sslStream = SSLSocketState.GetSslStream(socket);
        if (sslStream == null)
            return true;
        
        if (!sslStream.CanRead)
        {
            SSLSocketState.RemoveSslSocket(socket);
            result = 0;
            return false;
        }
        
        object? socketLock = SSLSocketState.GetSocketLock(socket);
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
            if (_sslSockets.TryGetValue(socket, out SslStream? stream))
            {
                _sslSockets.Remove(socket);
                _socketLocks.Remove(socket);
            }
        }
    }
}

#endregion
