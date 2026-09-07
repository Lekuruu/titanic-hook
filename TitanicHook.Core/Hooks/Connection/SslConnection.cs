// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Oreeeee

using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using TitanicHook.Core.Helpers;

namespace TitanicHook.Core.Hooks.Connection;

internal enum SslConnectionStatus
{
    Pending,
    Established,
    Failed
}

/// <summary>
/// SSL connection state and I/O for an upgraded socket
/// </summary>
internal sealed class SslConnection(Socket socket, string hostname)
{
    private const string HookName = TcpHttpsUpgradeHook.HookName;
    private readonly object _syncRoot = new();
    private volatile SslConnectionStatus _status;
    private SslStream? _stream;

    public bool IsEstablished => _status == SslConnectionStatus.Established;

    public SslConnectionStatus Establish(string operation)
    {
        lock (_syncRoot)
        {
            if (_status != SslConnectionStatus.Pending)
                return _status;

            try
            {
                if (!socket.Connected)
                    return SslConnectionStatus.Pending;

                using (SslOperation.EnterBlocking(socket))
                {
                    if (TryAuthenticate(out _stream))
                    {
                        _status = SslConnectionStatus.Established;
                        return _status;
                    }
                }
            }
            catch (InvalidOperationException)
            {
                // Socket not ready yet, retry later
                return SslConnectionStatus.Pending;
            }
            catch (Exception ex)
            {
                Logging.HookError(HookName, $"SSL connection failed ({operation}): {ex.Message}");
            }

            Remove();
            return _status;
        }
    }

    private bool TryAuthenticate(out SslStream? stream)
    {
        NetworkStream? networkStream = null;
        Exception? lastException = null;
        stream = null;

        foreach (var protocol in ProtocolsToTry)
        {
            try
            {
                networkStream?.Dispose();
                stream?.Dispose();
                networkStream = new NetworkStream(socket, ownsSocket: false);
                stream = new SslStream(networkStream, leaveInnerStreamOpen: true, ValidateServerCertificate);
                stream.AuthenticateAsClient(hostname, null, protocol, false);

                if (!stream.IsAuthenticated)
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
        stream?.Dispose();
        stream = null;
        return false;
    }

    // Define TLS 1.1 / 1.2 for .NET 2.0 compatibility
    private const SslProtocols Tls12 = (SslProtocols)3072;
    private const SslProtocols Tls11 = (SslProtocols)768;

    // SSL protocols to try in order of preference
    private static readonly SslProtocols[] ProtocolsToTry =
    [
        Tls12 | Tls11 | SslProtocols.Tls,
        Tls12,
        Tls11,
        SslProtocols.Tls,
        SslProtocols.Default
    ];

    private static bool ValidateServerCertificate(object sender, X509Certificate? certificate,
        X509Chain? chain, SslPolicyErrors errors) => true;

    public int Send(byte[] buffer, int offset, int count)
    {
        lock (_syncRoot)
        {
            if (_stream?.CanWrite != true)
            {
                Remove();
                return 0;
            }

            try
            {
                return Write(buffer, offset, count);
            }
            catch (ObjectDisposedException)
            {
                Remove();
            }
            catch (Exception ex)
            {
                Logging.HookError(HookName, $"SSL Send failed: {ex.Message}");
            }
            return 0;
        }
    }

    public int Receive(byte[] buffer, int offset, int count)
    {
        lock (_syncRoot)
        {
            if (_stream?.CanRead != true)
            {
                Remove();
                return 0;
            }

            try
            {
                using (SslOperation.Enter())
                {
                    if (!socket.Blocking && socket.Available == 0)
                        throw new SocketException((int)SocketError.WouldBlock);

                    using (SslOperation.EnterBlocking(socket))
                        return _stream.Read(buffer, offset, count);
                }
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.WouldBlock)
            {
                throw;
            }
            catch (IOException ex) when (ex.InnerException is SocketException { SocketErrorCode: SocketError.WouldBlock } socketError)
            {
                throw socketError;
            }
            catch (ObjectDisposedException)
            {
                Remove();
            }
            catch (IOException ex)
            {
                Logging.Error($"SSL IO error: {ex.Message}");
                Remove();
            }
            catch (Exception ex)
            {
                Logging.Error($"SSL Receive failed: {ex.Message}");
            }
            return 0;
        }
    }

    public CompletedAsyncResult SendCompleted(byte[] buffer, int offset, int count, object? state)
    {
        lock (_syncRoot)
        {
            if (_stream?.CanWrite != true)
            {
                Remove();
                return new CompletedAsyncResult(0, state, new IOException("SSL stream closed"));
            }

            try
            {
                return new CompletedAsyncResult(Write(buffer, offset, count), state);
            }
            catch (ObjectDisposedException)
            {
                Remove();
            }
            catch (IOException)
            {
                Remove();
            }
            catch (Exception ex)
            {
                Logging.HookError(HookName, $"BeginSend SSL write failed: {ex.Message}");
                Remove();
                return new CompletedAsyncResult(0, state, ex);
            }
            return new CompletedAsyncResult(0, state);
        }
    }

    public CompletedAsyncResult ReceiveCompleted(byte[] buffer, int offset, int count, object? state)
    {
        lock (_syncRoot)
        {
            if (_stream?.CanRead != true)
            {
                Remove();
                return new CompletedAsyncResult(0, state, new IOException("SSL stream closed"));
            }

            try
            {
                using (SslOperation.Enter())
                    return new CompletedAsyncResult(_stream.Read(buffer, offset, count), state);
            }
            catch (IOException ex) when (ex.InnerException is SocketException { SocketErrorCode: SocketError.WouldBlock })
            {
                return new CompletedAsyncResult(0, state);
            }
            catch (Exception ex)
            {
                Logging.HookError(HookName, $"BeginReceive SSL read failed: {ex.Message}");
                Remove();
                return new CompletedAsyncResult(0, state, ex);
            }
        }
    }

    private int Write(byte[] buffer, int offset, int count)
    {
        using (SslOperation.Enter())
        {
            _stream!.Write(buffer, offset, count);
            _stream.Flush();
            return count;
        }
    }

    private void Remove()
    {
        _status = SslConnectionStatus.Failed;
        SslSocketState.Remove(socket, this);
    }
}

internal static class SslSocketState
{
    private static readonly Dictionary<Socket, SslConnection> Connections = new();
    private static readonly object SyncRoot = new();

    public static void Track(Socket socket, string hostname)
    {
        lock (SyncRoot)
        {
            // Keep the SSL stream if another Connect call fails
            if (Connections.TryGetValue(socket, out var connection) && connection.IsEstablished)
                return;

            Connections[socket] = new SslConnection(socket, hostname);
        }
    }

    public static SslConnection? GetConnection(Socket socket)
    {
        if (SslOperation.IsActive)
            return null;

        lock (SyncRoot)
            return Connections.TryGetValue(socket, out var connection) ? connection : null;
    }

    public static SslConnection? GetForIo(Socket socket)
    {
        var connection = GetConnection(socket);
        return connection?.Establish("deferred I/O") == SslConnectionStatus.Established ? connection : null;
    }

    public static void Remove(Socket socket, SslConnection connection)
    {
        lock (SyncRoot)
        {
            if (Connections.TryGetValue(socket, out var current) && ReferenceEquals(current, connection))
                Connections.Remove(socket);
        }
    }
}

/// <summary>
/// Prevents socket hooks from being called recursively during SSL operations
/// </summary>
internal readonly struct SslOperation : IDisposable
{
    [ThreadStatic]
    private static int _depth;

    private readonly Socket? _socket;
    private readonly bool _wasBlocking;

    public static bool IsActive => _depth != 0;
    public static SslOperation Enter() => new(null);
    public static SslOperation EnterBlocking(Socket socket) => new(socket);

    private SslOperation(Socket? socket)
    {
        _socket = socket;
        _wasBlocking = socket?.Blocking ?? true;
        if (!_wasBlocking)
            socket!.Blocking = true;
        _depth++;
    }

    public void Dispose()
    {
        try
        {
            if (!_wasBlocking)
            {
                try { _socket!.Blocking = false; }
                catch (ObjectDisposedException) { }
                catch (SocketException) { }
            }
        }
        finally
        {
            _depth--;
        }
    }
}

/// <summary>
/// IAsyncResult implementation for completed SSL operations
/// </summary>
internal sealed class CompletedAsyncResult(int bytesTransferred, object? state, Exception? error = null) : IAsyncResult
{
    public int BytesTransferred { get; } = bytesTransferred;
    public Exception? Error { get; } = error;
    public object? AsyncState { get; } = state;
    public WaitHandle AsyncWaitHandle { get; } = new ManualResetEvent(true);
    public bool CompletedSynchronously => true;
    public bool IsCompleted => true;
}
