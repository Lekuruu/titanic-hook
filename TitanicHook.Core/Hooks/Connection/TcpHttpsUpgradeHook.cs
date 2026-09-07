// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Oreeeee

using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using Harmony;
using TitanicHook.Core.Framework;
using TitanicHook.Core.Helpers;

// ReSharper disable InconsistentNaming
namespace TitanicHook.Core.Hooks.Connection;

/// <summary>
/// Hook for upgrading raw HTTP connections to HTTPS
/// </summary>
public class TcpHttpsUpgradeHook() : TitanicPatch(HookName)
{
    public const string HookName = "sh.Titanic.Hook.TcpHttpsUpgrade";

    public override void Patch()
    {
        PatchSocketMethod("Connect", [typeof(EndPoint)],
            nameof(ConnectEndPointPrefix), nameof(ConnectPostfix));
        PatchSocketMethod("Connect", [typeof(IPAddress), typeof(int)],
            nameof(ConnectIpAddressPortPrefix), nameof(ConnectPostfix));
        PatchSocketMethod("Connect", [typeof(IPAddress[]), typeof(int)],
            nameof(ConnectIpAddressArrayPortPrefix), nameof(ConnectPostfix));
        PatchSocketMethod("Connect", [typeof(string), typeof(int)],
            nameof(ConnectHostPortPrefix), nameof(ConnectPostfix));

        PatchSocketMethod("BeginConnect", [typeof(EndPoint), typeof(AsyncCallback), typeof(object)],
            nameof(ConnectEndPointPrefix));
        PatchSocketMethod("BeginConnect", [typeof(IPAddress), typeof(int), typeof(AsyncCallback), typeof(object)],
            nameof(ConnectIpAddressPortPrefix));
        PatchSocketMethod("BeginConnect", [typeof(IPAddress[]), typeof(int), typeof(AsyncCallback), typeof(object)],
            nameof(ConnectIpAddressArrayPortPrefix));
        PatchSocketMethod("BeginConnect", [typeof(string), typeof(int), typeof(AsyncCallback), typeof(object)],
            nameof(ConnectHostPortPrefix));
        PatchSocketMethod("EndConnect", [typeof(IAsyncResult)], postfixName: nameof(ConnectPostfix));

        PatchSocketMethod("Send", [typeof(byte[]), typeof(int), typeof(int), typeof(SocketFlags)],
            nameof(SendPrefix));
        PatchSocketMethod("Send", [typeof(byte[]), typeof(SocketFlags)], nameof(SendBufferPrefix));
        PatchSocketMethod("Send", [typeof(byte[])], nameof(SendBufferPrefix));
        PatchSocketMethod("Send", [typeof(byte[]), typeof(int), typeof(int), typeof(SocketFlags), typeof(SocketError).MakeByRefType()],
            nameof(SendWithErrorPrefix));
        PatchSocketMethod("BeginSend", [typeof(byte[]), typeof(int), typeof(int), typeof(SocketFlags), typeof(AsyncCallback), typeof(object)],
            nameof(BeginSendPrefix));
        PatchSocketMethod("EndSend", [typeof(IAsyncResult)], nameof(EndTransferPrefix));

        PatchSocketMethod("Receive", [typeof(byte[]), typeof(int), typeof(int), typeof(SocketFlags)],
            nameof(ReceivePrefix));
        PatchSocketMethod("Receive", [typeof(byte[]), typeof(SocketFlags)], nameof(ReceiveBufferPrefix));
        PatchSocketMethod("Receive", [typeof(byte[])], nameof(ReceiveBufferPrefix));
        PatchSocketMethod("Receive", [typeof(byte[]), typeof(int), typeof(int), typeof(SocketFlags), typeof(SocketError).MakeByRefType()],
            nameof(ReceiveWithErrorPrefix));
        PatchSocketMethod("BeginReceive", [typeof(byte[]), typeof(int), typeof(int), typeof(SocketFlags), typeof(AsyncCallback), typeof(object)],
            nameof(BeginReceivePrefix));
        PatchSocketMethod("EndReceive", [typeof(IAsyncResult)], nameof(EndTransferPrefix));

        PatchSocketMember(typeof(Socket).GetProperty("Available")?.GetGetMethod(),
            "Available getter", nameof(AvailablePrefix));
        PatchSocketMethod("Poll", [typeof(int), typeof(SelectMode)], nameof(PollPrefix));
        PatchSocketMethod("Shutdown", [typeof(SocketShutdown)], nameof(KeepSslSocketOpenPrefix));
        PatchSocketMethod("Close", [], nameof(KeepSslSocketOpenPrefix));
    }

    private void PatchSocketMethod(string methodName, Type[] paramTypes, string? prefixName = null, string? postfixName = null)
    {
        var method = typeof(Socket).GetMethod(methodName, BindingFlags.Instance | BindingFlags.Public, null, paramTypes, null);
        string signature = $"{methodName}({string.Join(", ", paramTypes.Select(t => t.Name).ToArray())})";
        PatchSocketMember(method, signature, prefixName, postfixName);
    }

    private void PatchSocketMember(MethodInfo? method, string description, string? prefixName = null, string? postfixName = null)
    {
        try
        {
            if (method == null)
                throw new MissingMethodException($"Could not find Socket.{description}");

            Harmony.Patch(method, GetPatchMethod(prefixName), GetPatchMethod(postfixName));
        }
        catch (Exception ex)
        {
            HandleError($"Failed to patch Socket.{description}: {ex.Message}");
        }
    }

    private static HarmonyMethod? GetPatchMethod(string? name)
    {
        if (name == null)
            return null;

        var method = AccessTools.Method(typeof(TcpHttpsUpgradeHook), name);
        if (method == null)
            throw new MissingMethodException(typeof(TcpHttpsUpgradeHook).FullName, name);
        return new HarmonyMethod(method);
    }

    private static void ConnectEndPointPrefix(Socket __instance, ref EndPoint __0)
    {
        if (__0 is not IPEndPoint endpoint || endpoint.Port != 80)
            return;

        __0 = new IPEndPoint(endpoint.Address, 443);
        TrackUpgrade(__instance, endpoint.Address.ToString());
    }

    private static void ConnectIpAddressPortPrefix(Socket __instance, IPAddress __0, ref int __1)
    {
        if (__1 != 80)
            return;

        __1 = 443;
        TrackUpgrade(__instance, __0.ToString());
    }

    private static void ConnectIpAddressArrayPortPrefix(Socket __instance, IPAddress[] __0, ref int __1)
    {
        if (__1 != 80 || __0.Length == 0)
            return;

        __1 = 443;
        TrackUpgrade(__instance, __0[0].ToString());
    }

    private static void ConnectHostPortPrefix(Socket __instance, string __0, ref int __1)
    {
        if (__1 != 80)
            return;

        __1 = 443;
        TrackUpgrade(__instance, __0, resolveHostname: false);
    }

    private static void TrackUpgrade(Socket socket, string address, bool resolveHostname = true)
    {
        Logging.HookTrigger(HookName);
        Logging.HookOutput(HookName, $"Upgrading {address}:80 -> :443");
        string hostname = resolveHostname ? DnsHostByNameHook.GetHostnameForIp(address) ?? address : address;
        SslSocketState.Track(socket, hostname);
    }

    private static void ConnectPostfix(Socket __instance, MethodBase __originalMethod) =>
        SslSocketState.GetConnection(__instance)?.Establish(__originalMethod.Name);

    private static bool SendPrefix(Socket __instance, byte[] __0, int __1, int __2, ref int __result)
    {
        var connection = SslSocketState.GetForIo(__instance);
        if (connection == null)
            return true;

        __result = connection.Send(__0, __1, __2);
        return false;
    }

    private static bool SendBufferPrefix(Socket __instance, byte[] __0, ref int __result) =>
        SendPrefix(__instance, __0, 0, __0.Length, ref __result);

    private static bool SendWithErrorPrefix(Socket __instance, byte[] __0, int __1, int __2, ref SocketError __4, ref int __result)
    {
        var connection = SslSocketState.GetConnection(__instance);
        if (connection?.IsEstablished != true)
            return true;

        __result = connection.Send(__0, __1, __2);
        __4 = __result > 0 ? SocketError.Success : SocketError.SocketError;
        return false;
    }

    private static bool ReceivePrefix(Socket __instance, byte[] __0, int __1, int __2, ref int __result)
    {
        var connection = SslSocketState.GetForIo(__instance);
        if (connection == null)
            return true;

        __result = connection.Receive(__0, __1, __2);
        return false;
    }

    private static bool ReceiveBufferPrefix(Socket __instance, byte[] __0, ref int __result) =>
        ReceivePrefix(__instance, __0, 0, __0.Length, ref __result);

    private static bool ReceiveWithErrorPrefix(Socket __instance, byte[] __0, int __1, int __2, ref SocketError __4, ref int __result)
    {
        var connection = SslSocketState.GetConnection(__instance);
        if (connection?.IsEstablished != true)
            return true;

        __result = connection.Receive(__0, __1, __2);
        __4 = __result >= 0 ? SocketError.Success : SocketError.SocketError;
        return false;
    }

    private static bool BeginSendPrefix(Socket __instance, byte[] __0, int __1, int __2,
        AsyncCallback? __4, object? __5, ref IAsyncResult __result)
    {
        var connection = SslSocketState.GetForIo(__instance);
        if (connection == null)
            return true;

        __result = connection.SendCompleted(__0, __1, __2, __5);
        __4?.Invoke(__result);
        return false;
    }

    private static bool BeginReceivePrefix(Socket __instance, byte[] __0, int __1, int __2,
        AsyncCallback? __4, object? __5, ref IAsyncResult __result)
    {
        var connection = SslSocketState.GetForIo(__instance);
        if (connection == null)
            return true;

        __result = connection.ReceiveCompleted(__0, __1, __2, __5);
        __4?.Invoke(__result);
        return false;
    }

    private static bool EndTransferPrefix(IAsyncResult __0, ref int __result)
    {
        if (__0 is not CompletedAsyncResult completed)
            return true;

        if (completed.Error != null)
            throw completed.Error;

        __result = completed.BytesTransferred;
        return false;
    }

    private static bool AvailablePrefix(Socket __instance, ref int __result)
    {
        if (SslSocketState.GetConnection(__instance)?.IsEstablished != true)
            return true;

        using (SslOperation.Enter())
            __result = __instance.Available > 0 ? 1 : 0;
        return false;
    }

    private static bool PollPrefix(Socket __instance, int __0, SelectMode __1, ref bool __result)
    {
        if (__1 != SelectMode.SelectRead || SslSocketState.GetConnection(__instance)?.IsEstablished != true)
            return true;

        using (SslOperation.Enter())
            __result = __instance.Poll(__0, SelectMode.SelectRead);
        return false;
    }

    // Block Close & Shutdown for SSL sockets to allow pending reads
    private static bool KeepSslSocketOpenPrefix(Socket __instance) =>
        SslSocketState.GetConnection(__instance)?.IsEstablished != true;
}
