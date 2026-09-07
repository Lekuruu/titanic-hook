// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Oreeeee

using System.Linq;
using System.Net;
using System.Reflection;
using System.Collections.Generic;
using Harmony;
using TitanicHook.Core.Framework;
using TitanicHook.Core.Helpers;

namespace TitanicHook.Core.Hooks.Connection;

public class DnsHostByNameHook : TitanicPatch
{
    public const string HookName = "sh.Titanic.Hook.DnsHostByName";

    /// <summary>
    /// Maps resolved IP addresses to their original hostnames
    /// </summary>
    private static readonly Dictionary<string, string> _ipToHostname = new();
    private static readonly object _lock = new();

    /// <summary>
    /// Resolves the original hostname for an IP address
    /// </summary>
    public static string? GetHostnameForIp(string ipAddress)
    {
        lock (_lock)
            return _ipToHostname.TryGetValue(ipAddress, out string? hostname) ? hostname : null;
    }

    /// <summary>
    /// Stores IP -> Hostname mapping after DNS resolution
    /// </summary>
    private static void RecordIpHostnameMapping(string ipAddress, string hostname)
    {
        lock (_lock)
        {
            _ipToHostname[ipAddress] = hostname;
        }
    }

    public DnsHostByNameHook() : base(HookName)
    {
        TargetMethods = [GetTargetMethod()];
        Prefixes = [AccessTools.Method(typeof(DnsHostByNameHook), nameof(InternalGetHostByNamePrefix))];
        Postfixes = [AccessTools.Method(typeof(DnsHostByNameHook), nameof(InternalGetHostByNamePostfix))];
    }

    private static MethodInfo GetTargetMethod()
    {
        return typeof(Dns)
            .GetMethods(BindingFlags.Static | BindingFlags.NonPublic)
            .FirstOrDefault(m => m.Name == "InternalGetHostByName" && m.GetParameters().Length == 2);
    }
    
    #region Hook

    private static void InternalGetHostByNamePrefix(ref string __0)
    {
        Logging.HookTrigger(HookName);
        
        if (__0.Contains("ppy.sh"))
            __0 = __0.Replace("ppy.sh", EntryPoint.Config.ServerName);
        else if (__0 == "peppy.chigau.com")
            __0 = __0.Replace("peppy.chigau.com", $"chigau.{EntryPoint.Config.ServerName}");
    }

    private static void InternalGetHostByNamePostfix(string __0, IPHostEntry __result)
    {
        if (__result == null || __0 == null)
            return;
        
        // Record IP -> Hostname mapping for all resolved addresses
        foreach (IPAddress addr in __result.AddressList)
        {
            string ip = addr.ToString();
            RecordIpHostnameMapping(ip, __0);
            Logging.Info($"[{HookName}] Set DNS mapping: {ip} -> {__0}");
        }
    }
    
    #endregion
}
