// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Oreeeee

using System.Linq;
using System.Net;
using System.Reflection;
using System.Collections.Generic;
using Harmony;
using TitanicHookManaged.Framework;
using TitanicHookManaged.Helpers;

namespace TitanicHookManaged.Hooks.Connection;

public class DnsHostByNameHook : TitanicPatch
{
    public const string HookName = "sh.Titanic.Hook.DnsHostByName";

    /// <summary>
    /// Maps resolved IP addresses to their original hostnames
    /// </summary>
    private static readonly Dictionary<string, string> _ipToHostname = new Dictionary<string, string>();
    private static readonly object _lock = new object();

    /// <summary>
    /// Resolves the original hostname for an IP address
    /// </summary>
    public static string? GetHostnameForIp(string ipAddress)
    {
        lock (_lock)
        {
            if (_ipToHostname.TryGetValue(ipAddress, out string? hostname))
                return hostname;
            return null;
        }
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

    // Store the hostname being resolved (before potential modification)
    [System.ThreadStatic]
    private static string? _currentHostname;

    private static void InternalGetHostByNamePrefix(ref string __0)
    {
        Logging.HookTrigger(HookName);
        
        // Store the original hostname for the postfix
        _currentHostname = __0;
        
        if (__0.Contains("ppy.sh"))
        {
            __0 = __0.Replace("ppy.sh", EntryPoint.Config.ServerName);
            _currentHostname = __0; // Update to the modified hostname
        }
        else if (__0 == "peppy.chigau.com")
        {
            __0 = __0.Replace("peppy.chigau.com", $"chigau.{EntryPoint.Config.ServerName}");
            _currentHostname = __0;
        }
    }

    private static void InternalGetHostByNamePostfix(IPHostEntry __result)
    {
        if (__result == null || _currentHostname == null)
            return;
        
        // Record IP -> Hostname mapping for all resolved addresses
        foreach (IPAddress addr in __result.AddressList)
        {
            string ip = addr.ToString();
            RecordIpHostnameMapping(ip, _currentHostname);
            Logging.Info($"[{HookName}] Set DNS mapping: {ip} -> {_currentHostname}");
        }
    }
    
    #endregion
}
