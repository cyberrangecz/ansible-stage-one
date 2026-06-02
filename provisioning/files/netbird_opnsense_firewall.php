<?php

/*
 * Idempotently wire the NetBird tunnel (wt0) into the OPNsense firewall.
 *
 * Usage:  php netbird_opnsense_firewall.php <device> <descr> <source_net> <marker>
 *   device      tunnel device, e.g. wt0
 *   descr       interface description, e.g. NETBIRD
 *   source_net  rule source, e.g. "any" or "100.66.0.0/16"
 *   marker      rule description, used as the idempotency key
 *
 * Prints "changed <ifid>" or "unchanged <ifid>" and exits 0 on success.
 */

require_once("config.inc");
require_once("interfaces.inc");
require_once("util.inc");
require_once("system.inc");

use OPNsense\Core\Config;
use OPNsense\Firewall\Filter;

if ($argc < 5) {
    fwrite(STDERR, "usage: {$argv[0]} <device> <descr> <source_net> <marker>\n");
    exit(2);
}
list(, $device, $descr, $source_net, $marker) = $argv;

global $config;
$changed = false;

/* 1) Assign the tunnel device as an interface if it isn't already. */
$ifid = null;
foreach (($config['interfaces'] ?? []) as $id => $ifcfg) {
    if (($ifcfg['if'] ?? '') === $device) {
        $ifid = $id;
        break;
    }
}
if ($ifid === null) {
    $maxopt = 0;
    foreach (array_keys($config['interfaces'] ?? []) as $id) {
        if (preg_match('/^opt(\d+)$/', $id, $m)) {
            $maxopt = max($maxopt, (int)$m[1]);
        }
    }
    $ifid = 'opt' . ($maxopt + 1);
    $config['interfaces'][$ifid] = [
        'if' => $device,
        'descr' => $descr,
        'enable' => '1',
        'ipaddr' => 'none',
        'ipaddrv6' => 'none',
    ];
    write_config("netbird: assign {$device} as {$ifid}");
    $changed = true;
}

/*
 * 2) Converge the pass rule (MVC firewall), keyed by our description marker.
 *
 * Stateful, inbound-only, first-match:
 *   direction=in  -> only filters packets entering the host on wt0.
 *   quick=1       -> first match wins; stop evaluating further rules.
 *   statetype=keep-> create a (floating) state entry on the admitted flow.
 * Because the state matches the flow in both directions, replies and
 * routed return traffic pass automatically.
 */
$filter = new Filter();
$rule = null;
foreach ($filter->rules->rule->iterateItems() as $r) {
    if ((string)$r->description === $marker) {
        $rule = $r;
        break;
    }
}

$fields = [
    'enabled' => '1',
    'action' => 'pass',
    'direction' => 'in',
    'quick' => '1',
    'statetype' => 'keep',
    'interface' => $ifid,
    'ipprotocol' => 'inet',
    'protocol' => 'any',
    'source_net' => $source_net,
    'destination_net' => 'any',
    'description' => $marker,
];

$rule_changed = false;
if ($rule === null) {
    $rule = $filter->rules->rule->add();
    foreach ($fields as $k => $v) {
        $rule->$k = $v;
    }
    $rule_changed = true;
} else {
    /*
     * Reconcile only the fields that legitimately drift on a re-run and whose
     * stored value round-trips reliably (a changed source_net, or wt0
     * reassigned to a different optN). Comparing OPNsense-normalized fields
     * such as protocol='any' would risk a perpetual "changed" and needless
     * filter reloads / tunnel restarts.
     */
    foreach (['enabled', 'interface', 'source_net'] as $k) {
        if ((string)$rule->$k !== (string)$fields[$k]) {
            $rule->$k = $fields[$k];
            $rule_changed = true;
        }
    }
}
if ($rule_changed) {
    $filter->serializeToConfig();
    Config::getInstance()->save();
    $changed = true;
}

echo ($changed ? 'changed ' : 'unchanged ') . $ifid . "\n";
exit(0);
