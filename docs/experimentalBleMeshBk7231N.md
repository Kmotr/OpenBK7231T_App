# Experimental BK7231N BLE command relay

This fork contains an experimental, OpenBeken-only BLE advertisement relay for BK7231N. It is **not Bluetooth SIG Mesh** and is not interoperable with SIG Mesh controllers, nodes, or provisioning tools. Do not describe it as a production-ready Bluetooth Mesh implementation.

The implementation uses the BK7231N BLE 5.x advertising/scanning APIs already present in the OpenBeken SDK. It does not use the missing Beken BLE 4.2 Mesh library. This avoids initializing two BLE stacks, but it also means there are no SIG Mesh models, friendship, managed flooding, standard provisioning, or SIG Mesh device keys.

## Current scope

- Node IDs 1 through 254; target 0 is broadcast to all configured nodes.
- Power, dimmer, RGB, RGBCW, and color-temperature set values.
- MQTT-connected spots may all inject recognized cmnd/ updates. There is no exclusive gateway election.
- Relays rebroadcast a bounded BLE advertisement, decrement TTL, reject previously seen sender sequence numbers, and suppress identical operation/target/payload relays for three seconds.
- Per-operation state ordering prefers synchronized timestamps, then sender ID and sequence. A locally received MQTT update is protected from older BLE updates; when time is unsynchronized, a five-second local hold is used.
- The BLE Mesh configuration page is linked from Config → Configure BLE Mesh. Configure one unique node ID per spot and the same 128-bit hexadecimal key on all spots. The key is retained in OpenBeken configuration storage across reboot.
- Console commands: BLEMesh key <32-hex-chars>, BLEMesh node <1-254>, BLEMesh start, and BLEMesh send <0-254> <power|dimmer|rgbcw|rgb|temperature> <values...>.

The existing Wi-Fi/MQTT path remains active. BP1658CJ output and its pin roles are not replaced by the BLE relay; received BLE values are applied through the existing OpenBeken LED commands.

## Code map

- `src/hal/bk7231/hal_ble_mesh_bk7231n.c` implements the experimental advertisement frame, authentication tag, node/sequence tracking, state ordering, relay limits, MQTT bridge, CLI, and Web configuration.
- `src/hal/bk7231/hal_ble_mesh_bk7231n.h` exposes the HAL entry points.
- `platforms/BK723x/OpenBeken.mk` includes the implementation only in the BK7231N build and enables its compile-time feature flag.
- `src/mqtt/new_mqtt.c`, `src/hal/bk7231/hal_bt_proxy_bk7231.c`, `src/user_main.c`, and `src/httpserver/http_fns.c` connect MQTT, BLE advertisements, initialization, and the Config menu.
## Security and deployment limits

The custom frame carries a SipHash-2-4 authentication tag using the shared 128-bit key. It provides message authentication, **not encryption**: payloads are observable over the air. This is not SIG Mesh security, and key setup is not an authenticated out-of-band provisioning protocol. The Web UI submits the key over the device HTTP interface, so configure devices only on a trusted network. The key is stored in the existing OpenBeken configuration structure; storage encryption has not been established.

This relay is intended for bench evaluation only. Do not rely on it for safety or security functions. No on-device RF range, packet-loss, latency, power, RAM, or optical synchronization measurements are available. Group changes are not frame-synchronous. A BLE proxy remains a separate feature and is not a Mesh controller.

If every spot and every separate controller loses its connection to MQTT or the control station, a Home Assistant MQTT command cannot enter the network. A separate reachable controller is required for control in that condition.

## Build and OTA artifact

The source baseline is OpenBeken 1.18.318. This feature build uses the SemVer prerelease 1.18.318-blemesh.1; the trailing Test is kept separately as the device/OTA variant. The firmware USER_SW_VER is therefore 1.18.318-blemesh.1_Test, while the RBL header version is 1.18.318-blemesh.1 and the OTA filename is:

OpenBK7231N_1.18.318-blemesh.1_Test.rbl

Test is not the software version. The version string uses the upstream release as its base and labels this fork build as a prerelease.

From the repository root, build with the matching SDK/toolchain installed:

    mingw32-make APP_BIN_NAME=OpenBK7231N USER_SW_VER=1.18.318-blemesh.1_Test APP_VERSION=mesh-dev -j2 -C sdk/OpenBK7231N/platforms/bk7231n/bk7231n_os

The resulting BIN is normally under apps/OpenBK7231N/output/mesh-dev/. Package it using Python 3 and PyCryptodome:

    python -m pip install pycryptodome
    python build_scripts/package_bk7231n_rbl.py sdk/OpenBK7231N/apps/OpenBK7231N/output/mesh-dev/OpenBK7231N_mesh-dev.bin Release/OpenBK7231N_1.18.318-blemesh.1_Test.rbl --version 1.18.318-blemesh.1

The packager follows the RT-Thread algorithm 258 settings used by OpenBeken and verifies header/payload checksums plus decrypt/decompress round-trip. A successful local build was produced with GCC 15.2.1 and temporary SDK makefile compatibility overrides for the toolchain path, legacy diagnostics, and duplicate generated Berry class symbols. Those machine-specific overrides are not part of the source tree; a clean build with the repository stock BK7231N toolchain has not been independently verified.

The checked-in RBL is a convenience artifact, not evidence of a hardware test. No firmware has been flashed as part of this work. Use a recovery method before trying OTA on a real device.

## Upstream Mesh dependency finding

The inspected BK7231N SDK checkout and public SDK mirror did not contain the BK7231N-specific Beken SIG Mesh implementation/API needed to integrate standard Bluetooth Mesh. This was checked against the [OpenBeken 1.18.318 source](https://github.com/openshwprojects/OpenBK7231T_App/tree/1.18.318), the public SDK mirror [application.mk](https://gitee.com/belonpeter/beken_freertos_sdk_release/blob/master/application.mk), and the Beken [BK7231N product page](https://www.bekencorp.com/en/goods/detail/cid/39.html), whose BLE-version descriptions are not consistent enough to establish a matching Mesh API. The separate experimental relay above is a fallback protocol, not proof that this missing dependency is technically impossible to obtain. A production SIG Mesh port still requires a compatible, licensed Mesh stack, headers, examples, and coexistence documentation for the exact BK7231N BLE stack.
