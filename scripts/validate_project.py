#!/usr/bin/env python3
"""
Structural validation of the generated project.pbxproj.

Catches the failure modes that make Xcode reject a project outright:
  - unbalanced braces / parens
  - object IDs referenced but never defined (dangling refs)
  - required isa sections missing
  - source files on disk not included in any target
  - Shared/ files not compiled into BOTH targets
"""

import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PBX = os.path.join(ROOT, "MyDNS.xcodeproj", "project.pbxproj")

failures = []
warnings = []


def check(condition, message):
    if condition:
        print(f"  PASS  {message}")
    else:
        print(f"  FAIL  {message}")
        failures.append(message)


def main():
    if not os.path.exists(PBX):
        print("project.pbxproj not found — run generate_xcodeproj.py first")
        sys.exit(1)

    text = open(PBX).read()

    print("\n=== Syntax ===")
    check(text.count("{") == text.count("}"),
          f"braces balanced ({text.count('{')} open / {text.count('}')} close)")
    check(text.count("(") == text.count(")"),
          f"parens balanced ({text.count('(')} open / {text.count(')')} close)")
    check(text.startswith("// !$*UTF8*$!"), "UTF8 header present")
    check("rootObject = " in text, "rootObject declared")

    # ---- object definitions ----
    defined = set(re.findall(r"^\t\t([0-9A-F]{24}) ", text, re.MULTILINE))
    defined |= set(re.findall(r"^\t\t([0-9A-F]{24}) = \{", text, re.MULTILINE))
    all_ids = set(re.findall(r"\b([0-9A-F]{24})\b", text))

    print(f"\n=== Object graph ===")
    print(f"  {len(defined)} objects defined, {len(all_ids)} distinct IDs referenced")

    dangling = all_ids - defined
    check(not dangling,
          f"no dangling references"
          + (f" (found: {sorted(dangling)[:5]})" if dangling else ""))

    # ---- required sections ----
    print("\n=== Required sections ===")
    for isa, minimum in [
        ("PBXProject", 1),
        ("PBXNativeTarget", 2),
        ("PBXSourcesBuildPhase", 2),
        ("PBXResourcesBuildPhase", 1),
        ("PBXFrameworksBuildPhase", 2),
        ("PBXCopyFilesBuildPhase", 1),
        ("PBXTargetDependency", 1),
        ("PBXContainerItemProxy", 1),
        ("XCConfigurationList", 3),
        ("XCBuildConfiguration", 6),
        ("PBXGroup", 5),
    ]:
        count = len(re.findall(rf"isa = {isa};", text))
        check(count >= minimum, f"{isa}: {count} (need >= {minimum})")

    # ---- target wiring ----
    print("\n=== Target wiring ===")
    check('productType = "com.apple.product-type.application";' in text,
          "app product type set")
    check('productType = "com.apple.product-type.app-extension";' in text,
          "extension product type set")
    check("dstSubfolderSpec = 13;" in text,
          "extension embedded into PlugIns (dstSubfolderSpec 13)")
    check("PRODUCT_BUNDLE_IDENTIFIER" in text, "bundle identifiers configured")
    check("CODE_SIGN_ENTITLEMENTS" in text, "entitlements wired to targets")

    # ---- source membership ----
    print("\n=== Source membership ===")
    on_disk = {"app": [], "tunnel": [], "shared": []}
    for dirpath, _, names in os.walk(os.path.join(ROOT, "Sources")):
        for n in sorted(names):
            if not n.endswith(".swift"):
                continue
            rel = os.path.relpath(os.path.join(dirpath, n), ROOT)
            if "Sources/App" in rel:
                on_disk["app"].append(rel)
            elif "Sources/Tunnel" in rel:
                on_disk["tunnel"].append(rel)
            elif "Sources/Shared" in rel:
                on_disk["shared"].append(rel)

    for group, files in on_disk.items():
        for f in files:
            check(f in text, f"{group}: {os.path.basename(f)} referenced")

    # Each Shared file must appear as TWO build files (one per target).
    print("\n=== Shared files compiled into both targets ===")
    for f in on_disk["shared"]:
        fid = re.search(rf'([0-9A-F]{{24}}) /\* {re.escape(os.path.basename(f))} \*/ = '
                        rf'\{{isa = PBXFileReference', text)
        if not fid:
            check(False, f"{os.path.basename(f)} file reference found")
            continue
        refs = len(re.findall(rf"fileRef = {fid.group(1)};", text))
        check(refs == 2,
              f"{os.path.basename(f)} in both targets (found {refs} build files)")

    # ---- supporting files exist ----
    print("\n=== Supporting files on disk ===")
    for rel in [
        "MyDNS/Info.plist",
        "MyDNS/MyDNS.entitlements",
        "MyDNSTunnel/Info.plist",
        "MyDNSTunnel/MyDNSTunnel.entitlements",
        "MyDNS/Assets.xcassets/Contents.json",
        "MyDNS/Assets.xcassets/AppIcon.appiconset/icon-1024.png",
        "MyDNS.xcodeproj/xcshareddata/xcschemes/MyDNS.xcscheme",
    ]:
        check(os.path.exists(os.path.join(ROOT, rel)), f"{rel} exists")

    # ---- consistency between entitlements and code ----
    print("\n=== Identifier consistency ===")
    ent = open(os.path.join(ROOT, "MyDNS/MyDNS.entitlements")).read()
    app_config = open(os.path.join(ROOT, "Sources/Shared/AppConfig.swift")).read()
    group_in_ent = re.search(r"<string>(group\.[^<]+)</string>", ent)
    check(group_in_ent is not None, "app group declared in entitlements")
    if group_in_ent:
        check(group_in_ent.group(1) in app_config,
              f"app group {group_in_ent.group(1)} matches AppConfig default")

    check("packet-tunnel-provider" in ent,
          "packet-tunnel-provider entitlement present")

    tunnel_plist = open(os.path.join(ROOT, "MyDNSTunnel/Info.plist")).read()
    check("com.apple.networkextension.packet-tunnel" in tunnel_plist,
          "extension point identifier correct")
    check("PacketTunnelProvider" in tunnel_plist,
          "principal class points at PacketTunnelProvider")

    # ---- summary ----
    print("\n" + "=" * 52)
    if failures:
        print(f"{len(failures)} CHECK(S) FAILED")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    print("ALL CHECKS PASSED — project structure is valid")
    print("=" * 52)


if __name__ == "__main__":
    main()
