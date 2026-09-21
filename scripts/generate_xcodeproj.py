#!/usr/bin/env python3
"""
Generates MyDNS.xcodeproj without requiring XcodeGen, Ruby, or a Mac.

Produces a two-target project:
  - MyDNS            (iOS app)
  - MyDNSTunnel      (Packet Tunnel network extension, embedded in the app)

Usage:
    python3 scripts/generate_xcodeproj.py [--bundle-id com.yourname.mydns] [--team ABCDE12345]
"""

import argparse
import os
import secrets
import shutil

PROJECT_NAME = "MyDNS"
TUNNEL_NAME = "MyDNSTunnel"


def oid():
    """Xcode object IDs are 24 uppercase hex characters."""
    return secrets.token_hex(12).upper()


class Pbx:
    def __init__(self, bundle_id, team, deployment_target):
        self.bundle_id = bundle_id
        self.tunnel_bundle_id = f"{bundle_id}.tunnel"
        self.app_group = f"group.{bundle_id}"
        self.team = team
        self.deployment_target = deployment_target
        self.objects = []

    def add(self, text):
        self.objects.append(text)

    # ---------- source file discovery ----------

    def collect(self, root):
        app, tunnel, shared = [], [], []
        for dirpath, _, filenames in os.walk(root):
            for name in sorted(filenames):
                if not name.endswith(".swift"):
                    continue
                rel = os.path.relpath(os.path.join(dirpath, name), root)
                if rel.startswith("Sources/App"):
                    app.append(rel)
                elif rel.startswith("Sources/Tunnel"):
                    tunnel.append(rel)
                elif rel.startswith("Sources/Shared"):
                    shared.append(rel)
        return sorted(app), sorted(tunnel), sorted(shared)


def build_pbxproj(root, bundle_id, team, deployment_target="16.0"):
    p = Pbx(bundle_id, team, deployment_target)
    app_src, tunnel_src, shared_src = p.collect(root)

    if not app_src or not tunnel_src or not shared_src:
        raise SystemExit(
            f"Missing sources. app={len(app_src)} tunnel={len(tunnel_src)} shared={len(shared_src)}"
        )

    # ---- identifiers ----
    ids = {k: oid() for k in [
        "project", "mainGroup", "productsGroup", "sourcesGroup",
        "appGroupNode", "tunnelGroupNode", "sharedGroupNode",
        "appTarget", "tunnelTarget",
        "appProduct", "tunnelProduct",
        "appSources", "tunnelSources", "appResources",
        "appFrameworks", "tunnelFrameworks",
        "embedExtensions", "tunnelDependency", "containerProxy",
        "projectConfigList", "appConfigList", "tunnelConfigList",
        "projDebug", "projRelease", "appDebug", "appRelease",
        "tunnelDebug", "tunnelRelease",
        "assets", "appInfo", "tunnelInfo", "appEnt", "tunnelEnt",
        "resourcesGroup",
    ]}

    file_refs = {}     # relative path -> file reference id
    build_files = {}   # (path, target) -> build file id

    def file_ref(path, explicit_type=None, name=None):
        if path in file_refs:
            return file_refs[path]
        fid = oid()
        file_refs[path] = fid
        ftype = explicit_type or {
            ".swift": "sourcecode.swift",
            ".plist": "text.plist.xml",
            ".entitlements": "text.plist.entitlements",
            ".xcassets": "folder.assetcatalog",
        }.get(os.path.splitext(path)[1], "text")
        display = name or os.path.basename(path)
        p.add(
            f'\t\t{fid} /* {display} */ = {{isa = PBXFileReference; '
            f'lastKnownFileType = {ftype}; name = "{display}"; '
            f'path = "{path}"; sourceTree = "<group>"; }};'
        )
        return fid

    def build_file(path, tag):
        key = (path, tag)
        if key in build_files:
            return build_files[key]
        bid = oid()
        build_files[key] = bid
        fid = file_refs[path]
        p.add(
            f'\t\t{bid} /* {os.path.basename(path)} in Sources */ = '
            f'{{isa = PBXBuildFile; fileRef = {fid}; }};'
        )
        return bid

    # ---- file references ----
    for path in app_src + tunnel_src + shared_src:
        file_ref(path)

    file_ref("MyDNS/Assets.xcassets")
    file_ref("MyDNS/Info.plist")
    file_ref("MyDNS/MyDNS.entitlements")
    file_ref("MyDNSTunnel/Info.plist", name="Tunnel-Info.plist")
    file_ref("MyDNSTunnel/MyDNSTunnel.entitlements")

    # ---- products ----
    p.add(
        f'\t\t{ids["appProduct"]} /* {PROJECT_NAME}.app */ = {{isa = PBXFileReference; '
        f'explicitFileType = wrapper.application; includeInIndex = 0; '
        f'path = "{PROJECT_NAME}.app"; sourceTree = BUILT_PRODUCTS_DIR; }};'
    )
    p.add(
        f'\t\t{ids["tunnelProduct"]} /* {TUNNEL_NAME}.appex */ = {{isa = PBXFileReference; '
        f'explicitFileType = "wrapper.app-extension"; includeInIndex = 0; '
        f'path = "{TUNNEL_NAME}.appex"; sourceTree = BUILT_PRODUCTS_DIR; }};'
    )

    # ---- build files ----
    app_build = [build_file(f, "app") for f in app_src + shared_src]
    tunnel_build = [build_file(f, "tunnel") for f in tunnel_src + shared_src]

    assets_build = oid()
    p.add(
        f'\t\t{assets_build} /* Assets.xcassets in Resources */ = '
        f'{{isa = PBXBuildFile; fileRef = {file_refs["MyDNS/Assets.xcassets"]}; }};'
    )

    embed_build = oid()
    p.add(
        f'\t\t{embed_build} /* {TUNNEL_NAME}.appex in Embed Foundation Extensions */ = '
        f'{{isa = PBXBuildFile; fileRef = {ids["tunnelProduct"]}; '
        f'settings = {{ATTRIBUTES = (RemoveHeadersOnCopy, ); }}; }};'
    )

    # ---- groups ----
    def group(gid, name, children, path=None):
        kids = "\n".join(f"\t\t\t\t{c}," for c in children)
        path_line = f'\n\t\t\tpath = "{path}";' if path else ""
        p.add(
            f'\t\t{gid} /* {name} */ = {{\n'
            f'\t\t\tisa = PBXGroup;\n'
            f'\t\t\tchildren = (\n{kids}\n\t\t\t);\n'
            f'\t\t\tname = "{name}";{path_line}\n'
            f'\t\t\tsourceTree = "<group>";\n'
            f'\t\t}};'
        )

    group(ids["appGroupNode"], "App", [file_refs[f] for f in app_src])
    group(ids["tunnelGroupNode"], "Tunnel", [file_refs[f] for f in tunnel_src])
    group(ids["sharedGroupNode"], "Shared", [file_refs[f] for f in shared_src])
    group(ids["sourcesGroup"], "Sources",
          [ids["appGroupNode"], ids["tunnelGroupNode"], ids["sharedGroupNode"]])
    group(ids["resourcesGroup"], "Supporting Files", [
        file_refs["MyDNS/Assets.xcassets"],
        file_refs["MyDNS/Info.plist"],
        file_refs["MyDNS/MyDNS.entitlements"],
        file_refs["MyDNSTunnel/Info.plist"],
        file_refs["MyDNSTunnel/MyDNSTunnel.entitlements"],
    ])
    group(ids["productsGroup"], "Products", [ids["appProduct"], ids["tunnelProduct"]])
    group(ids["mainGroup"], "MyDNS",
          [ids["sourcesGroup"], ids["resourcesGroup"], ids["productsGroup"]])

    # ---- build phases ----
    def sources_phase(pid, files):
        kids = "\n".join(f"\t\t\t\t{f}," for f in files)
        p.add(
            f'\t\t{pid} /* Sources */ = {{\n'
            f'\t\t\tisa = PBXSourcesBuildPhase;\n'
            f'\t\t\tbuildActionMask = 2147483647;\n'
            f'\t\t\tfiles = (\n{kids}\n\t\t\t);\n'
            f'\t\t\trunOnlyForDeploymentPostprocessing = 0;\n'
            f'\t\t}};'
        )

    sources_phase(ids["appSources"], app_build)
    sources_phase(ids["tunnelSources"], tunnel_build)

    p.add(
        f'\t\t{ids["appResources"]} /* Resources */ = {{\n'
        f'\t\t\tisa = PBXResourcesBuildPhase;\n'
        f'\t\t\tbuildActionMask = 2147483647;\n'
        f'\t\t\tfiles = (\n\t\t\t\t{assets_build},\n\t\t\t);\n'
        f'\t\t\trunOnlyForDeploymentPostprocessing = 0;\n'
        f'\t\t}};'
    )

    for pid in (ids["appFrameworks"], ids["tunnelFrameworks"]):
        p.add(
            f'\t\t{pid} /* Frameworks */ = {{\n'
            f'\t\t\tisa = PBXFrameworksBuildPhase;\n'
            f'\t\t\tbuildActionMask = 2147483647;\n'
            f'\t\t\tfiles = (\n\t\t\t);\n'
            f'\t\t\trunOnlyForDeploymentPostprocessing = 0;\n'
            f'\t\t}};'
        )

    # Embed the extension inside the app bundle (PlugIns directory).
    p.add(
        f'\t\t{ids["embedExtensions"]} /* Embed Foundation Extensions */ = {{\n'
        f'\t\t\tisa = PBXCopyFilesBuildPhase;\n'
        f'\t\t\tbuildActionMask = 2147483647;\n'
        f'\t\t\tdstPath = "";\n'
        f'\t\t\tdstSubfolderSpec = 13;\n'
        f'\t\t\tfiles = (\n\t\t\t\t{embed_build},\n\t\t\t);\n'
        f'\t\t\tname = "Embed Foundation Extensions";\n'
        f'\t\t\trunOnlyForDeploymentPostprocessing = 0;\n'
        f'\t\t}};'
    )

    # ---- dependency wiring ----
    p.add(
        f'\t\t{ids["containerProxy"]} = {{\n'
        f'\t\t\tisa = PBXContainerItemProxy;\n'
        f'\t\t\tcontainerPortal = {ids["project"]};\n'
        f'\t\t\tproxyType = 1;\n'
        f'\t\t\tremoteGlobalIDString = {ids["tunnelTarget"]};\n'
        f'\t\t\tremoteInfo = "{TUNNEL_NAME}";\n'
        f'\t\t}};'
    )
    p.add(
        f'\t\t{ids["tunnelDependency"]} = {{\n'
        f'\t\t\tisa = PBXTargetDependency;\n'
        f'\t\t\ttarget = {ids["tunnelTarget"]};\n'
        f'\t\t\ttargetProxy = {ids["containerProxy"]};\n'
        f'\t\t}};'
    )

    # ---- targets ----
    p.add(
        f'\t\t{ids["appTarget"]} /* {PROJECT_NAME} */ = {{\n'
        f'\t\t\tisa = PBXNativeTarget;\n'
        f'\t\t\tbuildConfigurationList = {ids["appConfigList"]};\n'
        f'\t\t\tbuildPhases = (\n'
        f'\t\t\t\t{ids["appSources"]},\n'
        f'\t\t\t\t{ids["appFrameworks"]},\n'
        f'\t\t\t\t{ids["appResources"]},\n'
        f'\t\t\t\t{ids["embedExtensions"]},\n'
        f'\t\t\t);\n'
        f'\t\t\tbuildRules = (\n\t\t\t);\n'
        f'\t\t\tdependencies = (\n\t\t\t\t{ids["tunnelDependency"]},\n\t\t\t);\n'
        f'\t\t\tname = "{PROJECT_NAME}";\n'
        f'\t\t\tproductName = "{PROJECT_NAME}";\n'
        f'\t\t\tproductReference = {ids["appProduct"]};\n'
        f'\t\t\tproductType = "com.apple.product-type.application";\n'
        f'\t\t}};'
    )
    p.add(
        f'\t\t{ids["tunnelTarget"]} /* {TUNNEL_NAME} */ = {{\n'
        f'\t\t\tisa = PBXNativeTarget;\n'
        f'\t\t\tbuildConfigurationList = {ids["tunnelConfigList"]};\n'
        f'\t\t\tbuildPhases = (\n'
        f'\t\t\t\t{ids["tunnelSources"]},\n'
        f'\t\t\t\t{ids["tunnelFrameworks"]},\n'
        f'\t\t\t);\n'
        f'\t\t\tbuildRules = (\n\t\t\t);\n'
        f'\t\t\tdependencies = (\n\t\t\t);\n'
        f'\t\t\tname = "{TUNNEL_NAME}";\n'
        f'\t\t\tproductName = "{TUNNEL_NAME}";\n'
        f'\t\t\tproductReference = {ids["tunnelProduct"]};\n'
        f'\t\t\tproductType = "com.apple.product-type.app-extension";\n'
        f'\t\t}};'
    )

    # ---- project object ----
    p.add(
        f'\t\t{ids["project"]} = {{\n'
        f'\t\t\tisa = PBXProject;\n'
        f'\t\t\tattributes = {{\n'
        f'\t\t\t\tBuildIndependentTargetsInParallel = 1;\n'
        f'\t\t\t\tLastSwiftUpdateCheck = 1520;\n'
        f'\t\t\t\tLastUpgradeCheck = 1520;\n'
        f'\t\t\t\tTargetAttributes = {{\n'
        f'\t\t\t\t\t{ids["appTarget"]} = {{CreatedOnToolsVersion = 15.2; }};\n'
        f'\t\t\t\t\t{ids["tunnelTarget"]} = {{CreatedOnToolsVersion = 15.2; }};\n'
        f'\t\t\t\t}};\n'
        f'\t\t\t}};\n'
        f'\t\t\tbuildConfigurationList = {ids["projectConfigList"]};\n'
        f'\t\t\tdevelopmentRegion = en;\n'
        f'\t\t\thasScannedForEncodings = 0;\n'
        f'\t\t\tknownRegions = (\n\t\t\t\ten,\n\t\t\t\tBase,\n\t\t\t);\n'
        f'\t\t\tmainGroup = {ids["mainGroup"]};\n'
        f'\t\t\tproductRefGroup = {ids["productsGroup"]};\n'
        f'\t\t\tprojectDirPath = "";\n'
        f'\t\t\tprojectRoot = "";\n'
        f'\t\t\ttargets = (\n'
        f'\t\t\t\t{ids["appTarget"]},\n'
        f'\t\t\t\t{ids["tunnelTarget"]},\n'
        f'\t\t\t);\n'
        f'\t\t}};'
    )

    # ---- build configurations ----
    team_line = f'\t\t\t\tDEVELOPMENT_TEAM = {team};\n' if team else ""

    def project_config(cid, name, debug):
        opt = "-Onone" if debug else "-O"
        p.add(
            f'\t\t{cid} /* {name} */ = {{\n'
            f'\t\t\tisa = XCBuildConfiguration;\n'
            f'\t\t\tbuildSettings = {{\n'
            f'\t\t\t\tALWAYS_SEARCH_USER_PATHS = NO;\n'
            f'\t\t\t\tCLANG_ENABLE_MODULES = YES;\n'
            f'\t\t\t\tCLANG_ENABLE_OBJC_ARC = YES;\n'
            f'\t\t\t\tCOPY_PHASE_STRIP = NO;\n'
            f'\t\t\t\tDEBUG_INFORMATION_FORMAT = "dwarf-with-dsym";\n'
            f'\t\t\t\tENABLE_STRICT_OBJC_MSGSEND = YES;\n'
            f'\t\t\t\tENABLE_USER_SCRIPT_SANDBOXING = YES;\n'
            f'\t\t\t\tGCC_C_LANGUAGE_STANDARD = gnu17;\n'
            f'\t\t\t\tIPHONEOS_DEPLOYMENT_TARGET = {deployment_target};\n'
            f'\t\t\t\tMTL_ENABLE_DEBUG_INFO = {"INCLUDE_SOURCE" if debug else "NO"};\n'
            f'\t\t\t\tONLY_ACTIVE_ARCH = {"YES" if debug else "NO"};\n'
            f'\t\t\t\tSDKROOT = iphoneos;\n'
            f'\t\t\t\tSWIFT_OPTIMIZATION_LEVEL = "{opt}";\n'
            f'\t\t\t\tSWIFT_VERSION = 5.0;\n'
            f'\t\t\t\tTARGETED_DEVICE_FAMILY = "1,2";\n'
            f'\t\t\t\tVALIDATE_PRODUCT = {"NO" if debug else "YES"};\n'
            f'\t\t\t}};\n'
            f'\t\t\tname = {name};\n'
            f'\t\t}};'
        )

    project_config(ids["projDebug"], "Debug", True)
    project_config(ids["projRelease"], "Release", False)

    def target_config(cid, name, is_app):
        product_bundle = bundle_id if is_app else f"{bundle_id}.tunnel"
        info = "MyDNS/Info.plist" if is_app else "MyDNSTunnel/Info.plist"
        ent = ("MyDNS/MyDNS.entitlements" if is_app
               else "MyDNSTunnel/MyDNSTunnel.entitlements")

        extra = ""
        if is_app:
            extra = (
                f'\t\t\t\tASSETCATALOG_COMPILER_APPICON_NAME = AppIcon;\n'
                f'\t\t\t\tASSETCATALOG_COMPILER_GLOBAL_ACCENT_COLOR_NAME = AccentColor;\n'
                f'\t\t\t\tINFOPLIST_KEY_UIApplicationSceneManifest_Generation = YES;\n'
                f'\t\t\t\tINFOPLIST_KEY_UILaunchScreen_Generation = YES;\n'
                f'\t\t\t\tINFOPLIST_KEY_UISupportedInterfaceOrientations = '
                f'"UIInterfaceOrientationPortrait";\n'
                f'\t\t\t\tLD_RUNPATH_SEARCH_PATHS = '
                f'"$(inherited) @executable_path/Frameworks";\n'
            )
        else:
            extra = (
                f'\t\t\t\tLD_RUNPATH_SEARCH_PATHS = '
                f'"$(inherited) @executable_path/Frameworks '
                f'@executable_path/../../Frameworks";\n'
                f'\t\t\t\tSKIP_INSTALL = YES;\n'
            )

        p.add(
            f'\t\t{cid} /* {name} */ = {{\n'
            f'\t\t\tisa = XCBuildConfiguration;\n'
            f'\t\t\tbuildSettings = {{\n'
            f'\t\t\t\tCODE_SIGN_ENTITLEMENTS = "{ent}";\n'
            f'\t\t\t\tCODE_SIGN_STYLE = Automatic;\n'
            f'{team_line}'
            f'\t\t\t\tCURRENT_PROJECT_VERSION = 1;\n'
            f'\t\t\t\tGENERATE_INFOPLIST_FILE = NO;\n'
            f'\t\t\t\tINFOPLIST_FILE = "{info}";\n'
            f'{extra}'
            f'\t\t\t\tMARKETING_VERSION = 1.0;\n'
            f'\t\t\t\tPRODUCT_BUNDLE_IDENTIFIER = "{product_bundle}";\n'
            f'\t\t\t\tPRODUCT_NAME = "$(TARGET_NAME)";\n'
            f'\t\t\t\tSWIFT_EMIT_LOC_STRINGS = YES;\n'
            f'\t\t\t\tSWIFT_VERSION = 5.0;\n'
            f'\t\t\t}};\n'
            f'\t\t\tname = {name};\n'
            f'\t\t}};'
        )

    target_config(ids["appDebug"], "Debug", True)
    target_config(ids["appRelease"], "Release", True)
    target_config(ids["tunnelDebug"], "Debug", False)
    target_config(ids["tunnelRelease"], "Release", False)

    def config_list(lid, debug, release, label):
        p.add(
            f'\t\t{lid} /* Build configuration list for {label} */ = {{\n'
            f'\t\t\tisa = XCConfigurationList;\n'
            f'\t\t\tbuildConfigurations = (\n'
            f'\t\t\t\t{debug},\n'
            f'\t\t\t\t{release},\n'
            f'\t\t\t);\n'
            f'\t\t\tdefaultConfigurationIsVisible = 0;\n'
            f'\t\t\tdefaultConfigurationName = Release;\n'
            f'\t\t}};'
        )

    config_list(ids["projectConfigList"], ids["projDebug"], ids["projRelease"], "PBXProject")
    config_list(ids["appConfigList"], ids["appDebug"], ids["appRelease"], "PBXNativeTarget app")
    config_list(ids["tunnelConfigList"], ids["tunnelDebug"], ids["tunnelRelease"],
                "PBXNativeTarget tunnel")

    body = "\n".join(p.objects)
    return (
        "// !$*UTF8*$!\n"
        "{\n"
        "\tarchiveVersion = 1;\n"
        "\tclasses = {\n\t};\n"
        "\tobjectVersion = 56;\n"
        "\tobjects = {\n"
        f"{body}\n"
        "\t};\n"
        f"\trootObject = {ids['project']};\n"
        "}\n"
    ), ids


def write_scheme(root, ids, bundle_id):
    scheme_dir = os.path.join(
        root, f"{PROJECT_NAME}.xcodeproj", "xcshareddata", "xcschemes")
    os.makedirs(scheme_dir, exist_ok=True)

    scheme = f"""<?xml version="1.0" encoding="UTF-8"?>
<Scheme LastUpgradeVersion = "1520" version = "1.7">
   <BuildAction parallelizeBuildables = "YES" buildImplicitDependencies = "YES">
      <BuildActionEntries>
         <BuildActionEntry buildForTesting = "YES" buildForRunning = "YES" buildForProfiling = "YES" buildForArchiving = "YES" buildForAnalyzing = "YES">
            <BuildableReference
               BuildableIdentifier = "primary"
               BlueprintIdentifier = "{ids['appTarget']}"
               BuildableName = "{PROJECT_NAME}.app"
               BlueprintName = "{PROJECT_NAME}"
               ReferencedContainer = "container:{PROJECT_NAME}.xcodeproj">
            </BuildableReference>
         </BuildActionEntry>
      </BuildActionEntries>
   </BuildAction>
   <LaunchAction buildConfiguration = "Debug" selectedDebuggerIdentifier = "Xcode.DebuggerFoundation.Debugger.LLDB" selectedLauncherIdentifier = "Xcode.DebuggerFoundation.Launcher.LLDB" launchStyle = "0" useCustomWorkingDirectory = "NO" ignoresPersistentStateOnLaunch = "NO" debugDocumentVersioning = "YES" debugServiceExtension = "internal" allowLocationSimulation = "YES">
      <BuildableProductRunnable runnableDebuggingMode = "0">
         <BuildableReference
            BuildableIdentifier = "primary"
            BlueprintIdentifier = "{ids['appTarget']}"
            BuildableName = "{PROJECT_NAME}.app"
            BlueprintName = "{PROJECT_NAME}"
            ReferencedContainer = "container:{PROJECT_NAME}.xcodeproj">
         </BuildableReference>
      </BuildableProductRunnable>
   </LaunchAction>
   <ArchiveAction buildConfiguration = "Release" revealArchiveInOrganizer = "YES">
   </ArchiveAction>
</Scheme>
"""
    with open(os.path.join(scheme_dir, f"{PROJECT_NAME}.xcscheme"), "w") as f:
        f.write(scheme)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bundle-id", default="com.mydns.app")
    ap.add_argument("--team", default="")
    ap.add_argument("--deployment-target", default="16.0")
    ap.add_argument("--root", default=os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))))
    args = ap.parse_args()

    root = args.root
    proj_dir = os.path.join(root, f"{PROJECT_NAME}.xcodeproj")
    if os.path.exists(proj_dir):
        shutil.rmtree(proj_dir)
    os.makedirs(proj_dir, exist_ok=True)

    content, ids = build_pbxproj(root, args.bundle_id, args.team,
                                 args.deployment_target)

    with open(os.path.join(proj_dir, "project.pbxproj"), "w") as f:
        f.write(content)

    write_scheme(root, ids, args.bundle_id)

    print(f"Generated {proj_dir}")
    print(f"  App bundle ID    : {args.bundle_id}")
    print(f"  Tunnel bundle ID : {args.bundle_id}.tunnel")
    print(f"  App Group        : group.{args.bundle_id}")
    print(f"  Team             : {args.team or '(set in Xcode)'}")


if __name__ == "__main__":
    main()
