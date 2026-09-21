import Foundation

/// Single source of truth for identifiers. Change BUNDLE_PREFIX in one place
/// (project.yml / Xcode build settings) and everything else follows.
public enum AppConfig {

    /// Must match the App Groups capability on BOTH targets.
    public static let appGroup: String = {
        if let value = Bundle.main.object(forInfoDictionaryKey: "AppGroupIdentifier") as? String,
           !value.isEmpty {
            return value
        }
        return "group.com.mydns.app"
    }()

    /// Bundle ID of the packet tunnel extension.
    public static let tunnelBundleID: String = {
        if let value = Bundle.main.object(forInfoDictionaryKey: "TunnelBundleIdentifier") as? String,
           !value.isEmpty {
            return value
        }
        return "com.mydns.app.tunnel"
    }()

    /// Private virtual network used by the local tunnel.
    public enum Network {
        public static let virtualAddress = "10.7.0.2"
        public static let virtualNetmask = "255.255.255.0"
        public static let virtualDNS     = "10.7.0.53"
        public static let mtu: NSNumber  = 1400
    }

    public static var sharedDefaults: UserDefaults {
        UserDefaults(suiteName: appGroup) ?? .standard
    }

    public static var sharedContainer: URL? {
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup)
    }
}
