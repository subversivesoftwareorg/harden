import Foundation

struct DeviceIdentity: Codable {
    let hardwareUUID: String
    let serialNumber: String
    let model: String
    let hostname: String
    let localHostname: String
    let osVersion: String
    let osBuild: String
    let primaryMAC: String
    let currentUser: String

    var stableID: String { hardwareUUID }

    static func current() async -> DeviceIdentity {
        async let uuid = ShellCommand.run("ioreg -d2 -c IOPlatformExpertDevice | grep IOPlatformUUID | sed 's/.*= \"\\(.*\\)\"/\\1/'")
        async let serial = ShellCommand.run("ioreg -d2 -c IOPlatformExpertDevice | grep IOPlatformSerialNumber | sed 's/.*= \"\\(.*\\)\"/\\1/'")
        async let model = ShellCommand.run("sysctl -n hw.model 2>/dev/null")
        async let hostname = ShellCommand.run("scutil --get ComputerName 2>/dev/null")
        async let localHost = ShellCommand.run("scutil --get LocalHostName 2>/dev/null")
        async let osVer = ShellCommand.run("sw_vers -productVersion")
        async let osBld = ShellCommand.run("sw_vers -buildVersion")
        async let mac = ShellCommand.run("ifconfig en0 2>/dev/null | grep ether | awk '{print $2}'")
        async let user = ShellCommand.run("id -F 2>/dev/null || whoami")

        return await DeviceIdentity(
            hardwareUUID: uuid.output,
            serialNumber: serial.output,
            model: model.output,
            hostname: hostname.output,
            localHostname: localHost.output,
            osVersion: osVer.output,
            osBuild: osBld.output,
            primaryMAC: mac.output,
            currentUser: user.output
        )
    }
}
