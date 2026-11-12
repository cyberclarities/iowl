"""catalog.py — the rules iOwl uses to sort apps into kinds.

Every rule is a bundle-id prefix, matched case-insensitively against the start
of the id, so the reader can see exactly why an app landed where it did. The
technical report prints this whole table in its appendix.

These are vendor product identifiers, not anything about the person who owns
the Mac, so they are safe to show in a report. They are also a list that will
age: vendors rename bundles, and new products appear. Add to it freely; a
bundle that matches nothing is reported as unclassified, never guessed at.
"""

# kind -> (label, [(prefix, product)])
APP_KINDS = {
    "private_messenger": ("Private or encrypted messenger", [
        ("org.whispersystems.signal", "Signal"),
        ("net.whatsapp.", "WhatsApp"),
        ("desktop.whatsapp", "WhatsApp"),
        ("ru.keepcoder.telegram", "Telegram"),
        ("org.telegram.", "Telegram"),
        ("ph.telegra.", "Telegram"),
        ("ch.threema.", "Threema"),
        ("com.wire.", "Wire"),
        ("im.riot.", "Element"),
        ("io.element.", "Element"),
        ("com.viber.", "Viber"),
        ("com.sessionmessenger.", "Session"),
        ("chat.simplex.", "SimpleX"),
    ]),
    "work_collab": ("Work collaboration", [
        ("com.microsoft.teams", "Microsoft Teams"),
        ("com.microsoft.skype.teams", "Microsoft Teams"),
        ("com.tinyspeck.slackmacgap", "Slack"),
        ("com.tinyspeck.chatlyio", "Slack"),
        ("com.slack.", "Slack"),
        ("us.zoom.", "Zoom"),
        ("com.cisco.webex", "Webex"),
        ("com.webex.", "Webex"),
        ("com.google.chat", "Google Chat"),
    ]),
    "social_chat": ("Social and community chat", [
        ("com.hnc.discord", "Discord"),
        ("com.hammerandchisel.discord", "Discord"),
        ("com.discord", "Discord"),
        ("com.facebook.messenger", "Messenger"),
        ("com.facebook.facebook", "Facebook"),
        ("jp.naver.line", "LINE"),
        ("com.tencent.xin", "WeChat"),
        ("com.iwilab.kakaotalk", "KakaoTalk"),
        ("com.burbn.instagram", "Instagram"),
        ("com.linkedin.", "LinkedIn"),
        ("com.atebits.tweetie2", "X"),
        ("com.toyopagroup.picaboo", "Snapchat"),
    ]),
    "apple_comms": ("Apple Messages, Phone and FaceTime", [
        ("com.apple.mobilesms", "Messages"),
        ("com.apple.ichat", "Messages"),
        ("com.apple.messages", "Messages"),
        ("com.apple.mobilephone", "Phone"),
        ("com.apple.incallservice", "Phone"),
        ("com.apple.telephonyutilities", "Phone"),
        ("com.apple.facetime", "FaceTime"),
        ("com.apple.mobilemail", "Mail"),
        ("com.apple.mail", "Mail"),
    ]),
    "edr": ("Endpoint security (EDR and antivirus)", [
        ("com.crowdstrike.", "CrowdStrike Falcon"),
        ("com.sentinelone.", "SentinelOne"),
        ("com.microsoft.wdav", "Microsoft Defender"),
        ("com.sophos.", "Sophos"),
        ("com.vmware.carbonblack", "Carbon Black"),
        ("com.carbonblack.", "Carbon Black"),
        ("com.jamf.protect", "Jamf Protect"),
        ("com.malwarebytes.", "Malwarebytes"),
        ("com.eset.", "ESET"),
        ("com.kaspersky.", "Kaspersky"),
        ("com.bitdefender.", "Bitdefender"),
        ("com.trendmicro.", "Trend Micro"),
        ("co.elastic.", "Elastic"),
        ("com.objective-see.", "Objective-See"),
    ]),
    "mdm": ("Device management (MDM)", [
        ("com.microsoft.companyportalmac", "Company Portal (Intune)"),
        ("com.microsoft.companyportal", "Company Portal (Intune)"),
        ("com.jamfsoftware.", "Jamf"),
        ("com.jamf.management", "Jamf"),
        ("io.kandji.", "Kandji"),
        ("com.kandji.", "Kandji"),
        ("com.mosyle.", "Mosyle"),
        ("com.addigy.", "Addigy"),
        ("com.hexnode.", "Hexnode"),
        ("com.airwatch.", "Workspace ONE"),
        ("com.vmware.hub", "Workspace ONE"),
    ]),
    "vpn": ("VPN, proxy and circumvention", [
        ("com.cisco.anyconnect", "Cisco AnyConnect"),
        ("com.cisco.secureclient", "Cisco Secure Client"),
        ("com.paloaltonetworks.globalprotect", "GlobalProtect"),
        ("com.fortinet.", "FortiClient"),
        ("net.openvpn.", "OpenVPN"),
        ("com.wireguard.", "WireGuard"),
        ("com.nordvpn.", "NordVPN"),
        ("com.expressvpn.", "ExpressVPN"),
        ("ch.protonvpn.", "Proton VPN"),
        ("com.protonvpn.", "Proton VPN"),
        ("net.mullvad.", "Mullvad"),
        ("io.tailscale.", "Tailscale"),
        ("com.tailscale.", "Tailscale"),
        ("com.zscaler.", "Zscaler"),
        ("com.cloudflare.1dot1dot1dot1", "Cloudflare WARP"),
        ("com.privateinternetaccess.", "Private Internet Access"),
        ("com.surfshark.", "Surfshark"),
        ("ca.psiphon.", "Psiphon"),
        ("com.psiphon3.", "Psiphon"),
        ("org.torproject.", "Tor Browser"),
        ("org.getlantern.", "Lantern"),
        ("com.outline.", "Outline"),
        ("org.outline.", "Outline"),
    ]),
    "credentials": ("Password and credential managers", [
        ("com.1password.", "1Password"),
        ("com.agilebits.", "1Password"),
        ("com.bitwarden.", "Bitwarden"),
        ("com.lastpass.", "LastPass"),
        ("com.dashlane.", "Dashlane"),
        ("org.keepassxc.", "KeePassXC"),
        ("com.keepersecurity.", "Keeper"),
    ]),
    "remote_access": ("Remote access", [
        ("com.teamviewer.", "TeamViewer"),
        ("com.philandro.anydesk", "AnyDesk"),
        ("com.anydesk.", "AnyDesk"),
        ("com.splashtop.", "Splashtop"),
        ("com.logmein.", "LogMeIn"),
        ("com.realvnc.", "RealVNC"),
        ("com.microsoft.rdc", "Microsoft Remote Desktop"),
        ("com.screenconnect.", "ScreenConnect"),
    ]),
}

# The kinds that describe how the Mac is defended, for the "security stack
# catalogued" finding.
SECURITY_KINDS = ("edr", "mdm", "vpn", "credentials", "remote_access")

# The kinds whose traffic in the interaction log is communication with people.
COMMS_KINDS = ("private_messenger", "work_collab", "social_chat", "apple_comms")


def classify(bundle_id):
    """(kind, label, product) for a bundle id, or (None, None, None)."""
    b = (bundle_id or "").lower()
    for kind, (label, rules) in APP_KINDS.items():
        for prefix, product in rules:
            if b.startswith(prefix):
                return kind, label, product
    return None, None, None


def rules_table():
    """Every rule, flat, for the report appendix."""
    return [{"kind": kind, "label": label, "prefix": prefix, "product": product}
            for kind, (label, rules) in APP_KINDS.items()
            for prefix, product in rules]
