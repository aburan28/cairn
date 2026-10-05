import Foundation
import XCTest
@testable import Cairn

/// What the Fleet settings read back from `cairn fleet` and `GET /network`.
final class FleetTests: XCTestCase {
    func testTheMemberListDecodesAndAMemberOwnsItsSlices() throws {
        let text = """
            [{"expires_at":null,"invite":null,"joined_at":"2026-10-05T10:00:00Z",\
            "member":"\(String(repeating: "ab", count: 32))","name":"gpu-box-1","revoked_at":null,\
            "revoked_reason":null,"state":"member"},\
            {"expires_at":"2026-10-05T22:00:00Z","invite":"\(String(repeating: "cd", count: 32))",\
            "joined_at":"2026-10-05T10:00:00Z","member":"\(String(repeating: "ef", count: 32))",\
            "name":"rented-3f9a2c1b0d4e","revoked_at":"2026-10-05T11:00:00Z",\
            "revoked_reason":"box returned","state":"revoked"}]
            """
        let members = try FleetMember.decode(text)
        XCTAssertEqual(members.count, 2)
        XCTAssertEqual(members[0].name, "gpu-box-1")
        XCTAssertNil(members[0].expiresAt)
        XCTAssertEqual(members[1].revokedReason, "box returned")
        XCTAssertTrue(members[0].owns("gpu-box-1"))
        XCTAssertTrue(members[0].owns("gpu-box-1/gpu0"))
        XCTAssertFalse(members[0].owns("gpu-box-10"))
    }

    func testAnInvitationDecodesFromTheJSONTheCLIPrints() throws {
        let text = """
            {"directory":"/x/log/fleet","expires_at":"2026-10-06T10:00:00Z","invite":"\(String(repeating: "aa", count: 32))",\
            "join":"cairn fleet join --node http://192.168.1.20:8080 cairn-invite1.x.y","leader":"\(String(repeating: "bb", count: 32))",\
            "member_ttl_seconds":43200,"name":null,"note":null,"prefix":"rented","token":"cairn-invite1.x.y","uses":16}
            """
        let invitation = try FleetInvitation.decode(text)
        XCTAssertEqual(invitation.uses, 16)
        XCTAssertTrue(invitation.join.hasPrefix("cairn fleet join --node http://192.168.1.20:8080 "))
    }

    func testLiveMembersAndTheJoinAddressComeFromTheNetworkRoute() {
        let external: [String: Any] = ["status": "mapped", "public": true, "address": "203.0.113.7:8080"]
        let reach: [String: Any] = [
            "bound": "0.0.0.0:8080", "lan": true, "urls": ["http://192.168.1.20:8080"], "external": external,
        ]
        let workers: [[String: Any]] = [
            ["worker": "gpu-box-1/gpu0", "status": "live", "member": true],
            ["worker": "stranger", "status": "live", "member": false],
            ["worker": "old-box", "status": "gone", "member": true],
        ]
        let hosts: [[String: Any]] = [["host": "desk-box", "status": "live", "member": true]]
        let compute: [String: Any] = ["workers": workers, "hosts": ["hosts": hosts] as [String: Any]]
        let network: [String: Any] = ["node": ["reach": reach] as [String: Any], "compute": compute]
        XCTAssertEqual(FleetFacts.liveMemberNames(network), ["gpu-box-1/gpu0", "desk-box"])
        XCTAssertEqual(FleetFacts.joinAddress(network), "http://203.0.113.7:8080")

        let off: [String: Any] = ["status": "off"]
        let lanReach: [String: Any] = ["urls": ["http://192.168.1.20:8080"], "external": off]
        let lanOnly: [String: Any] = ["node": ["reach": lanReach] as [String: Any]]
        XCTAssertEqual(FleetFacts.joinAddress(lanOnly), "http://192.168.1.20:8080")
        XCTAssertNil(FleetFacts.joinAddress([:]))
    }
}
