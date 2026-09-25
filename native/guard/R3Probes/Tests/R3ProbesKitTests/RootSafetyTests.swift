// Root refusal. Refused candidates must be rejected before anything is created.
import Darwin
import XCTest
@testable import R3ProbesKit

final class RootSafetyTests: XCTestCase {
    private var scratch = ""

    override func setUpWithError() throws {
        scratch = try RootSafety.makeTemporaryRoot()
    }

    override func tearDownWithError() throws {
        if RootSafety.isAllowed(resolved: scratch) { try? FileManager.default.removeItem(atPath: scratch) }
    }

    func testPrefixRule() {
        XCTAssertTrue(RootSafety.isAllowed(resolved: "/private/tmp/r3"))
        XCTAssertTrue(RootSafety.isAllowed(resolved: "/private/var/folders/ab/cd/T/r3"))
        XCTAssertTrue(RootSafety.isAllowed(resolved: "/tmp/r3"))
        XCTAssertFalse(RootSafety.isAllowed(resolved: "/private/tmp"))
        XCTAssertFalse(RootSafety.isAllowed(resolved: "/private/tmp/"))
        XCTAssertFalse(RootSafety.isAllowed(resolved: "/private/tmpx/r3"))
        XCTAssertFalse(RootSafety.isAllowed(resolved: "/private/var/folder/r3"))
        XCTAssertFalse(RootSafety.isAllowed(resolved: "/private/tmp/../etc"))
        XCTAssertFalse(RootSafety.isAllowed(resolved: "/Users/someone/r3"))
        XCTAssertFalse(RootSafety.isAllowed(resolved: "relative/r3"))
    }

    func testTemporaryRootIsResolvedAndAllowed() {
        XCTAssertTrue(scratch.hasPrefix("/private/var/folders/") || scratch.hasPrefix("/private/tmp/"), scratch)
    }

    func testRefusesHomeWithoutCreatingAnything() {
        let candidate = NSHomeDirectory() + "/r3-probes-refusal-\(getpid())"
        XCTAssertThrowsError(try RootSafety.prepareNewRoot(candidate))
        var info = stat()
        XCTAssertNotEqual(lstat(candidate, &info), 0, "refused root was created")
    }

    func testRefusesRelativeAndDotNames() {
        XCTAssertThrowsError(try RootSafety.prepareNewRoot("r3-relative"))
        XCTAssertThrowsError(try RootSafety.prepareNewRoot(scratch + "/.."))
        XCTAssertThrowsError(try RootSafety.existingRoot("r3-relative"))
    }

    func testRefusesSymlinkedParentThatLeavesTemporaryAreas() throws {
        // The link points at /usr, which is neither temporary nor writable; nothing is
        // created there even if the check were missing, because mkdir would fail.
        let link = scratch + "/escape"
        XCTAssertEqual(symlink("/usr", link), 0)
        XCTAssertThrowsError(try RootSafety.prepareNewRoot(link + "/fixture"))
        XCTAssertThrowsError(try RootSafety.existingRoot(link))
    }

    func testRefusesNonEmptyDirectoryAndAcceptsEmptyOne() throws {
        let existing = scratch + "/existing"
        XCTAssertEqual(mkdir(existing, 0o700), 0)
        XCTAssertEqual(try RootSafety.prepareNewRoot(existing), existing)
        XCTAssertEqual(mkdir(existing + "/something", 0o700), 0)
        XCTAssertThrowsError(try RootSafety.prepareNewRoot(existing))
    }

    func testPrepareRefusesAGroupOrOtherWritableEmptyRoot() throws {
        let existing = scratch + "/shared"
        XCTAssertEqual(mkdir(existing, 0o700), 0)
        XCTAssertEqual(chmod(existing, 0o770), 0)
        XCTAssertThrowsError(try RootSafety.prepareNewRoot(existing))
        XCTAssertEqual(chmod(existing, 0o707), 0)
        XCTAssertThrowsError(try RootSafety.prepareNewRoot(existing))
    }

    /// Later commands do not resolve paths; a spelling with a symlinked, empty, `.` or `..`
    /// component is refused instead of being followed.
    func testExistingRootRequiresTheCanonicalSpelling() throws {
        let fixture = scratch + "/fixture"
        XCTAssertEqual(mkdir(fixture, 0o700), 0)
        XCTAssertEqual(try RootSafety.existingRoot(fixture), fixture)
        XCTAssertThrowsError(try RootSafety.existingRoot(scratch + "//fixture"))
        XCTAssertThrowsError(try RootSafety.existingRoot(scratch + "/./fixture"))
        XCTAssertThrowsError(try RootSafety.existingRoot(fixture + "/"))
        XCTAssertThrowsError(try RootSafety.existingRoot(fixture + "/../fixture"))
        XCTAssertEqual(symlink(fixture, scratch + "/alias"), 0)
        XCTAssertThrowsError(try RootSafety.existingRoot(scratch + "/alias"))
        // /var is a symlink to /private/var: the non-canonical temporary spelling is refused.
        if fixture.hasPrefix("/private/var/") {
            XCTAssertThrowsError(try RootSafety.existingRoot(String(fixture.dropFirst("/private".count))))
        }
    }

    func testExistingRootMustBeTemporaryPrivateDirectory() throws {
        XCTAssertThrowsError(try RootSafety.existingRoot("/private/tmp"))
        XCTAssertThrowsError(try RootSafety.existingRoot(NSHomeDirectory()))
        XCTAssertEqual(chmod(scratch, 0o777), 0)
        XCTAssertThrowsError(try RootSafety.existingRoot(scratch), "group/other-writable root accepted")
        XCTAssertEqual(chmod(scratch, 0o700), 0)
        XCTAssertEqual(try RootSafety.existingRoot(scratch), scratch)
    }

    func testOutputFileMustBeTemporary() throws {
        XCTAssertThrowsError(try RootSafety.outputFile(NSHomeDirectory() + "/r3-results.json"))
        XCTAssertEqual(try RootSafety.outputFile(scratch + "/out.json"), scratch + "/out.json")
        XCTAssertThrowsError(try RootSafety.outputFile(scratch + "/"))
        XCTAssertThrowsError(try RootSafety.outputFile(scratch + "/missing/out.json"))
        XCTAssertThrowsError(try RootSafety.outputFile(scratch + "/.."))
    }

    /// The parent is split off at the last "/" byte of the original spelling: a multi-byte
    /// (NFC) name must not shift the cut or be renormalized.
    func testOutputFileKeepsNonASCIINamesByteExact() throws {
        XCTAssertEqual(mkdir(scratch + "/abcde", 0o700), 0)
        let spelling = scratch + "/abcde/\u{e9}\u{e9}\u{e9}"
        let path = try RootSafety.outputFile(spelling)
        XCTAssertEqual(Array(path.utf8), Array(spelling.utf8))
        let decomposed = scratch + "/abcde/e\u{301}"
        XCTAssertEqual(Array(try RootSafety.outputFile(decomposed).utf8), Array(decomposed.utf8))
    }
}
