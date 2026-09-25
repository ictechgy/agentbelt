import Foundation


/// The single entry point File Guard uses for both the ES callback and XPC control.
///
/// The registry rejects a clock that goes backwards (`clock_regression`, "invalid or
/// regressed clock"). Two threads that read a monotonic clock and then race for the
/// registry lock can still arrive out of order, so the clock is read inside this lock.
public final class ClockedRegistry: @unchecked Sendable {
    public let registry: Registry
    private let clock: @Sendable () -> Int64
    private let lock = NSLock()

    public init(registry: Registry, clock: @escaping @Sendable () -> Int64) {
        self.registry = registry
        self.clock = clock
    }

    public func run<T>(_ body: (Registry, Int64) throws -> T) rethrows -> T {
        lock.lock()
        defer { lock.unlock() }
        return try body(registry, clock())
    }
}
