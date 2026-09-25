// agentbelt File Guard — Endpoint Security system extension, R2 skeleton.
//
// SKELETON MODE: only NOTIFY lineage events are subscribed. No AUTH event is
// subscribed, so this build can neither allow nor deny any operation, and it never
// answers an authorization deadline. Enforcement arrives in R3, after Apple approves
// the ES capability and the registry is ported from task_registry.py.
import EndpointSecurity
import Foundation
import GuardCore
import GuardTransport
import SpawnGate
import os

let log = Logger(subsystem: "dev.agentbelt.fileguard", category: "lifecycle")

// Trust roots come from the Info.plist sealed into this extension's own signature,
// never from Bundle.main (which CFProcessPath can redirect). Unsigned builds stop here.
let configuration: GuardConfiguration
do {
    guard let signedInfo = CodeIdentity.signedInfoOfSelf() else { throw GuardError("no signed Info.plist") }
    configuration = try GuardConfiguration.parse(signedInfo: signedInfo)
} catch {
    log.error("File Guard is not configured; refusing to start")
    exit(EX_CONFIG)
}

let observer = LineageObserver()
var client: OpaquePointer?
let created = es_new_client(&client) { _, message in observer.observe(message) }
guard created == ES_NEW_CLIENT_RESULT_SUCCESS, let client else {
    // ERR_NOT_PRIVILEGED / NOT_ENTITLED / NOT_PERMITTED are expected until approval, root and FDA.
    log.error("es_new_client failed with result \(created.rawValue, privacy: .public)")
    exit(EX_UNAVAILABLE)
}

var ownToken = audit_token_t()
if agb_self_audit_token(&ownToken) != 0 || es_mute_process(client, &ownToken) != ES_RETURN_SUCCESS {
    // Not fatal for NOTIFY-only observation; an AUTH client (R3) must treat it as fatal.
    log.error("could not mute File Guard's own events")
}

let lineageEvents: [es_event_type_t] = [ES_EVENT_TYPE_NOTIFY_FORK, ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_EXIT]
guard es_subscribe(client, lineageEvents, UInt32(lineageEvents.count)) == ES_RETURN_SUCCESS else {
    log.error("es_subscribe failed")
    exit(EX_SOFTWARE)
}

let gate = PeerGate(policy: configuration.policy, oracle: NoRegistryYet())
let control = ControlListener(machServiceName: configuration.machServiceName, gate: gate) { _, _, _ in
    // Refuse rather than pretend: nothing may be launched as protected before R3.
    .failed("registry_not_ported")
}
control.start()

log.info("File Guard skeleton running: NOTIFY lineage only, no authorization")
dispatchMain()
