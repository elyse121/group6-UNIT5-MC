"""
Mini Project 5.1: Cellular-style mutual authentication + signaling-plane anomaly detection
Python 3, standard library only. Everything is simulated in memory.

Run:  python project_5.1.py
"""
import hashlib
import hmac
import random
import secrets

# =====================================================================
# PART A: Challenge-response authentication (GSM A3/A8 / AKA-inspired)
# =====================================================================

def generate_rand():
    """Fresh 16-byte random challenge (RAND). Called only by HomeNetwork."""
    return secrets.token_bytes(16)


def compute_response(K, RAND):
    """Simplified A3-style function: SRES/RES = HMAC-SHA256(K, RAND)."""
    return hmac.new(K, RAND, hashlib.sha256).digest()


def derive_session_key(K, RAND):
    """Distinct label => session key is cryptographically separate from the
    response (like AKA deriving RES, CK, IK separately from one secret)."""
    return hmac.new(K, b"SESSIONKEY" + RAND, hashlib.sha256).digest()


def compute_network_token(K, RAND):
    """AUTN-like token so the network proves itself to the device (Lab Task 3)."""
    return hmac.new(K, b"AUTN" + RAND, hashlib.sha256).digest()


class Device:
    """Stands in for the SIM/USIM: holds K, never transmits it."""
    def __init__(self, K):
        self._K = K
        self.session_key = b""

    def respond(self, RAND, autn=None):
        # Mutual authentication: verify the network first, if a token is supplied.
        if autn is not None:
            if not hmac.compare_digest(autn, compute_network_token(self._K, RAND)):
                raise ValueError("Network authentication failed (bad AUTN)")
        self.session_key = derive_session_key(self._K, RAND)
        return compute_response(self._K, RAND)


class HomeNetwork:
    """Stands in for the operator's Authentication Center."""
    def __init__(self, K):
        self._K = K
        self.used_rands = set()      # replay protection (Lab Task 1)
        self.session_key = b""

    def start_auth(self):
        RAND = generate_rand()
        while RAND in self.used_rands:   # never reuse a RAND
            RAND = generate_rand()
        self.used_rands.add(RAND)
        return RAND, compute_network_token(self._K, RAND)

    def verify(self, RAND, response):
        expected = compute_response(self._K, RAND)
        if hmac.compare_digest(expected, response):
            self.session_key = derive_session_key(self._K, RAND)
            return True
        return False

    def verify_checked_replay(self, RAND, response, issued_rands):
        """Reject a RAND that was already consumed successfully."""
        if RAND in issued_rands:
            return False
        return self.verify(RAND, response)


class Attacker:
    """Sees only RAND and response that crossed the channel. No access to K."""
    def __init__(self, observed_rand, observed_response):
        self.rand = observed_rand
        self.resp = observed_response

    def replay_old_response(self, new_rand):
        return self.resp

    def guess_key_by_inspection(self, new_rand):
        # Naive guess: treat the observed response as if it were the key.
        return compute_response(self.resp, new_rand)


def part_a():
    print("=" * 60)
    print("PART A: Mutual authentication simulation")
    print("=" * 60)
    K = secrets.token_bytes(32)          # shared secret, never sent
    device, network = Device(K), HomeNetwork(K)

    # --- Successful run (with network-to-device authentication) ---
    RAND, AUTN = network.start_auth()
    response = device.respond(RAND, AUTN)      # device checks AUTN first
    ok = network.verify(RAND, response)
    print(f"RAND sent         : {RAND.hex()}")
    print(f"Device response   : {response.hex()[:32]}...")
    print(f"Authentication OK : {ok}")
    print(f"Session keys equal: {hmac.compare_digest(device.session_key, network.session_key)}")
    print("K and session key were never part of any 'sent' message.\n")

    # --- Attacker with one observed pair, new challenge ---
    attacker = Attacker(RAND, response)
    RAND2, AUTN2 = network.start_auth()
    real = compute_response(K, RAND2)
    print("Attacker holds one RAND/response pair, faces new RAND2:")
    print(f"  replay old response matches? {hmac.compare_digest(attacker.replay_old_response(RAND2), real)}")
    print(f"  key-guess response matches?  {hmac.compare_digest(attacker.guess_key_by_inspection(RAND2), real)}")
    print(f"  network accepts replayed response? {network.verify(RAND2, attacker.replay_old_response(RAND2))}")
    # Why this is infeasible: HMAC-SHA256 is a one-way keyed pseudorandom function,
    # so observed (input, output) pairs reveal neither K nor the output for an
    # unseen input.

    # --- Lab Task 1: replay with RAND tracking ---
    print("\nReplay of a fully valid old (RAND, response) pair:")
    print(f"  without tracking: accepted = {network.verify(RAND, response)}  (RAND reuse is the danger)")
    consumed = {RAND}
    print(f"  with RAND tracking: accepted = {network.verify_checked_replay(RAND, response, consumed)}")
    print("  Parallel: real AKA uses a sequence number (SQN) in AUTN so the USIM rejects stale challenges.")

    # --- Lab Task 3: a fake network is rejected by the device ---
    print("\nRogue network (does not know K) tries to authenticate to the device:")
    try:
        device.respond(generate_rand(), secrets.token_bytes(32))
    except ValueError as e:
        print(f"  Device refused: {e}")
    print("  GSM's one-way A3 could not do this => fake base stations were possible;")
    print("  UMTS/LTE/5G AKA adds AUTN so the network must prove itself too.")

    print("\nLab Task 4: ways this simplifies real 5G AKA:")
    for item in [
        "No SUCI: the subscriber identity is not concealed with asymmetric encryption.",
        "No MILENAGE/TUAK: HMAC-SHA256 replaces the standardized f1-f5 algorithms.",
        "No anonymity key (AK) and no SQN resynchronisation (AUTS) handling.",
        "No key hierarchy (KAUSF/KSEAF/KAMF, separate NAS/AS keys); one flat session key.",
    ]:
        print("  -", item)


# =====================================================================
# PART B: Rule-based signaling-plane IDS over a synthetic log
# =====================================================================

ALLOWED_EVENTS = {"attach", "location_update", "auth_request"}
REQUIRED_FIELDS = ("timestamp", "subscriber_id", "event_type", "country")
HOME_COUNTRY = {"S1": "ZA", "S2": "KE", "S3": "RW", "S4": "NG", "S5": "ZA",
                "S6": "UG", "S7": "TZ", "S8": "KE"}


def generate_signaling_log(n, seed=None):
    """Mostly plausible events + injected anomalies. Returns (log, injected)."""
    rng = random.Random(seed)
    subs = list(HOME_COUNTRY)
    per_sub = max(2, n // len(subs))
    log = []
    last_ts = {}
    for s in subs:
        t = rng.randint(0, 600)
        for _ in range(per_sub):
            t += rng.randint(900, 3600)          # 15-60 min between events
            log.append({"timestamp": t, "subscriber_id": s,
                        "event_type": rng.choice(sorted(ALLOWED_EVENTS)),
                        "country": HOME_COUNTRY[s]})
        last_ts[s] = t
    log.sort(key=lambda e: e["timestamp"])
    injected = {}

    # 1) implausible roaming: ZA event, then US only 10 minutes later
    t = last_ts["S1"]
    log.append({"timestamp": t + 600, "subscriber_id": "S1",
                "event_type": "location_update", "country": "US"})
    injected["implausible_travel"] = "S1 ZA -> US in 10 minutes"

    # 2) malformed: missing field + invalid event_type
    log.append({"timestamp": last_ts["S2"] + 100, "subscriber_id": "S2",
                "event_type": "attach"})                      # no country
    log.append({"timestamp": last_ts["S3"] + 100, "subscriber_id": "S3",
                "event_type": "hack_request", "country": "RW"})
    injected["malformed"] = "S2 missing country; S3 invalid event_type"

    # 3) burst of auth_requests
    base = last_ts["S4"] + 500
    for i in range(12):
        log.append({"timestamp": base + i * 2, "subscriber_id": "S4",
                    "event_type": "auth_request", "country": "NG"})
    injected["auth_burst"] = "S4 12 auth_request events in ~24 s"

    # 4) non-monotonic timestamp (log order says later, timestamp says earlier)
    log.append({"timestamp": last_ts["S5"] - 5000, "subscriber_id": "S5",
                "event_type": "attach", "country": "ZA"})
    injected["non_monotonic"] = "S5 event with timestamp earlier than previous"
    return log, injected


def detect(log, min_travel_s=3 * 3600, burst_window_s=60, burst_max=5):
    flags = []   # (log_index, event, rule)
    bad_idx = set()

    # Rule 1: schema / conformance
    for i, e in enumerate(log):
        missing = [f for f in REQUIRED_FIELDS if f not in e]
        if missing:
            flags.append((i, e, f"schema: missing {missing}"))
            bad_idx.add(i)
        elif e["event_type"] not in ALLOWED_EVENTS:
            flags.append((i, e, f"schema: invalid event_type '{e['event_type']}'"))
            bad_idx.add(i)

    # group valid events per subscriber (keeping log index)
    by_sub = {}
    for i, e in enumerate(log):
        if i not in bad_idx:
            by_sub.setdefault(e["subscriber_id"], []).append((i, e))

    for sub, items in by_sub.items():
        # Rule 2: implausible travel (sort by time, flag country change too fast)
        ordered = sorted(items, key=lambda x: x[1]["timestamp"])
        for (_, a), (j, b) in zip(ordered, ordered[1:]):
            gap = b["timestamp"] - a["timestamp"]
            if a["country"] != b["country"] and gap < min_travel_s:
                flags.append((j, b, f"implausible_travel: {a['country']}->{b['country']} in {gap}s"))

        # Rule 3: auth_request rate per subscriber (sliding window)
        auth = [(i, e) for i, e in ordered if e["event_type"] == "auth_request"]
        flagged_burst = False
        for k in range(len(auth)):
            window = [x for x in auth[k:] if x[1]["timestamp"] - auth[k][1]["timestamp"] <= burst_window_s]
            if len(window) >= burst_max and not flagged_burst:
                idx, ev = window[burst_max - 1]
                flags.append((idx, ev, f"auth_rate: >={burst_max} auth_request in {burst_window_s}s"))
                flagged_burst = True

        # Rule 4 (Lab Task 6): non-monotonic timestamps in LOG order
        prev = None
        for i, e in items:
            if prev is not None and e["timestamp"] < prev:
                flags.append((i, e, "non_monotonic: timestamp earlier than previous log entry"))
            prev = e["timestamp"] if prev is None else max(prev, e["timestamp"])
    return sorted(flags, key=lambda f: f[0])


def part_b():
    print("\n" + "=" * 60)
    print("PART B: Signaling-plane anomaly detection")
    print("=" * 60)
    log, injected = generate_signaling_log(80, seed=42)
    print(f"Log size: {len(log)} events. Injected anomalies:")
    for k, v in injected.items():
        print(f"  [{k}] {v}")
    flags = detect(log)
    print(f"\nDetector flagged {len(flags)} entries:")
    for idx, ev, rule in flags:
        print(f"  #{idx:03d} {ev}  <-- {rule}")

    flagged_subs = {ev.get("subscriber_id") for _, ev, _ in flags}
    print("\nSummary vs injected anomalies:")
    expected = {"S1": "implausible_travel", "S2": "malformed", "S3": "malformed",
                "S4": "auth_burst", "S5": "non_monotonic"}
    for s, kind in expected.items():
        print(f"  {kind:20s} ({s}) detected: {s in flagged_subs}")
    extra = flagged_subs - set(expected)
    print(f"  unexpected subscribers flagged (false positives): {sorted(extra) or 'none'}")

    # Lab Task 5: threshold tuning on a larger log
    print("\nLab Task 5: tuning the travel threshold on a larger log (seed 7)")
    big, _ = generate_signaling_log(800, seed=7)
    for hours in (0.1, 1, 3, 12):
        n = sum(1 for _, _, r in detect(big, min_travel_s=int(hours * 3600)) if r.startswith("implausible_travel"))
        print(f"  threshold {hours:>4} h -> {n} travel flags")
    print("  Too low a threshold misses fast hops (false negatives); too high a threshold")
    print("  flags genuine travel (false positives). Only one planted case exists, so any")
    print("  extra flag at a high threshold is a false positive.")
    print("\nNon-monotonic timestamps may indicate log tampering, replayed/injected")
    print("messages, or clock skew between network elements.")


if __name__ == "__main__":
    part_a()
    part_b()