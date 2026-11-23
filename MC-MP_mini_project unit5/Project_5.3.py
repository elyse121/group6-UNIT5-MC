"""
Mini Project 5.3: Privacy-compliance checklist tool for a hypothetical mobile app
Frameworks: GDPR, CCPA/CPRA, LGPD, DPDP Act.  Python 3, standard library only.

Hypothetical app: "RideNow", a ride-hailing app.

Run:  python project_5.3.py
"""

# --------------------------------------------------------------------
# 1. App data profile (declared practices)
# --------------------------------------------------------------------
# consent: "opt-in" | "opt-out" | "bundled" | "none"
# basis  : "consent" | "contract" | "legitimate_interest" | "none"
PRACTICES = [
    dict(id="P1", category="Precise location", purpose="Match riders with drivers",
         basis="contract", consent="bundled", retention_days=90, shared=False, sold=False,
         sensitive=True, notice=True, withdraw_easy=False, opt_out_link=False, limit_link=False),
    dict(id="P2", category="Precise location (background)", purpose="Ad targeting",
         basis="none", consent="bundled", retention_days=730, shared=True, sold=True,
         sensitive=True, notice=True, withdraw_easy=False, opt_out_link=False, limit_link=False),
    dict(id="P3", category="Contacts list", purpose="Friend referrals",
         basis="consent", consent="opt-in", retention_days=180, shared=False, sold=False,
         sensitive=False, notice=True, withdraw_easy=True, opt_out_link=False, limit_link=False),
    dict(id="P4", category="Usage analytics", purpose="Product improvement",
         basis="legitimate_interest", consent="opt-out", retention_days=365, shared=False, sold=False,
         sensitive=False, notice=True, withdraw_easy=True, opt_out_link=True, limit_link=False),
    dict(id="P5", category="Advertising identifier", purpose="Cross-app advertising",
         basis="none", consent="opt-out", retention_days=None, shared=True, sold=True,
         sensitive=False, notice=True, withdraw_easy=False, opt_out_link=False, limit_link=False),
    dict(id="P6", category="Biometric (face check for driver ID)", purpose="Identity verification",
         basis="consent", consent="bundled", retention_days=365, shared=False, sold=False,
         sensitive=True, notice=True, withdraw_easy=False, opt_out_link=False, limit_link=False),
]

OK, GAP, NA = "compliant", "gap", "n/a"


# --------------------------------------------------------------------
# 2. Rule sets (each rule returns (status, reason, fix))
# --------------------------------------------------------------------
def gdpr(p):
    r = []
    if p["basis"] == "none" or (p["basis"] == "consent" and p["consent"] != "opt-in"):
        r.append((GAP, "No affirmative lawful basis; consent must be opt-in, not bundled/opt-out",
                  "Use a separate, unticked opt-in dialog (or a valid basis such as contract)"))
    else:
        r.append((OK, "Lawful basis present", ""))
    if p["sensitive"] and p["consent"] != "opt-in" and p["basis"] != "contract":
        r.append((GAP, "Location/biometric data needs explicit opt-in consent",
                  "Add an explicit opt-in step before collection"))
    if p["retention_days"] is None:
        r.append((GAP, "No defined retention period (storage limitation)", "Define and publish a retention limit"))
    elif p["retention_days"] > 365 and p["basis"] != "contract":
        r.append((GAP, "Retention appears longer than the purpose needs", "Shorten retention or document justification"))
    if p["shared"] and p["basis"] == "none":
        r.append((GAP, "Third-party sharing without lawful basis", "Obtain opt-in consent before sharing"))
    return r


def ccpa(p):
    r = []
    if p["sold"] or p["shared"]:
        if not p["opt_out_link"]:
            r.append((GAP, "Sale/sharing requires an opt-out ('Do Not Sell or Share') mechanism",
                      "Add a Do Not Sell or Share My Personal Information link/setting"))
        else:
            r.append((OK, "Opt-out for sale/sharing provided", ""))
    else:
        r.append((NA, "No sale or sharing; opt-out rule not triggered", ""))
    if p["sensitive"] and p["category"].lower().startswith("precise location") and not p["limit_link"]:
        r.append((GAP, "Precise geolocation is sensitive personal information; no right-to-limit option",
                  "Add a 'Limit the Use of My Sensitive Personal Information' control"))
    if not p["notice"]:
        r.append((GAP, "Missing notice at collection", "Show categories and purposes at collection"))
    if p["retention_days"] is None:
        r.append((GAP, "Retention period not disclosed", "Disclose retention per category"))
    return r


def lgpd(p):
    r = []
    if p["basis"] == "none":
        r.append((GAP, "No valid legal basis (LGPD Art. 7 analogue of GDPR)", "Assign consent, contract or legitimate interest"))
    elif p["basis"] == "consent" and p["consent"] != "opt-in":
        r.append((GAP, "Consent must be free, informed and specific; bundled consent is invalid",
                  "Collect separate, purpose-specific consent"))
    else:
        r.append((OK, "Valid legal basis", ""))
    if p["sensitive"] and "biometric" in p["category"].lower() and p["consent"] != "opt-in":
        r.append((GAP, "Sensitive data (biometric) needs specific, highlighted consent",
                  "Use a dedicated biometric consent screen"))
    if p["shared"] and not p["notice"]:
        r.append((GAP, "Sharing not disclosed to the data subject", "Disclose recipients"))
    return r


def dpdp(p):
    r = []
    if p["consent"] == "opt-in" and p["notice"]:
        r.append((OK, "Clear notice and consent by the Data Principal", ""))
    elif p["basis"] == "contract" and p["purpose"] in ("Match riders with drivers",):
        r.append((OK, "Plausible 'legitimate use' (service requested by the Data Principal)", ""))
    else:
        r.append((GAP, "Needs clear notice + consent from the Data Principal, or a defined legitimate use",
                  "Show itemised notice and take free, specific, unambiguous consent"))
    if p["basis"] == "consent" and not p["withdraw_easy"]:
        r.append((GAP, "Data Principal must be able to withdraw consent as easily as giving it",
                  "Add a one-tap consent withdrawal in settings"))
    if p["retention_days"] is None:
        r.append((GAP, "Data Fiduciary has no erasure/retention rule once purpose is served",
                  "Erase data when the purpose is fulfilled"))
    return r


FRAMEWORKS = {"GDPR": gdpr, "CCPA/CPRA": ccpa, "LGPD": lgpd, "DPDP Act": dpdp}


def worst(results):
    sts = [s for s, _, _ in results]
    if GAP in sts:
        return GAP
    return NA if all(s == NA for s in sts) else OK


# --------------------------------------------------------------------
# 3. Run checklist and print gap report
# --------------------------------------------------------------------
def priority(p):
    score = 0
    if p["sensitive"]:
        score += 2
    if p["shared"] or p["sold"]:
        score += 2
    return score


def main():
    print("RideNow - privacy compliance checklist\n")
    print(f"{'ID':4} {'Data practice':36}" + "".join(f"{f:12}" for f in FRAMEWORKS))
    print("-" * (40 + 12 * len(FRAMEWORKS)))
    gaps = []   # (priority, practice, framework, reason, fix)
    for p in PRACTICES:
        row = f"{p['id']:4} {p['category'][:35]:36}"
        for name, fn in FRAMEWORKS.items():
            res = fn(p)
            row += f"{worst(res):12}"
            for s, reason, fix in res:
                if s == GAP:
                    gaps.append((priority(p), p, name, reason, fix))
        print(row)

    print("\n=== GAP REPORT PER FRAMEWORK ===")
    for name in FRAMEWORKS:
        items = [g for g in gaps if g[2] == name]
        print(f"\n{name}: {len(items)} gap(s)")
        for _, p, _, reason, _ in items:
            print(f"  [{p['id']}] {p['category']}: {reason}")

    print("\n=== PRIORITISED REMEDIATION (sensitive data and third-party sharing first) ===")
    for n, (pr, p, name, reason, fix) in enumerate(sorted(gaps, key=lambda g: -g[0]), 1):
        print(f"{n:2}. (priority {pr}) [{p['id']} {p['category']}] {name}: {fix}")


if __name__ == "__main__":
    main()