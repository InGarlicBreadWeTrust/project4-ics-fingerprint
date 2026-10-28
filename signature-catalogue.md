# Signature Catalogue — starter (passive-only, permissive)

*V1 starter. Each entry is a passive detector: it matches fields the **device
already emitted** in observed traffic. **No entry causes a request/response.* Every
match carries a **confidence tier** (L0–L3, see `detection-methodology.md §4`) and
evidence (field offsets) for audit.

Format per entry:
```
name: <protocol/role>
transport: <L3/L4 + IANA port(s) + EtherType>
detect:  <passive match rule — magic / structure / fields — NEVER an active request>
fingerprint_fields: <fields read from observed packets only>
role_hints: <PLC/RTU/HMI/server/gateway/sensor>
confidence: <base tier; how many signals for L2+>
notes: <passive-only caveats, gotchas, OUI/family linkage>
status: <starter>
license: <Apache-2.0; this file is data we own>
```

---

## A. Field / fieldbus & SCADA protocols

### Modbus-TCP
```
transport: TCP/502 (non-standard seen: 502–503, 20502). 
detect: L0 = port 502; L1 = MBAP header: protocol_id==0x0000 AND len==1 byte +
        unit_id + PDU len (byte[7]==byte[6]); FC byte in {0x01,0x02,0x03,0x04,
        0x05,0x06,0x0F,0x10}; exception FC = FC|0x80. L2 = consistent FC grammar
        + unit-id + request/response pairing.
fingerprint_fields: unit_id (unit/function address), function-code profile
        (read-only vs read-write => PLC vs historian), poll cadence.
role_hints: master=scanner/HMI/SCADA (initiates+polls); slave=PLC/RTU (responds).
confidence: L1 (port+MBAP); L2 (FC grammar+pairing across many tx).
notes: No-auth by design → "control traffic with no authentication" is a
        finding (IEC 62443 FR1 / T0842). Cleartext. Read vs write distinction is
        a high-value passive signal. NEVER send a Modbus request — read only the
        PDU already on the wire.
status: starter
```

### Siemens S7comm (S7) over COTP/TPKT
```
transport: TCP/102. 
detect: L1 = TPKT magic (L0: 0x03 0x00 <len2>) then COTP (0x11/0x16/0x17) then
        S7 header (0x32 0x01/0x02 PDU length, 0x33/0x34 protocol id). L2 =
        job/ack PDU pairing; unit-id + slot + rack + db/item. 
fingerprint_fields: slot/rack/DB-number/item, PDU length profile, S7 protocol
        id (0x32=S1/2 comm? actually 0x32/0x33 are S7 protocol id 0x32). 
role_hints: master=SCADA/PLC-programmer; slave=S7 PLC (S7-300/400/1200/1500).
confidence: L1 (TPKT+COTP); L2 (job/ack PDU grammar).
notes: Siemens OUI (00:30:30 / 50:0E:… range) cross-validates family. No-auth
        on comm channel → finding. Never originate an S7 job/ack.
status: starter
```

### DNP3 (Data NaviGation Protocol 3.0)
```
transport: UDP/20000 and/or TCP/20000. 
detect: L1 = start bytes 0x5A 0x5A AND length byte consistent (0x5A<<7 | len<=300;
        0x5A 0x5A for len). L2 = ASDU type/codes + originator + source/dest addr +
        cause-of-transmission (spontaneous vs polled). 
fingerprint_fields: originator address + source/dest station; link + application
        layer; ASDU profile (analog/binary/trend).
role_hints: master=RTU/HMI/SCADA; slave=RTU/concentrator.
confidence: L1 (0x5A 0x5A + len); L2 (ASDU + CoT grammar).
notes: CoT "spontaneous unscheduled" => event (alarm); periodic polled =>
        routine. Good passive "is this RTU alarming now" signal. No-auth → finding.
status: starter
```

### IEC 60870-5-104 (SCADA/RTU TCP)
```
transport: TCP/2404 (also 0–1023 custom seen). 
detect: L1 = control field APDU length (2 bytes, = payload+2) + control field byte
        (I-format 0x…01, S-format 0x…10… , U-format 0xE4/0xF0). L2 = type-ID +
        ASDU info; common address (COS/CA). 
fingerprint_fields: common-addr (station), type-id profile, spontaneous-I
        (event) vs S-format (keep-alive).
role_hints: master=SCADA; slave=RTU.
confidence: L1 (APDU + control field); L2 (type-id + ASDU).
notes: S-format keep-alive + periodic I-format => "alive & polling."
status: starter
```

### EtherNet/IP (CIP) / ENIP
```
transport: TCP/44818 (and/UDP 22 CIP for encapsulated; 44818 ENIP over TCP). 
detect: L1 = ENIP Encapsulation header: command code 0x00000005 + vendor/id
        fields (0x0001 vendor = Rockwell/Siemens/etc.) when payload>0. CIP
        EtherNet (0x6F EtherType 0x8892 for PROFINET see below). 
fingerprint_fields: vendor id, path/attribute, command sequence.
role_hints: controller=PLC; gateway/EPICS/SCADA = client.
confidence: L1 (Encapsulation command 0x05); L2 (CIP command grammar).
notes: Common on Rockwell Allen-Bradley. No-auth default on many => finding.
status: starter
```

### OPC-UA (open platform communications unified architecture)
```
transport: TCP/4840 (HTTPS) or TCP/other; also MQTT for publish. 
detect: L1 = OPC-UA header 10-byte (message-type byte 'O'/'A'/'V'/'S' +
        chunk-type + version 0x00 + total-length). L2 = RequestId/ResponseId
        pairing, request type code (OpType 0x0001…), service ids 
        (Read 0x000a, Browse 0x0062, ReadNodeAttributes…). L3 = server
        identity from GetEndpoints (endpoint URL, certificate subject) — but only
        if a real client already requested it in-window (we read the response, not
        the request we originate).
fingerprint_fields: server endpoint URL + version + certificate subject.
role_hints: server=engineering/HMI/SCADA; client=PLC/edge-gateway.
confidence: L1 (header magic); L3 (endpoint identity, if observed as response).
notes: SecurityMode=NONE / no cert in observed traffic is a strong finding
        (T0861/T0874). Never send a FindServer or GetEndpoints.
status: starter
```

### BACnet (building automation; water/HVAC in co-ops & plants)
```
transport: UDP/47808 (BACnet/IP) and/or TCP/47809 (NPDU). 
detect: L1 = version byte 0x01 + APDU; NPDU over TCP (0xc0/0x40). L2 = service
        class/code (Read-Property 0x0E, Who-Is-I-Am, ConfirmData 0x08…),
        object types. 
fingerprint_fields: source/dest device-instance (router/source/destination),
        service profile.
role_hints: whois/iam => device identity; property-reads => controller/panel.
confidence: L1 (version+APDU); L2 (service grammar).
notes: BACnet has built-in discovery via Who-Is but we OBSERVE existing
        responses, we don't send Who-Is.
status: starter
```

### HART-IP (Hirschmann)
```
transport: TCP/5090. 
detect: L1 = HART-IP over TCP; application header; L2 = HART comm profile
        (master/field device). 
role_hints: master=RTU; slave=HART field device.
confidence: L1.
notes: Niche; include with L1 confidence only; mark low-confidence.
status: starter
```

### Sparkplug B over MQTT (industrial pub/sub — very common in modern plant)
```
transport: MQTT 1883/8883 (TCP/TLS). Also CoAP/AMQPS. 
detect: L1 = MQTT CONNECT/FIXED-HEADER over TCP; L2 = topic tree "spBv1.0/<
        namespace>/node/<nodeId>/…" + payloads NDJSON with "bq" (birth), "d", 
        "bd" (data), metrics; L3 = nodeId + alias + "bq" birth-qualifier = device
        identity.
fingerprint_fields: namespace, nodeId, device-type (from d/bq), metric names.
role_hints: node=PLC/edge-gateway; the node that publishes "bq" births is an
        edge/gateway; a node publishing many metrics under a parent is a plant.
confidence: L1 (MQTT); L3 (Sparkplug topic + birth).
notes: MQTT often cleartext/ unauthenticated at 1883 → finding. "bq" births are
        a great passive device-enumeration signal.
status: starter
```

### IEC 61850 MMS / GOOSE / Sampled Values
```
transport: MMS = TCP/101 (or 102) ASN.1 BER (X.690); GOOSE & SV on Ethernet.
detect MMS: L1 = ASN.1 BER over TCP (0x60/0xA0/0x45/0x85 tags) + MMS PDU. 
detect GOOSE: EtherType 0x88B8; AppID + AppID; L1 magic. 
detect SV : EtherType 0x88BA; appid + config; sampling rate.
fingerprint_fields: MMS device identity (Logical Node / DataSet / IED name,
        "deviceDescription" via ACSI — observe only); GOOSE/SV AppID + IED.
role_hints: GOOSE/SV = substation automation (IEDs, relays, PMU/FTU/MU); MMS =
        IED/control.
confidence: L1 (EtherType magic; MMS BER); L2 (GOOSE/SV AppID + IED).
notes: **GOOSE & SV are 1-2 Hz / high-rate; capture must keep up or you miss
        them — resource bound (§6 of SAFETY-POLICY). IEDs often lack auth — 
        finding.
status: starter
```

### IEEE C37.118 (Synchrophasor / PMU — the rural-co-op-relevant one)
```
transport: UDP/24001. 
detect: L1 = PDU header 16 bytes: PDU type (0x11=118 v1, 0x04/0x01/0x02…) +
        sequence number + time-stamp (64-bit). L2 = SOE/phasor data set.
fingerprint_fields: sequence, time source (sync), data type (1=phasors,
        0x11=events).
role_hints: publisher=PMU/FTU/MU/receiver; receiver=SCADA.
confidence: L1 (PDU type+len); L2 (frame body).
notes: Common in distribution/energy; a 25/50 Hz or PTP-synced 1s PDU stream
        is a strong passive "PMU is here & streaming" signal.
status: starter
```

---

## B. IT baseline (is IT on the OT network?)

### SNMP
```
transport: UDP/161 (get/getnext/next), UDP/162 (traps), TCP/161/162. 
detect: L1 = SNMP community string / version byte; L2 = MIB; L3 = sysDescr /
        sysObjectID / sysName => **vendor + model + OS** (classic passive 
        identity — but only read the *response* the device already sent, NOT a
        request we issue).
fingerprint_fields: sysDescr → vendor+model; sysObjectID; sysName (hostname).
role_hints: router/switch/PLC/RTU with SNMP.
confidence: L1 (SNMP framing); L3 (sysDescr/sysObjectID).
notes: sysDescr leaks full identity — gold passive signal. Cleartext community
        strings "public"/"private" => finding.
status: starter
```

### TCP/IP passive fingerprint (p0f-style, derived)
```
transport: any TCP/UDP. 
detect: TTL class (0/64/128/255 → OS family), initial window size, TCP options
        (MSS/WS/timestamp/SACK), IPID behaviour, DF/TCE — all read from
        existing packets. 
fingerprint_fields: OS class (Linux/Windows/Embedded), vendor.
role_hints: "embedded" / "ARM" hint => embedded controller/gateway.
confidence: L1–L2.
notes: Like p0f, derived from observed packets (not a probe). No active probe.
status: starter
```

### DNS / HTTP / DNS-over-TCP
```
transport: DNS 53/UDP+TCP; HTTP/HTTPS 80/443. 
detect: L1 framing. L2 = HTTP Server/User-Agent banner (observe existing, not
        requested) → server/OS/software identity; DNS = hostname resolution
        (passive "what's registered / beaconing"). 
fingerprint_fields: HTTP Server/User-Agent; response body version banners.
role_hints: server = HMI/web server; periodic unknown-internet DNS = 
        possible C2 / exfil — finding.
confidence: L1–L2.
notes: HTTP banner is gold passive identity; only read what's already on wire.
status: starter
```

---

## C. OUI / vendor (L2/L3 identity)

```
OUI lookups: L2 MAC address first 3 bytes → vendor + device-class from IEEE/IANA
   vendor OUI registry. OUI is ONE signal (collisions known — see detection-
   methodology §5 "anti-mis-ID rule"); never classified to a specific product
   from OUI alone; OUI class + protocol/family cross-validate.
OUI data source & license: see license-assessment.md § (choose a permissive/MIT
   OUI list, or derive from IEEE registry; pin + checksum version).
status: starter (data pending license pick)
```

---

## D. Catalogue maintenance rules

1. **Passive-only:** a signature is *rejected* in code-review if it requires the
   tool to originate any request (banner grab, SNMP get we initiate, "ping", a
   "safe" active probe). The CI in `build-approach.md` statically forbids it.
2. **Every signature declares its confidence tier** and its **evidence fields**
   (offsets) so a finding is reproducible & auditable.
3. **Confidential/credential fields are redacted** at output time
   (SAFETY-POLICY §8), not stored in clear.
4. **Catalogue is version + checksum-pinned** so a re-run is reproducible (§8 of
   detection-methodology).
5. **Add a protocol with a passive-only proof:** each new entry must ship a
   "passive-only proof" test (runs on a PCAP, matches via observed fields,
   emits zero egress). No entry without its proof.
6. **False-positive control:** L0/L1 matches are "candidates"; only L2/L3 (or
   cross-validated) become asserted. OUI collisions → class, not product.

## E. Coverage & gaps (for stakeholders)

- **Not covered (gaps to note):** proprietary/binary-only control
   protocols with no public signature (some OEM PLCs) — flagged as "unknown,
   needs signature." Proprietary IEC 61850 GOOSE with vendor-specific AppIDs.
- **Flow-feed limits (Tier 2):** payload-less flows can't do L2/L3 app-layer;
   those entries degrade to L0 (port) + entropy — marked accordingly.
- **Signature currency:** ICS protocol versions drift; catalog is a rolling
   effort. Recommend a "signature update only via vetted PR, permissive-licensed,
   passive-proof-checked" cadence — never a download-at-runtime (no phone-home,
   SAFETY-POLICY §8).
