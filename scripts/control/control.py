#!/usr/bin/env python3
import frida, sys, argparse, json, time, os

OUT = None
PKG = None
PIDS = set()

def now():
    return time.strftime('%Y-%m-%dT%H:%M:%S')

def log_event(payload):
    print("[event]", json.dumps(payload, ensure_ascii=False))
    if OUT:
        OUT.write(json.dumps({"ts": now(), "pkg": PKG, **payload}, ensure_ascii=False) + "\n")
        OUT.flush()

def on_message(message, data):
    t = message.get("type")
    if t == "send":
        log_event(message["payload"])
    elif t == "error":
        print("[error]", message.get("stack", message))
    else:
        print("[msg]", message)

def load_scripts(session, scripts):
    for path in scripts:
        with open(path, "r", encoding="utf-8") as f:
            s = session.create_script(f.read())
        s.on("message", on_message)
        s.load()

def main():
    ap = argparse.ArgumentParser(description="Frida control (spawn/attach, spawn-gating, NDJSON logging)")
    ap.add_argument("-p","--package", required=True, help="Android package or running process identifier")
    ap.add_argument("-s","--script", required=True, help="Main JS to load inside target")
    ap.add_argument("--also", action="append", default=[], help="Load extra JS (can repeat)")
    ap.add_argument("--mode", choices=["recon","precision","aggressive"], default="recon")
    ap.add_argument("--outfile", help="Write NDJSON events to file")
    ap.add_argument("--attach", action="store_true", help="Attach to running process")
    ap.add_argument("--spawn", dest="spawn", action="store_true", help="Spawn the package")
    ap.add_argument("--no-spawn", dest="spawn", action="store_false", help="Do not spawn the package")
    ap.set_defaults(spawn=True)
    ap.add_argument("--spawn-gating", action="store_true", help="Instrument child spawns automatically")
    args = ap.parse_args()

    global OUT, PKG
    PKG = args.package
    if args.outfile:
        OUT = open(args.outfile, "a", encoding="utf-8")

    device_id = os.environ.get("DEVICE_ID")
    if device_id:
        device = frida.get_device_manager().get_device(device_id, timeout=5)
    else:
        device = frida.get_usb_device(timeout=5)

    # Modes
    if args.mode == "aggressive":
        args.spawn = True
        args.spawn_gating = True
    elif args.mode == "precision":
        args.attach = True

    scripts = [args.script] + args.also

    def handle_spawn(spawn):
        try:
            sess = device.attach(spawn.pid)
            load_scripts(sess, scripts)
            device.resume(spawn.pid)
            PIDS.add(spawn.pid)
            ident = getattr(spawn, "identifier", "?")
            log_event({"ev":"spawn-attached", "pid": int(spawn.pid), "id": ident})
        except Exception as e:
            print("[spawn-handler-error]", e)

    if args.spawn_gating:
        device.enable_spawn_gating()
        device.on("spawn-added", handle_spawn)

    try:
        if args.attach or not args.spawn:
            target = None
            for p in device.enumerate_processes():
                if p.identifier == PKG or p.name == PKG:
                    target = p; break
            if not target:
                print("[!] process not found:", PKG); sys.exit(1)
            sess = device.attach(target.pid)
            load_scripts(sess, scripts)
            PIDS.add(target.pid)
        elif args.spawn:
            pid = device.spawn([PKG])
            if not args.spawn_gating:
                sess = device.attach(pid)
                load_scripts(sess, scripts)
                device.resume(pid)
            PIDS.add(pid)

        print("[+] ready. CTRL+C to exit.")
        while True: time.sleep(0.2)
    except KeyboardInterrupt:
        pass
    finally:
        if OUT:
            OUT.close()

if __name__ == "__main__":
    main()
