#!/usr/bin/env python3
"""
m17_ai_bot.py - Talk to an AI over M17 through a Pi-Star hotspot (low-latency version).

  radio -> MMDVMHost -> [this script]
     speech-to-text runs WHILE you talk (c2dec -> Vosk, streamed)
     Claude's answer is streamed; each sentence is spoken as soon as it arrives
     transmission starts after the first sentence, the rest is fed in behind it

This script takes M17Gateway's place on the local UDP link, so stop
m17gateway before running it. Works on Pi-Star 4.1 (Python 3.7).

  sudo systemctl stop m17gateway.timer m17gateway.service
  export ANTHROPIC_API_KEY=sk-ant-...
  python3 m17_gpt.py --src URCALL --vosk-model ~/vosk-model-small-en-us-0.15
  python3 m17_gpt.py --src URCALL --stt-url http://127.0.0.1:8765/transcribe   (Whisper on PC)

ensure you are disconnected from any reflectors. 
"""
import argparse, audioop, json, os, queue, random, re, shutil, socket, struct, subprocess
import sys, tempfile, threading, time, urllib.error, urllib.request, wave

CHARSET = " ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-/."
FRAME_SECONDS = 0.04          # one M17 stream frame = 2 Codec2 3200 frames of 8 bytes

SYSTEM_PROMPT = (
    "You are a friendly voice assistant reached over amateur radio (M17 digital voice on 70 cm) "
    "through the station of {call}. Your replies are converted to speech and heard over a radio, so: "
    "keep answers short, usually one or two sentences and under forty words, unless the user asks "
    "for a story or more detail. Start with the most useful sentence and keep that first sentence "
    "short. No lists, markdown, emojis, URLs or symbols; write numbers and units the way they are "
    "spoken. Talk like a normal helpful voice assistant, not a radio operator: no radio procedure "
    "words such as over, roger, copy, or seventy-three, no signal reports, and no role-playing a "
    "radio contact. The user's words come from a small offline speech recognizer listening through a "
    "low-bitrate digital radio codec, so they are often wrong but SOUND like what was said: treat "
    "them phonetically (for example 'grace napa' is probably 'gray snapper', 'thing report' may be "
    "'fishing report'). Answer the most "
    "likely meaning, and if you had to guess, say what you understood in a few words first. Only ask "
    "the user to repeat if you truly cannot guess. {about}Keep everything appropriate for amateur radio: "
    "no profanity, no music, nothing commercial. Do not say the station callsign yourself; it is "f
    "added automatically."
)

# ---------------------------------------------------------------- M17 helpers
def encode_callsign(cs):
    cs = cs.upper()
    if cs in ("ALL", "@ALL", "BROADCAST"):
        return b"\xff" * 6
    val = 0
    for ch in reversed(cs[:9]):
        idx = CHARSET.find(ch)
        val = val * 40 + (idx if idx >= 0 else 0)
    return val.to_bytes(6, "big")

def decode_callsign(b):
    val = int.from_bytes(b, "big")
    if val == 0xFFFFFFFFFFFF:
        return "ALL"
    if val >= 262144000000000:
        return "?"
    out = ""
    while val:
        out += CHARSET[val % 40]
        val //= 40
    return out.strip()

def crc_m17(data):
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x5935) if crc & 0x8000 else (crc << 1)
            crc &= 0xFFFF
    return crc

def parse_packet(pkt):
    """Return (stream_id, src, dst, fn, payload) or None."""
    if len(pkt) < 54 or pkt[:4] != b"M17 ":
        return None
    sid = struct.unpack(">H", pkt[4:6])[0]
    return sid, decode_callsign(pkt[12:18]), decode_callsign(pkt[6:12]), \
        struct.unpack(">H", pkt[34:36])[0], pkt[36:52]

def transmit_stream(sock, target, chunks, src, dst, can, silence8):
    """Send Codec2 audio from a queue as ONE continuous M17 stream.
    Chunks (bytes, multiples of 8) are appended as they arrive; None ends the stream.
    If the next sentence isn't ready yet, silence is sent so the stream stays open."""
    ftype = 0x0001 | (0b10 << 1) | ((can & 0x0F) << 7)       # voice stream, 3200, CAN
    lsd = encode_callsign(dst) + encode_callsign(src) + struct.pack(">H", ftype) + b"\x00" * 14
    sid = struct.pack(">H", random.randint(1, 0xFFFF))
    buf, done, n = b"", False, 0
    t0 = time.monotonic()
    while True:
        while not done:                                       # grab whatever is ready
            try:
                item = chunks.get_nowait()
            except queue.Empty:
                break
            if item is None:
                done = True
            else:
                buf += item
        if len(buf) < 16:
            if done:
                last = True
                buf += silence8 * ((16 - len(buf)) // 8)
            else:
                last = False
                buf += silence8 * ((16 - len(buf)) // 8)      # gap filler
        else:
            last = done and len(buf) <= 16
        payload, buf = buf[:16], buf[16:]
        fn = (n & 0x7FFF) | (0x8000 if last else 0)
        pkt = b"M17 " + sid + lsd + struct.pack(">H", fn) + payload
        sock.sendto(pkt + struct.pack(">H", crc_m17(pkt)), target)
        n += 1
        if last:
            return n * FRAME_SECONDS
        delay = t0 + n * FRAME_SECONDS - time.monotonic()
        if delay > 0:
            time.sleep(delay)

# ---------------------------------------------------------------- speech-to-text (streaming)
class StreamingSTT:
    """Feed Codec2 payloads as they arrive; Vosk transcribes while you are still talking."""
    def __init__(self, rec):
        self.rec = rec
        self.proc = subprocess.Popen(["c2dec", "3200", "-", "-"], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        self.pcm16k = []
        self.thread = threading.Thread(target=self._reader, daemon=True)
        self.thread.start()

    def _reader(self):
        state, rest = None, b""
        while True:
            data = self.proc.stdout.read1(4096)
            if not data:
                break
            data, rest = rest + data, b""
            if len(data) % 2:
                data, rest = data[:-1], data[-1:]
            up, state = audioop.ratecv(data, 2, 1, 8000, 16000, state)
            self.pcm16k.append(up)
            if self.rec:
                self.rec.AcceptWaveform(up)

    def feed(self, payload):
        try:
            self.proc.stdin.write(payload)
            self.proc.stdin.flush()
        except (BrokenPipeError, ValueError):
            pass

    def finish(self, save_path=None):
        try:
            self.proc.stdin.close()
        except Exception:
            pass
        self.thread.join(timeout=30)
        self.proc.wait(timeout=5)
        res = json.loads(self.rec.FinalResult()) if self.rec else {}
        text = res.get("text", "").strip()
        if save_path:
            with open(save_path, "wb") as f:
                f.write(self.wav_bytes())
        return text

    def wav_bytes(self):
        import io
        bio = io.BytesIO()
        w = wave.open(bio, "wb")
        w.setnchannels(1); w.setsampwidth(2); w.setframerate(16000)
        w.writeframes(b"".join(self.pcm16k)); w.close()
        return bio.getvalue()

def remote_stt(url, wav, hint, timeout=30):
    """Send a WAV to m17_whisper_server.py and return the text."""
    headers = {"Content-Type": "audio/wav"}
    if hint:
        headers["X-Prompt"] = hint.encode("latin-1", "replace").decode("latin-1")
    req = urllib.request.Request(url, data=wav, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode()).get("text", "").strip()

# ---------------------------------------------------------------- text-to-speech
def run(cmd, **kw):
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, **kw)

def strip_c2_header(data):
    # c2enc adds a 7-byte header when the file name ends in .c2; M17 needs raw frames
    return data[7:] if data[:3] == b"\xc0\xde\xc2" else data

def text_to_c2(text, args):
    with tempfile.TemporaryDirectory() as wd:
        wav, raw, c2 = (os.path.join(wd, n) for n in ("tx.wav", "tx.raw", "tx.bit"))
        if args.tts == "piper":
            run([args.piper_bin, "--model", args.piper_model, "--output_file", wav], input=text.encode())
        elif args.tts == "pico":
            run(["pico2wave", "-l", args.pico_lang, "-w", wav, text])
        elif args.tts == "festival":
            run(["text2wave", "-eval", "(%s)" % args.festival_voice, "-o", wav], input=text.encode())
        else:
            run(["espeak-ng", "-v", args.espeak_voice, "-s", "155", "-w", wav, text])
        run(["sox", wav, "-r", "8000", "-c", "1", "-b", "16", "-e", "signed-integer", raw,
             "highpass", "200", "norm", str(args.gain)])
        run(["c2enc", "3200", raw, c2])
        with open(c2, "rb") as f:
            return strip_c2_header(f.read())

def make_silence8():
    with tempfile.TemporaryDirectory() as wd:
        raw, c2 = os.path.join(wd, "s.raw"), os.path.join(wd, "s.bit")
        with open(raw, "wb") as f:
            f.write(b"\x00\x00" * 320)
        run(["c2enc", "3200", raw, c2])
        with open(c2, "rb") as f:
            return strip_c2_header(f.read())[:8]

# ---------------------------------------------------------------- Claude (streaming)
def stream_claude(history, args):
    """Yield text pieces as Claude writes them."""
    body = json.dumps({
        "model": args.model, "max_tokens": 250, "stream": True,
        "system": SYSTEM_PROMPT.format(call=args.src, about=(args.about.strip() + " ") if args.about else ""), "messages": history,
    }).encode()
    req = urllib.request.Request("https://api.anthropic.com/v1/messages", data=body, headers={
        "content-type": "application/json", "x-api-key": args.api_key,
        "anthropic-version": "2023-06-01"})
    with urllib.request.urlopen(req, timeout=60) as r:
        for raw in r:
            line = raw.decode("utf-8", "replace").strip()
            if not line.startswith("data:"):
                continue
            ev = json.loads(line[5:].strip())
            if ev.get("type") == "content_block_delta" and ev["delta"].get("type") == "text_delta":
                yield ev["delta"]["text"]
            elif ev.get("type") == "error":
                raise RuntimeError(ev.get("error"))

SENTENCE_END = re.compile(r"(.+?[.!?])(\s+|$)", re.S)

def sentences(pieces, min_len=25):
    """Group streamed text into speakable sentences (short fragments are merged)."""
    buf = ""
    for p in pieces:
        buf += p
        while True:
            m = SENTENCE_END.match(buf)
            if not m or not m.group(2):
                break
            cut = m.end()
            if len(buf[:cut].strip()) < min_len:
                m2 = SENTENCE_END.match(buf, cut)
                if not m2 or not m2.group(2):
                    break
                cut = m2.end()
            yield buf[:cut].strip()
            buf = buf[cut:]
    if buf.strip():
        yield buf.strip()

# ---------------------------------------------------------------- one reply, pipelined
def reply_pipeline(text_source, args, chunks, result, t_unkey, id_text):
    """Producer thread: text sentences -> Codec2 chunks into the queue."""
    spoken, first = [], True
    try:
        for s in text_source():
            spoken.append(s)
            c2 = text_to_c2(s, args)
            if first:
                print("  first sentence ready %.1fs after unkey" % (time.monotonic() - t_unkey))
                first = False
            chunks.put(c2)
    except Exception as e:
        print("  reply error:", e)
        if not spoken:
            msg = "Sorry, I couldn't reach the A I service."
            spoken.append(msg)
            try:
                chunks.put(text_to_c2(msg, args))
            except Exception:
                pass
    if id_text:
        try:
            chunks.put(text_to_c2(id_text, args))
        except Exception:
            pass
    result["text"] = " ".join(spoken)
    chunks.put(None)

# ---------------------------------------------------------------- main
def main():
    p = argparse.ArgumentParser()
    p.add_argument("--src", required=True, help="callsign the bot transmits under")
    p.add_argument("--dst", default="ALL")
    p.add_argument("--can", type=int, default=0)
    p.add_argument("--allow", default=None, help="comma list of callsigns to answer (default: --src)")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=17011, help="MMDVMHost [M17 Network] LocalPort")
    p.add_argument("--bind-port", type=int, default=17010, help="[M17 Network] GatewayPort")
    p.add_argument("--vosk-model", default=None,
                   help="Vosk model folder (on-Pi STT; used as fallback when --stt-url is set)")
    p.add_argument("--stt-url", default=None,
                   help="Whisper server, e.g. http://127.0.0.1:8765/transcribe")
    p.add_argument("--stt-hint", default=None,
                   help="words Whisper should expect (default: taken from --about)")
    p.add_argument("--model", default="claude-haiku-4-5-20251001")
    p.add_argument("--tts", choices=["espeak", "pico", "festival", "piper"], default=None,
                   help="default: pico if installed, else festival, else espeak")
    p.add_argument("--espeak-voice", default="en-us+f3")
    p.add_argument("--pico-lang", default="en-US", help="en-US or en-GB (both female)")
    p.add_argument("--festival-voice", default="voice_cmu_us_slt_arctic_hts")
    p.add_argument("--piper-bin", default=os.path.expanduser("~/piper/piper"))
    p.add_argument("--piper-model", default=None)
    p.add_argument("--gain", type=float, default=-3.0)
    p.add_argument("--min-seconds", type=float, default=0.6, help="ignore shorter key-ups")
    p.add_argument("--turnaround", type=float, default=0.5, help="minimum pause before replying")
    p.add_argument("--history", type=int, default=10, help="messages of context to keep")
    p.add_argument("--about", default="", help="context about you for the AI, e.g. location and interests")
    p.add_argument("--selftest", metavar="TEXT", default=None,
                   help="no radio: speak TEXT, run it through Codec2 + STT, then ask Claude")
    args = p.parse_args()
    if args.tts is None:
        args.tts = "pico" if shutil.which("pico2wave") else "festival" if shutil.which("text2wave") else "espeak"
    print("Voice engine: %s" % args.tts)

    needed = ["sox", "c2enc", "c2dec"] + [{"espeak": "espeak-ng", "pico": "pico2wave",
               "festival": "text2wave", "piper": args.piper_bin}[args.tts]]
    missing = [t for t in needed if not shutil.which(t)]
    if missing:
        sys.exit("Missing tools: " + ", ".join(missing))
    args.api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not args.api_key and not args.selftest:
        sys.exit("Set ANTHROPIC_API_KEY first.")
    if args.tts == "piper" and not args.piper_model:
        sys.exit("--piper-model is required with --tts piper")
    allow = [c.strip().upper() for c in (args.allow or args.src).split(",") if c.strip()]
    if not args.vosk_model and not args.stt_url:
        sys.exit("Give --stt-url (Whisper on your PC) and/or --vosk-model.")
    hint = args.stt_hint or ("Amateur radio conversation with %s. %s" % (args.src, args.about)).strip()

    rec = None
    if args.vosk_model:
        print("Loading Vosk model...")
        from vosk import Model, KaldiRecognizer, SetLogLevel
        SetLogLevel(-1)
        t = time.monotonic()
        rec = KaldiRecognizer(Model(os.path.expanduser(args.vosk_model)), 16000)
        rec.AcceptWaveform(b"\x00\x00" * 16000)              # warm-up
        rec.FinalResult()
        print("Vosk ready in %.1fs" % (time.monotonic() - t))
    silence8 = make_silence8()
    if args.stt_url:
        print("Checking Whisper server at %s ..." % args.stt_url)
        try:
            empty = StreamingSTT(None)
            empty.finish()
            remote_stt(args.stt_url, empty.wav_bytes(), hint, timeout=10)
            print("Whisper server OK")
        except Exception as e:
            print("WARNING: Whisper server not reachable (%s)%s" % (e, "; will use Vosk" if rec else ""))

    def transcribe(stt_obj, t_ref):
        """Return the transcript, using Whisper if available, else Vosk."""
        vosk_text = stt_obj.finish(os.path.expanduser("~/last_rx.wav"))
        if args.stt_url:
            try:
                text = remote_stt(args.stt_url, stt_obj.wav_bytes(), hint)
                print("  Whisper: %r  (%.1fs after unkey)" % (text, time.monotonic() - t_ref))
                return text
            except Exception as e:
                print("  Whisper failed (%s)%s" % (e, ", using Vosk" if rec else ""))
        return vosk_text

    if args.selftest:
        t = time.monotonic()
        c2 = text_to_c2(args.selftest, args)
        print("TTS (%s) + Codec2: %.1fs audio in %.1fs" % (args.tts, len(c2) / 400.0, time.monotonic() - t))
        stt = StreamingSTT(rec)
        for i in range(0, len(c2), 16):
            stt.feed(c2[i:i + 16])
        t = time.monotonic()
        heard = transcribe(stt, t)
        print("STT heard %r, finished %.1fs after end of audio" % (heard, time.monotonic() - t))
        if args.api_key:
            t = time.monotonic()
            for s in sentences(stream_claude([{"role": "user", "content": heard or args.selftest}], args)):
                print("  Claude sentence at %.1fs: %r" % (time.monotonic() - t, s))
        return

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.host, args.bind_port))
    sock.settimeout(0.2)
    target = (args.host, args.port)

    def flush_socket():
        sock.setblocking(False)
        try:
            while True:
                sock.recv(2048)
        except (BlockingIOError, socket.error):
            pass
        sock.settimeout(0.2)

    history, last_id = [], 0.0
    cur_sid, cur_src, stt, nframes, last_rx = None, None, None, 0, 0.0
    print("Listening. Key up on your radio (answering: %s)." % ", ".join(allow))

    while True:
        done = False
        try:
            pkt, _ = sock.recvfrom(2048)
            parsed = parse_packet(pkt)
            if parsed:
                sid, src, dst, fn, payload = parsed
                if sid != cur_sid:
                    if stt:
                        stt.finish()
                    cur_sid, cur_src, nframes = sid, src, 0
                    ok = any(src.upper().startswith(a) for a in allow)
                    stt = StreamingSTT(rec) if ok else None
                    print("RX start from %s to %s%s" % (src, dst, "" if ok else " (not on allow list)"))
                nframes += 1
                if stt:
                    stt.feed(payload)
                last_rx = time.monotonic()
                done = bool(fn & 0x8000)
        except socket.timeout:
            done = cur_sid is not None and time.monotonic() - last_rx > 1.0
        if not done:
            continue

        t_unkey = time.monotonic()
        seconds, this_stt = nframes * FRAME_SECONDS, stt
        cur_sid, stt = None, None
        print("RX end from %s, %.1fs" % (cur_src, seconds))
        if not this_stt:
            continue
        if seconds < args.min_seconds:
            this_stt.finish()
            continue
        text = transcribe(this_stt, t_unkey)
        print("  heard: %r  (STT done %.1fs after unkey)" % (text, time.monotonic() - t_unkey))

        now = time.time()
        id_text = None
        if now - last_id > 540:                               # ID at least every 10 minutes
            id_text = " ".join(args.src) + "."
            last_id = now

        if not text:
            source = lambda: iter(["Sorry, I didn't catch that. Please try again."])
            use_history = False
        elif "reset conversation" in text or "clear conversation" in text:
            history = []
            source = lambda: iter(["Okay, starting a fresh conversation."])
            use_history = False
        else:
            history.append({"role": "user", "content": text})
            snapshot = list(history)
            source = lambda: sentences(stream_claude(snapshot, args))
            use_history = True

        chunks, result = queue.Queue(), {}
        worker = threading.Thread(target=reply_pipeline,
                                  args=(source, args, chunks, result, t_unkey, id_text), daemon=True)
        worker.start()
        first = chunks.get()                                  # wait for first sentence
        wait = args.turnaround - (time.monotonic() - t_unkey)
        if wait > 0:
            time.sleep(wait)
        pre = queue.Queue()
        pre.put(first if first is not None else silence8 * 2)
        if first is None:
            pre.put(None)
        else:
            threading.Thread(target=lambda: [pre.put(c) for c in iter(chunks.get, None)] + [pre.put(None)],
                             daemon=True).start()
        print("  TX start %.1fs after unkey" % (time.monotonic() - t_unkey))
        dur = transmit_stream(sock, target, pre, args.src, args.dst, args.can, silence8)
        worker.join(timeout=10)
        reply = result.get("text", "")
        print("  reply: %r" % reply)
        print("  TX done, %.1fs of audio" % dur)

        if use_history:
            if reply and not reply.startswith("Sorry, I couldn't reach"):
                history.append({"role": "assistant", "content": reply})
            else:
                history.pop()
            history = history[-args.history:]
            while history and history[0]["role"] != "user":
                history.pop(0)
        flush_socket()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped.")