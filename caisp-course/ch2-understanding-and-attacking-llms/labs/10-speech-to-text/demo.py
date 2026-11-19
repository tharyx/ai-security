"""Speech-to-text pipeline demo (simulated audio).  From the repo root:
    .venv/Scripts/python caisp-course/ch2-understanding-and-attacking-llms/labs/10-speech-to-text/demo.py
"""

from voice_agent import (OWNER_CMD, TV_INJECTION, ULTRASONIC_INJECTION, SecureVoiceAgent,
                         VulnerableVoiceAgent, transcribe, wer)


def main() -> None:
    print("== 1. Transcript quality (word error rate) ==")
    ref = OWNER_CMD.text
    hyp = " ".join(s.text for s in transcribe([OWNER_CMD], noisy=True))
    print(f"reference : {ref}\nhypothesis: {hyp}\nWER = {wer(ref, hyp):.0%}")

    print("\n== 2. Normal command through both agents ==")
    for cls in (VulnerableVoiceAgent, SecureVoiceAgent):
        a = cls()
        print(f"{cls.__name__:20}", a.handle(transcribe([OWNER_CMD])), a.tools.log)

    print("\n== 3. Audio prompt injection: TV ad speaks a directive while the owner talks ==")
    audio = transcribe([OWNER_CMD, TV_INJECTION])
    v = VulnerableVoiceAgent()
    print("vulnerable:", v.handle(audio), "| tool log:", v.tools.log)
    s = SecureVoiceAgent()
    print("secure    :", s.handle(audio), "| tool log:", s.tools.log)
    print("blocked   :", s.blocked)

    print("\n== 4. Ultrasonic/out-of-band injection ==")
    audio = transcribe([ULTRASONIC_INJECTION])
    v = VulnerableVoiceAgent()
    print("vulnerable:", v.handle(audio), "| tool log:", v.tools.log)
    s = SecureVoiceAgent()
    print("secure    :", s.handle(audio), "| blocked:", s.blocked)

    print("\n== 5. Layer 2 alone (we wrongly trust every source) ==")
    s = SecureVoiceAgent(trust_all_sources=True)
    print("secure(trust-all):", s.handle(transcribe([TV_INJECTION])), "| tool log:", s.tools.log)
    print("blocked          :", s.blocked)


if __name__ == "__main__":
    main()
