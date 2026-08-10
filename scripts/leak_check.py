"""공개 전 금지어 점검 — 저장소를 public 으로 바꾸기 직전에 돌린다.

    python scripts/leak_check.py [대상경로 ...]

금지어 목록은 `denylist.local.txt` 에서 읽는다. **이 파일은 gitignore 대상이다.**

> 목록 자체가 보호하려는 이름들이므로, 저장소에 넣으면 그 파일이 유출원이 된다.
> 점검 도구는 공개하고 점검 대상 목록은 공개하지 않는다.

검사 범위 — 본문만 보면 놓친다
  · 파일 내용
  · 파일명 · 디렉터리명
  · git 커밋 메시지
  · git 이력에 한 번이라도 들어간 파일의 경로

종료 코드
  0  깨끗함
  1  검출됨 (공개하지 말 것)
  2  설정 오류
"""

import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DENY = os.path.join(ROOT, "denylist.local.txt")
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv"}
BINARY_EXT = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".xlsx", ".pptx", ".hwpx", ".docx"}

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, ValueError):
    pass


def load_terms():
    if not os.path.exists(DENY):
        print(f"금지어 목록이 없다: {DENY}", file=sys.stderr)
        print("denylist.example.txt 를 복사해 채운 뒤 다시 돌린다.", file=sys.stderr)
        sys.exit(2)
    terms = []
    for line in open(DENY, encoding="utf-8"):
        s = line.split("#", 1)[0].strip()
        if s:
            terms.append(s)
    if not terms:
        print("금지어 목록이 비어 있다.", file=sys.stderr)
        sys.exit(2)
    return terms


def hits_in(text, terms):
    """금지어 검출.

    대문자 약어는 **대소문자를 구분**해 단어경계로 찾는다.
    구분하지 않으면 `per_run` · `counter` 같은 평범한 코드 식별자가 전부 걸린다.
    헛경보가 많은 검사는 결국 무시당하고, 그러면 검사가 없는 것과 같아진다.

    반대로 경계에 `_` 를 넣지는 않는다. `ABC_목록.md` 같은 파일명을 놓치기 때문이다.
    """
    out = []
    for t in terms:
        if re.fullmatch(r"[A-Z0-9]{2,8}", t):          # 대문자 약어
            pat, flags = rf"(?<![A-Za-z0-9]){re.escape(t)}(?![A-Za-z0-9])", 0
        elif re.fullmatch(r"[A-Za-z0-9\-]+", t):        # 그 밖의 영문
            pat, flags = rf"(?<![A-Za-z0-9]){re.escape(t)}(?![A-Za-z0-9])", re.I
        else:                                           # 한글 등
            pat, flags = re.escape(t), re.I
        for m in re.finditer(pat, text, flags):
            out.append((t, m.start()))
    return out


def line_of(text, pos):
    return text.count("\n", 0, pos) + 1


def main():
    terms = load_terms()
    targets = sys.argv[1:] or [ROOT]
    found = 0

    for target in targets:
        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

            for d in dirs:                                    # 디렉터리명
                for t, _ in hits_in(d, terms):
                    print(f"❌ 디렉터리명  {os.path.join(root, d)}  ← '{t}'")
                    found += 1

            for f in files:
                p = os.path.join(root, f)
                if f == os.path.basename(DENY):
                    continue  # 목록 파일 자신은 건너뛴다 (전부 검출되는 게 당연하다)
                              # 다른 저장소를 검사할 때 그쪽 목록도 걸리므로 이름으로 판정한다
                for t, _ in hits_in(f, terms):                # 파일명
                    print(f"❌ 파일명      {p}  ← '{t}'")
                    found += 1
                if os.path.splitext(f)[1].lower() in BINARY_EXT:
                    continue
                try:
                    s = open(p, encoding="utf-8", errors="replace").read()
                except OSError:
                    continue
                for t, pos in hits_in(s, terms):              # 본문
                    print(f"❌ 내용        {p}:{line_of(s, pos)}  ← '{t}'")
                    found += 1

    # git 이력 — 지운 파일도 이력에는 남는다
    # 🔴 검사 대상마다 그 저장소의 이력을 본다. 스크립트가 있는 곳이 아니라.
    #    (처음엔 ROOT 고정이라, 다른 저장소를 검사해도 자기 이력만 보고 있었다)
    for target in targets:
        if not os.path.isdir(os.path.join(target, ".git")):
            print(f"ℹ  {os.path.basename(target) or target}: git 저장소가 아니다. 이력 검사 건너뜀.")
            continue
        for what, cmd in [("커밋메시지", ["log", "--all", "--format=%h %s%n%b"]),
                          ("이력내파일", ["log", "--all", "--name-only", "--format="])]:
            r = subprocess.run(["git", "-C", target, "-c", "core.quotepath=false", *cmd],
                               capture_output=True, text=True, encoding="utf-8", errors="replace")
            for line in set(filter(None, (r.stdout or "").splitlines())):
                for t, _ in hits_in(line, terms):
                    print(f"❌ git {what} [{os.path.basename(target)}]  {line.strip()}  ← '{t}'")
                    found += 1

    print()
    if found:
        print(f"🔴 {found}건 검출 — 공개하지 말 것.")
        print("   커밋된 적이 있다면 파일을 지우는 것으로 끝나지 않는다. 저장소를 새로 파는 편이 안전하다.")
        return 1
    print("✅ 검출 없음.")
    print("   다만 이 검사는 목록에 적은 것만 본다. 문단을 남에게 읽히고 "
          "'어느 조직 얘기 같아?'를 물어보는 절차를 대체하지 않는다.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
