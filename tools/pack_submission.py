"""Build the PDF and a lecture-compliant, unencrypted ZIP submission.

Fill docs/submission.json, install requirements-dev.txt, then run this script.
The existing source tree and previous delivery folders are never removed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from datetime import datetime
import zipfile

from build_report import build

BASE = Path(__file__).resolve().parent.parent


def safe_component(value):
    value = value.strip()
    if not value or value in (".","..") or re.search(r'[<>:"/\\|?*\x00-\x1f]',value) or value.endswith(("."," ")):
        raise ValueError("姓名/学号含不支持的文件名字符")
    return value


def pack(destination=None):
    meta = json.loads((BASE/"docs/submission.json").read_text(encoding="utf-8"))
    prefix = safe_component(meta["name"])+"_"+safe_component(meta["student_id"])
    destination = Path(destination or BASE/"deliverables")
    destination.mkdir(parents=True,exist_ok=True)
    folder = destination/(prefix+"_EX1A")
    if folder.exists():
        destination = destination/datetime.now().strftime("rebuild_%Y%m%d_%H%M%S")
        destination.mkdir(parents=True,exist_ok=False)
        folder = destination/(prefix+"_EX1A")
    folder.mkdir()
    source = folder/(prefix+"_ex1A_src")
    source.mkdir()
    wanted = ["run.py","启动嗅探器.bat","requirements.txt","requirements-dev.txt","LICENSE.txt",".gitignore",".gitattributes"]
    for filename in wanted:
        shutil.copy2(BASE/filename,source/filename)
    for directory in ("sniffer","tests","tools","samples"):
        shutil.copytree(BASE/directory,source/directory,ignore=shutil.ignore_patterns("__pycache__","*.pyc"))
    (source/"docs").mkdir()
    shutil.copy2(BASE/"docs/submission.json",source/"docs/submission.json")
    (source/"evidence").mkdir()
    for path in sorted((BASE/"evidence").iterdir()):
        if path.is_file() and path.suffix in (".json",".txt",".pcap",".pcapng",".png"):
            shutil.copy2(path,source/"evidence"/path.name)
    pdf = folder/(prefix+"_ex1A_report.pdf")
    build(pdf,meta)
    video = BASE/"evidence/ex1A_play.mp4"
    if not video.is_file():
        sibling_videos = list(BASE.parent.glob("*_ex1A_play.mp4"))
        if len(sibling_videos) == 1:
            video = sibling_videos[0]
    if not video.is_file() or video.stat().st_size == 0:
        raise RuntimeError("演示视频缺失，先运行 tools/record_demo.py")
    shutil.copy2(video,folder/(prefix+"_ex1A_play.mp4"))
    git = subprocess.run(["git","rev-parse","--show-toplevel"],cwd=BASE,capture_output=True,text=True,encoding="utf-8")
    if git.returncode == 0 and Path(git.stdout.strip()).resolve() == BASE.resolve():
        subprocess.run(["git","bundle","create",str(source/"history.bundle"),"--all"],cwd=BASE,check=True)
    elif (BASE/"history.bundle").is_file():
        shutil.copy2(BASE/"history.bundle",source/"history.bundle")
    else:
        raise RuntimeError("缺少 Git 历史；先初始化仓库并提交源码")
    files = sorted(p for p in folder.rglob("*") if p.is_file())
    manifest = {"format":"ZIP (unencrypted)","personal_fields_pending":any("待填写" in meta[k] for k in ("name","student_id","repository_url")),
                "files":[{"path":p.relative_to(folder).as_posix(),"bytes":p.stat().st_size,
                          "sha256":hashlib.sha256(p.read_bytes()).hexdigest()} for p in files]}
    archive = destination/(prefix+"_EX1A.zip")
    with zipfile.ZipFile(archive,"w",zipfile.ZIP_DEFLATED) as z:
        for path in files:
            z.write(path,path.relative_to(destination).as_posix())
    with zipfile.ZipFile(archive) as z:
        if z.testzip() is not None:
            raise RuntimeError("ZIP integrity check failed")
        assert all(not item.flag_bits & 1 for item in z.infolist()),"Unexpected encrypted member"
    manifest["archive_sha256"] = hashlib.sha256(archive.read_bytes()).hexdigest()
    (destination/"package_manifest.json").write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding="utf-8")
    print("Submission:",archive)
    print("Files:",len(files))
    print("SHA256:",manifest["archive_sha256"])
    return archive


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--destination")
    args = parser.parse_args()
    pack(args.destination)
