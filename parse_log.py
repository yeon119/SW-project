#!/usr/bin/env python3

import json
import re
from pathlib import Path


# nftables의 WG-DROP 기록이 저장되는 로그 파일
LOG_PATH = Path("/var/log/wireguard-access.log")


FIELD_PATTERN = re.compile(r"\b([A-Z]+)=([^\s]+)")

TCP_FLAGS = ("SYN", "ACK", "FIN", "RST", "PSH", "URG")

# 문자열이 숫자라면 정수로 반환하고 값아 없거나 숫자가 아니면 None으로 반환
def number_or_none(value):
   
    if value and value.isdigit():
        return int(value)

    return None

#로그에서 한줄을 분석해서 필요한 부분을 추출 WG-LOG가 아니라면 None , 맞다면 분석해서 딕셔너리로 반환
def parse_line(line):
    
    if "WG-DROP:" not in line:
        return None

    # FIELD_PATTERN과 일치하는 KEY=VALUE 값을 모두 찾기
    fields = dict(FIELD_PATTERN.findall(line))

    # TCP 플래그 중 현재 로그에 들어 있는 플래그를 찾기
    flags = [
        flag
        for flag in TCP_FLAGS
        if re.search(rf"\b{flag}\b", line)
    ]

    # 찾은 값을 약어로 변경
    return {
        
        "input_interface": fields.get("IN"),
        "output_interface": fields.get("OUT"),
        "source_ip": fields.get("SRC"),
        "destination_ip": fields.get("DST"),
        "protocol": fields.get("PROTO"),
        "source_port": number_or_none(fields.get("SPT")),
        "destination_port": number_or_none(fields.get("DPT")),
        "packet_length": number_or_none(fields.get("LEN")),
        "tcp_flags": flags,
    }

# 로그파일을 열어서 한줄씩 분석하는 메인 함수
def main():
    
    # 로그 파일이 실제로 존재하는지 먼저 확인
    if not LOG_PATH.exists():
        print(f"로그 파일이 없습니다: {LOG_PATH}")
        return

    # 로그 파일을 읽기 전용으로 열어 utf-8방식으로 읽고 해석 못하는 문자는 대체문자로 바꿔서 계속 읽기
    
    with LOG_PATH.open(
        "r",
        encoding="utf-8",
        errors="replace",
    ) as log_file:

        # 로그 파일을 첫 번째 줄부터 마지막 줄까지 반복
        for line in log_file:

            # 현재 로그 한 줄을 분석
            event = parse_line(line)

            # WG-DROP 기록만 출력
            if event is not None:

                # 딕셔너리를 JSON 문자열로 변환하여 출력
                #
                # ensure_ascii=False:
                # 한글을 \\uXXXX 형태로 바꾸지 않고 그대로 출력
                print(json.dumps(event, ensure_ascii=False))


if __name__ == "__main__":
    main()